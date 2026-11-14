//! The web access layer: fetching pages and running searches through the configured proxy.
//!
//! [`WebClient`] is the single gateway to the network. It wraps a
//! [`scrapling_fetch::Fetcher`] (TLS/HTTP2 browser impersonation, retries, SOCKS/HTTP proxy)
//! and exposes two high-level operations used by the MCP tools in [`crate::mcp`] and by the
//! debugging subcommands in `main`:
//!
//! * [`WebClient::fetch_page`] — download a URL and convert it to Markdown, text, or HTML.
//! * [`WebClient::search`] — query the configured [`SearchEngine`]s, falling back in order.
//!
//! Every response is first checked by [`block::detect`]; anti-bot challenge pages become
//! [`WebError::Blocked`] instead of being passed off as content. [`WebError::log`] is the single
//! place failures are logged, at a level matching their cause.
//!
//! HTML parsing and conversion are CPU-bound, so they run on Tokio's blocking pool via
//! [`tokio::task::spawn_blocking`] to keep the async workers responsive.

use std::{collections::HashMap, sync::Arc};

use scrapling::{selector::Selector, shell::Convertor};
use scrapling_fetch::{
    FetchError, Fetcher, FollowRedirects, Impersonate, Proxy, RequestConfig, Response,
};
use serde::Deserialize;
use tracing::{debug, error, info, warn};
use url::Url;

use crate::{
    block::{self, Block},
    config::Config,
    cookies::{CookieJar, domain_matches},
    images::{self, ImageError, Prepared},
    search::{SearchEngine, SearchHit},
};

/// Redirects followed per request before giving up.
const MAX_REDIRECTS: usize = 10;

/// Largest image download accepted.
const MAX_IMAGE_BYTES: usize = 25 * 1024 * 1024;

/// A logged-in session for one site, threaded through requests so `Set-Cookie` updates
/// (including those on intermediate redirects) are captured.
#[derive(Debug, Clone)]
pub struct SiteSession {
    /// Domain the cookies apply to (and its subdomains).
    pub domain: String,
    /// Current cookies.
    pub jar: CookieJar,
    /// Whether the jar changed since it was loaded and should be saved.
    pub changed: bool,
}

impl SiteSession {
    /// Wraps a loaded jar for `domain`.
    pub fn new(domain: impl Into<String>, jar: CookieJar) -> Self {
        Self {
            domain: domain.into(),
            jar,
            changed: false,
        }
    }

    fn covers(&self, url: &Url) -> bool {
        url.host_str()
            .is_some_and(|host| domain_matches(&self.domain, host))
    }
}

/// A form submission: `application/x-www-form-urlencoded` fields, sent as POST.
#[derive(Debug, Clone)]
pub struct FormPost {
    /// Field names and values, in order.
    pub fields: Vec<(String, String)>,
    /// Page the form was on, sent as `Referer` (and its origin as `Origin`).
    pub referer: Url,
}

/// An image fetched for the model.
#[derive(Debug, Clone)]
pub struct FetchedImage {
    /// Final URL after redirects.
    pub url: String,
    /// Size of the original download.
    pub source_bytes: usize,
    /// The prepared image.
    pub image: Prepared,
}

/// Elements tried, in order, to locate a page's main content when no selector is given.
const MAIN_CONTENT_SELECTORS: &[&str] = &["main", "article", "[role=main]"];

/// A main-content candidate must hold at least this fraction (in percent) of the body's
/// visible text. Pages that fill `<main>` with JavaScript (e.g. Craigslist search) ship it
/// empty and keep the server-rendered content elsewhere, so an empty `<main>` must lose to
/// `<body>`.
const MAIN_CONTENT_MIN_SHARE_PERCENT: usize = 25;

/// Tags whose text is not visible content.
const INVISIBLE_TAGS: &[&str] = &["script", "style", "noscript", "template", "svg"];

/// A successful page with less readable text than this is flagged as possibly JS-rendered…
const THIN_CONTENT_CHARS: usize = 200;
/// …but only if its HTML is at least this large: a big document with almost no text is an
/// app shell, while a small one (e.g. `example.com`) is just a short page.
const APP_SHELL_MIN_BYTES: usize = 5 * 1024;

/// Output representation for fetched pages.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, schemars::JsonSchema, clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    /// Markdown, preserving headings, links, lists, and tables. Best for LLMs.
    #[default]
    Markdown,
    /// Plain visible text with all markup removed.
    Text,
    /// The raw HTML of the selected region.
    Html,
}

/// Parameters for [`WebClient::fetch_page`].
#[derive(Debug, Clone)]
pub struct PageRequest {
    /// Absolute `http`/`https` URL to fetch.
    pub url: String,
    /// Desired output representation.
    pub format: Format,
    /// Optional CSS selector restricting output to matching elements.
    pub selector: Option<String>,
    /// Character offset to start returning content from (for paging through long pages).
    pub start: usize,
    /// Maximum characters to return; `None` uses the configured default.
    pub max_chars: Option<usize>,
}

/// A fetched and converted page, ready to hand to the model.
#[derive(Debug, Clone)]
pub struct Page {
    /// Final URL after redirects.
    pub url: String,
    /// HTTP status code.
    pub status: u16,
    /// Contents of `<title>`, if any.
    pub title: Option<String>,
    /// The requested slice of converted content.
    pub content: String,
    /// Length in characters of the full converted content.
    pub total_chars: usize,
    /// Offset to pass as `start` to read the next slice, if content was truncated.
    pub next_start: Option<usize>,
    /// A caveat for the model about the content, e.g. that the page needs JavaScript.
    pub notice: Option<&'static str>,
}

impl std::fmt::Display for Page {
    /// Renders a compact header followed by the content — the format returned to the model.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "URL: {}", self.url)?;
        writeln!(f, "Status: {}", self.status)?;
        if let Some(title) = &self.title {
            writeln!(f, "Title: {title}")?;
        }
        if let Some(notice) = self.notice {
            writeln!(f, "Note: {notice}")?;
        }
        if let Some(next) = self.next_start {
            writeln!(
                f,
                "Truncated: showing up to char {next} of {}; call again with start={next} for more.",
                self.total_chars
            )?;
        }
        write!(f, "\n{}", self.content)
    }
}

/// Everything that can go wrong while fetching or searching.
#[derive(Debug, thiserror::Error)]
pub enum WebError {
    /// The input was not an absolute URL.
    #[error("invalid URL `{url}`: {source}")]
    InvalidUrl {
        /// The rejected input.
        url: String,
        /// Parser error.
        source: url::ParseError,
    },
    /// Only `http` and `https` are fetched.
    #[error("unsupported URL scheme `{0}`; only http and https are allowed")]
    UnsupportedScheme(String),
    /// The URL targets a loopback, private, or link-local address.
    #[error("refusing to fetch internal address `{0}`")]
    InternalAddress(String),
    /// Network, proxy, TLS, or retry-exhaustion failure from the fetcher.
    #[error(transparent)]
    Fetch(#[from] FetchError),
    /// A user-supplied CSS selector matched no elements.
    #[error("CSS selector `{0}` matched nothing on the page")]
    SelectorMatchedNothing(String),
    /// The site answered with an anti-bot challenge, CAPTCHA, or denial instead of content.
    #[error(
        "{url} blocked the request: {block}. The site's anti-bot protection rejected this \
         server; retrying will not help, so try another source for this information."
    )]
    Blocked {
        /// The URL that was requested.
        url: String,
        /// What blocked it.
        block: Block,
    },
    /// A redirect chain was too long (or looped).
    #[error("too many redirects fetching {0}")]
    TooManyRedirects(String),
    /// The response was not a usable image.
    #[error("{url}: {source}")]
    Image {
        /// The URL requested.
        url: String,
        /// What was wrong.
        source: ImageError,
    },
    /// The image URL answered with an error status.
    #[error("{url} returned HTTP {status} instead of an image")]
    ImageStatus {
        /// The final URL.
        url: String,
        /// The HTTP status.
        status: u16,
    },
    /// The image is larger than the download limit.
    #[error("{0} is larger than the 25 MB image limit")]
    ImageTooLarge(String),
    /// Every configured search engine failed or returned no results.
    #[error("no search results for `{query}` (tried: {tried})")]
    NoResults {
        /// The query that was searched.
        query: String,
        /// Summary of each engine attempt.
        tried: String,
    },
    /// The blocking HTML-conversion task panicked.
    #[error("content extraction task failed: {0}")]
    Extraction(#[from] tokio::task::JoinError),
}

impl WebError {
    /// Logs this failure once, at a level that matches its cause.
    ///
    /// * `WARN`: the target site blocked us, or the request was refused as an internal address.
    /// * `ERROR`: network, proxy, TLS, or internal failures, and searches where every engine
    ///   failed. These need an operator's attention.
    /// * `INFO`: bad input from the client (invalid URL, selector that matched nothing).
    ///
    /// `operation` names what was attempted (e.g. `"fetch_url"`); `target` is the URL or query.
    pub fn log(&self, operation: &str, target: &str) {
        match self {
            Self::Blocked { block, .. } => warn!(
                operation,
                target,
                reason = block.reason,
                status = block.status,
                "site blocked request"
            ),
            Self::InternalAddress(_) => {
                warn!(operation, target, error = %self, "refused internal address")
            }
            Self::Fetch(_)
            | Self::NoResults { .. }
            | Self::Extraction(_)
            | Self::TooManyRedirects(_) => {
                error!(operation, target, error = %self, "request failed")
            }
            Self::Image { .. } | Self::ImageStatus { .. } | Self::ImageTooLarge(_) => {
                warn!(operation, target, error = %self, "unusable image")
            }
            Self::InvalidUrl { .. }
            | Self::UnsupportedScheme(_)
            | Self::SelectorMatchedNothing(_) => {
                info!(operation, target, error = %self, "rejected request")
            }
        }
    }
}

/// Cheaply cloneable handle for all outbound web traffic.
///
/// All clones share one [`Fetcher`] and the immutable [`Config`]; proxy, timeout, retry,
/// and impersonation settings are fixed at construction.
#[derive(Clone)]
pub struct WebClient {
    fetcher: Arc<Fetcher>,
    config: Arc<Config>,
}

impl WebClient {
    /// Builds a client from configuration.
    ///
    /// # Errors
    ///
    /// Returns [`FetchError::InvalidProxy`] if the fetcher rejects the proxy settings.
    pub fn new(config: &Config) -> Result<Self, FetchError> {
        Ok(Self {
            fetcher: Arc::new(build_fetcher(config)?),
            config: Arc::new(config.clone()),
        })
    }

    /// Fetches a page and converts the selected region to the requested [`Format`].
    ///
    /// Non-2xx responses are *not* errors: the status is reported on the returned [`Page`]
    /// so the model can see e.g. a 404 body.
    ///
    /// # Errors
    ///
    /// [`WebError::InvalidUrl`]/[`WebError::UnsupportedScheme`] for bad input,
    /// [`WebError::Fetch`] for network/proxy failures, and
    /// [`WebError::SelectorMatchedNothing`] if an explicit selector finds no elements.
    ///
    /// With a `session`, its cookies are sent to the site and updated from the responses.
    pub async fn fetch_page(
        &self,
        req: PageRequest,
        session: Option<&mut SiteSession>,
    ) -> Result<Page, WebError> {
        let url = parse_http_url(&req.url)?;
        let response = self.request(&url, None, session).await?;
        let max_chars = req.max_chars.unwrap_or(self.config.max_chars);
        let page =
            tokio::task::spawn_blocking(move || extract_page(&response, &req, max_chars)).await??;
        info!(url = %page.url, status = page.status, chars = page.total_chars, "fetched page");
        if let Some(notice) = page.notice {
            warn!(url = %page.url, status = page.status, chars = page.total_chars, notice, "thin page content");
        }
        Ok(page)
    }

    /// Searches the web, trying each configured engine in order until one returns hits.
    ///
    /// # Errors
    ///
    /// [`WebError::NoResults`] if every engine failed or returned nothing; the message lists
    /// what happened with each engine so proxy problems are easy to diagnose.
    pub async fn search(&self, query: &str, limit: usize) -> Result<Vec<SearchHit>, WebError> {
        let engines = &self.config.search_engines;
        let mut attempts = Vec::with_capacity(engines.len());
        for &engine in engines {
            match self.search_with(engine, query).await {
                Ok(hits) if !hits.is_empty() => {
                    info!(%engine, count = hits.len(), "search succeeded");
                    return Ok(hits.into_iter().take(limit).collect());
                }
                Ok(_) => {
                    warn!(%engine, query, "search engine returned no results");
                    attempts.push(format!("{engine}: no results"));
                }
                Err(WebError::Blocked { block, .. }) => {
                    warn!(%engine, query, reason = block.reason, status = block.status, "search engine blocked request");
                    attempts.push(format!("{engine}: blocked ({block})"));
                }
                Err(err) => {
                    warn!(%engine, query, error = %err, "search engine failed");
                    attempts.push(format!("{engine}: {err}"));
                }
            }
        }
        Err(WebError::NoResults {
            query: query.to_owned(),
            tried: attempts.join("; "),
        })
    }

    async fn search_with(
        &self,
        engine: SearchEngine,
        query: &str,
    ) -> Result<Vec<SearchHit>, WebError> {
        let response = self.request(&engine.results_url(query), None, None).await?;
        let html = String::from_utf8_lossy(&response.body).into_owned();
        Ok(tokio::task::spawn_blocking(move || engine.parse(&html)).await?)
    }

    /// Downloads an image and prepares it for the model (see [`images::prepare`]).
    ///
    /// # Errors
    ///
    /// The [`fetch_page`](Self::fetch_page) errors, plus [`WebError::Image`] when the URL does
    /// not serve an image and [`WebError::ImageTooLarge`] above the size limit.
    pub async fn fetch_image(
        &self,
        url: &str,
        session: Option<&mut SiteSession>,
    ) -> Result<FetchedImage, WebError> {
        let url = parse_http_url(url)?;
        let response = self.request(&url, None, session).await?;
        let final_url = response.url().to_owned();
        if !(200..300).contains(&response.status) {
            return Err(WebError::ImageStatus {
                url: final_url,
                status: response.status,
            });
        }
        if response.body.len() > MAX_IMAGE_BYTES {
            return Err(WebError::ImageTooLarge(final_url));
        }
        let content_type = header(&response.headers, "content-type").map(str::to_owned);
        let source_bytes = response.body.len();
        let prepared = tokio::task::spawn_blocking(move || {
            images::prepare(&response.body, content_type.as_deref())
        })
        .await?;
        let image = prepared.map_err(|source| WebError::Image {
            url: final_url.clone(),
            source,
        })?;
        info!(url = %final_url, bytes = source_bytes, "fetched image");
        Ok(FetchedImage {
            url: final_url,
            source_bytes,
            image,
        })
    }

    /// Sends a GET (or the `form` POST) to `url`, following redirects manually.
    ///
    /// Following redirects here rather than in the HTTP client lets every hop pass the SSRF
    /// guard, and lets a `session` send and capture cookies on each hop (logins commonly set
    /// the session cookie on a `302`). 301/302/303 turn a POST into a GET; 307/308 repeat it.
    /// The final response is checked by [`block::detect`].
    ///
    /// # Errors
    ///
    /// Network/proxy failures, [`WebError::InternalAddress`] for a redirect into a private
    /// network, [`WebError::TooManyRedirects`], and [`WebError::Blocked`].
    pub async fn request(
        &self,
        url: &Url,
        form: Option<&FormPost>,
        mut session: Option<&mut SiteSession>,
    ) -> Result<Response, WebError> {
        match self
            .request_as(url, form, session.as_deref_mut(), Profile::Browser)
            .await
        {
            Err(WebError::Blocked { block, .. })
                if block.is_generic_denial() && self.config.impersonate != "none" =>
            {
                // Some sites (e.g. Wikimedia's file servers) reject impersonated browsers but
                // serve plain clients; vendor challenges are never retried.
                info!(%url, "generic 403 while impersonating a browser; retrying as a plain client");
                self.request_as(url, form, session, Profile::Plain).await
            }
            other => other,
        }
    }

    /// One redirect-following request with the given client [`Profile`].
    async fn request_as(
        &self,
        url: &Url,
        form: Option<&FormPost>,
        mut session: Option<&mut SiteSession>,
        profile: Profile,
    ) -> Result<Response, WebError> {
        let mut url = url.clone();
        let mut form = form;
        for _ in 0..=MAX_REDIRECTS {
            let session_cookies = session
                .as_deref()
                .filter(|s| s.covers(&url) && !s.jar.is_empty())
                .map(|s| s.jar.to_map());
            let config = request_config(session_cookies, form, profile);
            debug!(%url, method = if form.is_some() { "POST" } else { "GET" }, "request");
            let response = match form {
                Some(_) => self.fetcher.post(url.as_str(), Some(config)).await?,
                None => self.fetcher.get(url.as_str(), Some(config)).await?,
            };
            if let Some(session) = session.as_deref_mut().filter(|s| s.covers(&url)) {
                session.changed |= session.jar.merge(&response.cookies);
            }

            let location = header(&response.headers, "location");
            match (response.status, location) {
                (301 | 302 | 303 | 307 | 308, Some(location)) => {
                    let next = url.join(location).map_err(|source| WebError::InvalidUrl {
                        url: location.to_owned(),
                        source,
                    })?;
                    url = parse_http_url(next.as_str())?;
                    if matches!(response.status, 301..=303) {
                        form = None;
                    }
                }
                _ => {
                    return match block::detect(response.status, &response.headers, &response.body) {
                        Some(block) => Err(WebError::Blocked {
                            url: url.to_string(),
                            block,
                        }),
                        None => Ok(response),
                    };
                }
            }
        }
        Err(WebError::TooManyRedirects(url.to_string()))
    }
}

/// Builds the shared [`Fetcher`] from `config`.
fn build_fetcher(config: &Config) -> Result<Fetcher, FetchError> {
    let impersonate = match config.impersonate.as_str() {
        "none" | "" => Impersonate::None,
        browser => Impersonate::Single(browser.to_owned()),
    };
    let mut builder = Fetcher::builder()
        .timeout_secs(config.timeout_secs)
        .retries(config.retries.max(1))
        .impersonate(impersonate);
    match &config.proxy {
        Some(proxy) => {
            info!(%proxy, "routing web traffic through proxy");
            builder = builder.proxy(Proxy::Url(proxy.as_str().to_owned()));
        }
        None => warn!("no proxy configured; web traffic goes out directly"),
    }
    Fetcher::from_builder(builder)
}

/// How a request presents itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Profile {
    /// The configured browser impersonation and stealth headers (the default).
    Browser,
    /// No impersonation or stealth headers: a plain HTTP client.
    Plain,
}

/// Per-request fetcher settings: no automatic redirects, plus cookies, form body, and profile.
fn request_config(
    cookies: Option<HashMap<String, String>>,
    form: Option<&FormPost>,
    profile: Profile,
) -> RequestConfig {
    let plain = profile == Profile::Plain;
    let mut config = RequestConfig {
        follow_redirects: Some(FollowRedirects::None),
        cookies,
        impersonate: plain.then_some(Impersonate::None),
        stealthy_headers: plain.then_some(false),
        ..Default::default()
    };
    if let Some(form) = form {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(&form.fields)
            .finish();
        let origin = form.referer.origin().ascii_serialization();
        config.headers = Some(HashMap::from([
            (
                "content-type".to_owned(),
                "application/x-www-form-urlencoded".to_owned(),
            ),
            ("referer".to_owned(), form.referer.to_string()),
            ("origin".to_owned(), origin),
        ]));
        config.data = Some(body.into_bytes());
    }
    config
}

/// Case-insensitive response header lookup.
fn header<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

/// Parses `input` as an absolute `http`/`https` URL that is not an internal address.
pub fn parse_http_url(input: &str) -> Result<Url, WebError> {
    let url = Url::parse(input.trim()).map_err(|source| WebError::InvalidUrl {
        url: input.to_owned(),
        source,
    })?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(WebError::UnsupportedScheme(url.scheme().to_owned()));
    }
    match url.host() {
        Some(host) if is_internal_host(&host) => Err(WebError::InternalAddress(host.to_string())),
        _ => Ok(url),
    }
}

/// Whether `host` names this machine or a non-public network.
///
/// A best-effort SSRF guard for public deployments: it blocks `localhost` and IP literals in
/// loopback, private (RFC 1918 / ULA), link-local (incl. cloud metadata `169.254.169.254`),
/// CGNAT, and unspecified ranges. It cannot see hostnames that *resolve* to such addresses
/// or redirects to them; routing traffic through a SOCKS proxy contains those cases, since
/// connections then originate from the proxy rather than this host.
fn is_internal_host(host: &url::Host<&str>) -> bool {
    use std::net::Ipv4Addr;
    let v4_internal = |ip: Ipv4Addr| {
        let cgnat = ip.octets()[0] == 100 && (ip.octets()[1] & 0xC0) == 64;
        ip.is_loopback() || ip.is_private() || ip.is_link_local() || ip.is_unspecified() || cgnat
    };
    match host {
        url::Host::Domain(name) => {
            let name = name.trim_end_matches('.').to_ascii_lowercase();
            name == "localhost" || name.ends_with(".localhost")
        }
        url::Host::Ipv4(ip) => v4_internal(*ip),
        url::Host::Ipv6(ip) => {
            let first = ip.segments()[0];
            ip.is_loopback()
                || ip.is_unspecified()
                || (first & 0xFE00) == 0xFC00 // unique local fc00::/7
                || (first & 0xFFC0) == 0xFE80 // link-local fe80::/10
                || ip.to_ipv4_mapped().is_some_and(v4_internal)
        }
    }
}

/// Synchronous half of [`WebClient::fetch_page`]: select, convert, and window the content.
fn extract_page(
    response: &Response,
    req: &PageRequest,
    max_chars: usize,
) -> Result<Page, WebError> {
    let doc = response.selector();
    let html = match &req.selector {
        Some(selector) => outer_html(doc, selector)
            .ok_or_else(|| WebError::SelectorMatchedNothing(selector.clone()))?,
        None => main_content_html(doc)
            .unwrap_or_else(|| String::from_utf8_lossy(&response.body).into_owned()),
    };

    let converted = match req.format {
        Format::Markdown => Convertor::to_markdown(&html),
        Format::Text => Convertor::to_text(&html),
        Format::Html => html,
    };
    let (content, total_chars, next_start) = window(converted.trim(), req.start, max_chars);
    let thin = req.selector.is_none()
        && (200..300).contains(&response.status)
        && total_chars < THIN_CONTENT_CHARS
        && response.body.len() >= APP_SHELL_MIN_BYTES;
    let notice = thin.then_some(
        "the page has very little readable content. It is probably rendered by JavaScript, \
         which this fetcher does not run; look for an API, RSS feed, or another source.",
    );

    Ok(Page {
        url: response.url().to_owned(),
        status: response.status,
        title: doc
            .css("title")
            .first()
            .map(|t| t.text().trim().to_owned())
            .filter(|t| !t.is_empty()),
        content,
        total_chars,
        next_start,
        notice,
    })
}

/// The HTML of the page's main content: the first of [`MAIN_CONTENT_SELECTORS`] holding a
/// meaningful share of the visible text, else `<body>`. `None` if there is no body either.
fn main_content_html(doc: &Selector) -> Option<String> {
    let body_chars = doc.css("body").iter().map(visible_chars).sum::<usize>();
    let min_chars = (body_chars * MAIN_CONTENT_MIN_SHARE_PERCENT / 100).max(1);
    MAIN_CONTENT_SELECTORS
        .iter()
        .find(|selector| doc.css(selector).iter().map(visible_chars).sum::<usize>() >= min_chars)
        .and_then(|selector| outer_html(doc, selector))
        .or_else(|| outer_html(doc, "body"))
}

/// Number of visible (non-script/style) text characters inside `element`.
fn visible_chars(element: &Selector) -> usize {
    element
        .get_all_text(" ", true, INVISIBLE_TAGS, true)
        .chars()
        .filter(|c| !c.is_whitespace())
        .count()
}

/// Concatenated outer HTML of every element matching `selector`, or `None` if nothing
/// (non-blank) matches.
fn outer_html(doc: &Selector, selector: &str) -> Option<String> {
    let html = doc
        .css(selector)
        .iter()
        .map(|el| el.get().into_inner())
        .collect::<Vec<_>>()
        .join("\n");
    (!html.trim().is_empty()).then_some(html)
}

/// Returns the `[start, start + max)` character window of `text`, the total character count,
/// and the offset of the next window if anything remains.
fn window(text: &str, start: usize, max: usize) -> (String, usize, Option<usize>) {
    let total = text.chars().count();
    let content: String = text.chars().skip(start).take(max).collect();
    let end = start.saturating_add(max);
    (content, total, (end < total).then_some(end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_http_schemes() {
        assert!(
            matches!(parse_http_url("file:///etc/passwd"), Err(WebError::UnsupportedScheme(s)) if s == "file")
        );
        assert!(matches!(
            parse_http_url("not a url"),
            Err(WebError::InvalidUrl { .. })
        ));
        assert!(parse_http_url(" https://example.com ").is_ok());
    }

    #[test]
    fn blocks_internal_targets() {
        for url in [
            "http://localhost:8787/mcp",
            "http://api.localhost/",
            "http://127.0.0.1/",
            "http://10.0.0.5/",
            "http://172.18.0.2/",
            "http://192.168.1.1/",
            "http://169.254.169.254/latest/meta-data/",
            "http://100.64.0.1/",
            "http://0.0.0.0/",
            "http://[::1]/",
            "http://[fd00::1]/",
            "http://[fe80::1]/",
            "http://[::ffff:127.0.0.1]/",
        ] {
            assert!(
                matches!(parse_http_url(url), Err(WebError::InternalAddress(_))),
                "{url} should be blocked"
            );
        }
        for url in [
            "https://8.8.8.8/",
            "https://example.com/",
            "http://[2606:4700::1111]/",
        ] {
            assert!(parse_http_url(url).is_ok(), "{url} should be allowed");
        }
    }

    #[test]
    fn main_content_skips_empty_js_shell() {
        // Craigslist-style: `<main>` is filled by JavaScript, results are elsewhere.
        let html = r#"<html><body><main>
            </main><ol class="results"><li>Fuji hybrid bike $175</li><li>Kona road bike $400</li></ol>
            <script>var big = "lots of script text that should not count as content";</script></body></html>"#;
        let doc = Selector::from_html(html);
        let chosen = main_content_html(&doc).unwrap();
        assert!(chosen.contains("Fuji hybrid bike"), "{chosen}");
    }

    #[test]
    fn main_content_prefers_article_when_it_holds_the_text() {
        let html = format!(
            "<html><body><nav>Home About</nav><article>{}</article><footer>c</footer></body></html>",
            "The real story. ".repeat(50)
        );
        let doc = Selector::from_html(&html);
        let chosen = main_content_html(&doc).unwrap();
        assert!(chosen.starts_with("<article"), "{chosen}");
    }

    #[test]
    fn window_pages_through_text_on_char_boundaries() {
        let text = "héllo wörld";
        assert_eq!(window(text, 0, 5), ("héllo".into(), 11, Some(5)));
        assert_eq!(window(text, 6, 100), ("wörld".into(), 11, None));
        assert_eq!(window(text, 50, 10), (String::new(), 11, None));
    }

    #[test]
    fn page_display_mentions_truncation() {
        let page = Page {
            url: "https://e.x/".into(),
            status: 200,
            title: Some("T".into()),
            content: "body".into(),
            total_chars: 10,
            next_start: Some(4),
            notice: None,
        };
        let shown = page.to_string();
        assert!(shown.contains("Title: T"));
        assert!(shown.contains("start=4"));
        assert!(shown.ends_with("\nbody"));
    }
}

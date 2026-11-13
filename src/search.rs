//! Search-engine adapters: building result-page URLs and scraping hits out of the HTML.
//!
//! This module is deliberately I/O-free. [`SearchEngine::results_url`] says *what* to fetch
//! and [`SearchEngine::parse`] turns the returned HTML into [`SearchHit`]s; the actual request
//! (through the proxy, with browser impersonation) is made by
//! [`WebClient::search`](crate::web::WebClient::search). Keeping parsing pure makes every
//! engine unit-testable against saved HTML.
//!
//! Engines are tried in the order configured by the user; the first that yields results
//! wins. DuckDuckGo Lite is the default because it has the simplest, most stable markup and
//! is the least aggressive about bot challenges.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scrapling::selector::Selector;
use serde::Serialize;
use url::Url;

/// One organic search result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct SearchHit {
    /// Result title as shown by the engine.
    pub title: String,
    /// Destination URL, with engine click-tracking redirects already unwrapped.
    pub url: String,
    /// Short text excerpt, possibly empty.
    pub snippet: String,
}

/// A supported search backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum SearchEngine {
    /// `lite.duckduckgo.com` — minimal table-based markup.
    DuckduckgoLite,
    /// `html.duckduckgo.com` — the no-JS DuckDuckGo page.
    DuckduckgoHtml,
    /// `www.bing.com` — useful as a fallback when DuckDuckGo issues a challenge.
    Bing,
}

impl std::fmt::Display for SearchEngine {
    /// Uses the same kebab-case name accepted on the command line / in `.env`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use clap::ValueEnum as _;
        let value = self.to_possible_value().expect("no variants are skipped");
        f.write_str(value.get_name())
    }
}

impl SearchEngine {
    /// The URL of the results page for `query`.
    pub fn results_url(self, query: &str) -> Url {
        let (base, key) = match self {
            Self::DuckduckgoLite => ("https://lite.duckduckgo.com/lite/", "q"),
            Self::DuckduckgoHtml => ("https://html.duckduckgo.com/html/", "q"),
            Self::Bing => ("https://www.bing.com/search", "q"),
        };
        Url::parse_with_params(base, [(key, query)]).expect("static base URL is valid")
    }

    /// Extracts organic results from a results page, in rank order, skipping ads.
    ///
    /// Returns an empty vector (not an error) when nothing matches, which callers treat as
    /// "try the next engine" — this also covers CAPTCHA/anomaly pages.
    pub fn parse(self, html: &str) -> Vec<SearchHit> {
        let doc = Selector::from_html(html);
        let hits = match self {
            Self::DuckduckgoLite => parse_ddg_lite(&doc),
            Self::DuckduckgoHtml => parse_blocks(
                &doc,
                ".result:not(.result--ad)",
                "a.result__a",
                ".result__snippet",
            ),
            Self::Bing => parse_blocks(&doc, "li.b_algo", "h2 a", ".b_caption p"),
        };
        dedup_by_url(hits)
    }
}

/// DuckDuckGo Lite puts the link and its snippet in *sibling* table rows, so walk rows in
/// order and attach each snippet to the most recent link.
fn parse_ddg_lite(doc: &Selector) -> Vec<SearchHit> {
    let mut hits: Vec<SearchHit> = Vec::new();
    for row in doc.css("tr") {
        if let Some(hit) = row.css("a.result-link").first().and_then(hit_from_link) {
            hits.push(hit);
        } else if let (Some(snippet), Some(last)) =
            (row.css("td.result-snippet").first(), hits.last_mut())
            && last.snippet.is_empty()
        {
            last.snippet = text_of(snippet);
        }
    }
    hits
}

/// Parses engines where each result is a self-contained block element.
fn parse_blocks(doc: &Selector, block: &str, link: &str, snippet: &str) -> Vec<SearchHit> {
    doc.css(block)
        .iter()
        .filter_map(|result| {
            let mut hit = hit_from_link(result.css(link).first()?)?;
            hit.snippet = result.css(snippet).first().map(text_of).unwrap_or_default();
            Some(hit)
        })
        .collect()
}

fn hit_from_link(anchor: &Selector) -> Option<SearchHit> {
    let href = anchor.attrib().get("href")?.to_string();
    let url = unwrap_redirect(&href)?;
    let title = text_of(anchor);
    (!title.is_empty()).then(|| SearchHit {
        title,
        url: url.into(),
        snippet: String::new(),
    })
}

/// All descendant text of `node`, with runs of whitespace collapsed to single spaces.
fn text_of(node: &Selector) -> String {
    let raw = node.get_all_text(" ", true, &[], true);
    raw.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Resolves an engine result link to the real destination.
///
/// Handles DuckDuckGo's `/l/?uddg=<url>` and Bing's `/ck/a?u=a1<base64url>` click trackers,
/// and protocol-relative hrefs. Returns `None` for non-HTTP targets and for links that stay
/// on the engine's own domain (ads, internal navigation).
fn unwrap_redirect(href: &str) -> Option<Url> {
    let absolute = if href.starts_with("//") {
        format!("https:{href}")
    } else {
        href.to_owned()
    };
    let url = Url::parse(&absolute).ok()?;
    let param = |name: &str| {
        url.query_pairs()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
    };

    let target = match url.host_str()? {
        "duckduckgo.com" | "html.duckduckgo.com" | "lite.duckduckgo.com" => {
            Url::parse(&param("uddg")?).ok()?
        }
        "www.bing.com" | "bing.com" => {
            let encoded = param("u")?;
            let bytes = URL_SAFE_NO_PAD.decode(encoded.strip_prefix("a1")?).ok()?;
            Url::parse(std::str::from_utf8(&bytes).ok()?).ok()?
        }
        _ => url,
    };

    let is_engine = target
        .host_str()
        .is_some_and(|h| h.ends_with("duckduckgo.com") || h.ends_with("bing.com"));
    (matches!(target.scheme(), "http" | "https") && !is_engine).then_some(target)
}

fn dedup_by_url(hits: Vec<SearchHit>) -> Vec<SearchHit> {
    let mut seen = std::collections::HashSet::new();
    hits.into_iter()
        .filter(|hit| seen.insert(hit.url.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DDG_LITE: &str = r#"<table>
      <tr><td>1.</td><td><a rel="nofollow" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Frust%2Dlang.github.io%2Fasync%2Dbook%2F&amp;rut=abc" class='result-link'>Async <b>Rust</b> book</a></td></tr>
      <tr><td>&nbsp;</td><td class='result-snippet'>Learn   <b>async</b> Rust.</td></tr>
      <tr><td>&nbsp;</td><td><span class='link-text'>rust-lang.github.io</span></td></tr>
      <tr><td>2.</td><td><a href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fduckduckgo.com%2Fy.js%3Fad%3D1" class='result-link'>Sponsored</a></td></tr>
      <tr><td>3.</td><td><a href="https://tokio.rs/" class='result-link'>Tokio</a></td></tr>
    </table>"#;

    const DDG_HTML: &str = r#"<div class="result result--ad"><a class="result__a" href="https://ads.example/">Ad</a></div>
      <div class="result results_links"><h2><a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2F">Example</a></h2>
      <a class="result__snippet">An example.</a></div>"#;

    const BING: &str = r#"<ol><li class="b_algo"><h2><a href="https://www.bing.com/ck/a?!&amp;p=x&amp;u=a1aHR0cHM6Ly9ydXN0LWxhbmcub3JnLw&amp;ntb=1"><strong>Rust</strong> Programming Language</a></h2>
      <div class="b_caption"><p>Rust is blazingly fast.</p></div></li></ol>"#;

    #[test]
    fn parses_duckduckgo_lite() {
        let hits = SearchEngine::DuckduckgoLite.parse(DDG_LITE);
        assert_eq!(
            hits,
            vec![
                SearchHit {
                    title: "Async Rust book".into(),
                    url: "https://rust-lang.github.io/async-book/".into(),
                    snippet: "Learn async Rust.".into(),
                },
                SearchHit {
                    title: "Tokio".into(),
                    url: "https://tokio.rs/".into(),
                    snippet: String::new()
                },
            ]
        );
    }

    #[test]
    fn parses_duckduckgo_html_and_skips_ads() {
        let hits = SearchEngine::DuckduckgoHtml.parse(DDG_HTML);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].url, "https://example.com/");
        assert_eq!(hits[0].snippet, "An example.");
    }

    #[test]
    fn parses_bing_and_decodes_tracker() {
        let hits = SearchEngine::Bing.parse(BING);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].title, "Rust Programming Language");
        assert_eq!(hits[0].url, "https://rust-lang.org/");
        assert_eq!(hits[0].snippet, "Rust is blazingly fast.");
    }

    #[test]
    fn challenge_page_yields_no_hits() {
        let html = r#"<form id="challenge-form" action="//duckduckgo.com/anomaly.js"></form>"#;
        assert!(SearchEngine::DuckduckgoHtml.parse(html).is_empty());
    }

    #[test]
    fn results_url_encodes_query() {
        let url = SearchEngine::DuckduckgoLite.results_url("rust & tokio");
        assert_eq!(
            url.as_str(),
            "https://lite.duckduckgo.com/lite/?q=rust+%26+tokio"
        );
    }
}

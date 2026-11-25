//! The MCP tool surface exposed to Claude.
//!
//! [`WebMcp`] implements [`rmcp::ServerHandler`] with these tools:
//!
//! | Tool | Purpose |
//! |---|---|
//! | `web_search` | Search the web; ranked results (title, URL, snippet). |
//! | `fetch_url` | Read a page as Markdown/text/HTML, with paging; logged in when a session exists. |
//! | `fetch_image` | Download an image and return it as image content the model can see. |
//! | `site_login` | Log in to a site with a username/password form; the session is kept. |
//! | `list_site_logins` | Which sites the caller has saved logins or sessions for. |
//! | `send_email` | Send an email with attachments from the operator's account (only when configured). |
//!
//! All traffic goes through the configured proxy via [`Sites`]/[`WebClient`](crate::web::WebClient). Each call acts
//! for the authenticated [`Principal`]: over HTTP it is attached to the request by
//! [`crate::auth::require_auth`] and read from the forwarded request parts; over stdio it is
//! the built-in admin. Failures are logged once, in [`report`].

use base64::{Engine as _, engine::general_purpose::STANDARD};
use rmcp::{
    RoleServer, ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, ContentBlock},
    service::RequestContext,
    tool, tool_handler, tool_router,
};
use serde::Deserialize;

use crate::{
    auth::Principal,
    images::Prepared,
    mail::{Attachment, Email, MailError, Mailer},
    sites::{LoginMode, SiteError, Sites},
    store::Credentials,
    web::{Format, PageRequest},
};

/// Hard ceiling on `web_search` results, regardless of what the model asks for.
const MAX_SEARCH_RESULTS: usize = 25;

/// Arguments for the `web_search` tool.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SearchArgs {
    /// The search query, written as you would type it into a search engine.
    pub query: String,
    /// Maximum number of results to return (1-25, default 10).
    #[serde(default)]
    pub max_results: Option<usize>,
}

/// Arguments for the `fetch_url` tool.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FetchArgs {
    /// Absolute http(s) URL of the page to read.
    pub url: String,
    /// Output format: `markdown` (default), `text`, or `html`.
    #[serde(default)]
    pub format: Format,
    /// Optional CSS selector to return only matching elements (e.g. `article`, `#content`).
    #[serde(default)]
    pub css_selector: Option<String>,
    /// Character offset to start from; use the value suggested in a truncated response.
    #[serde(default)]
    pub start: Option<usize>,
    /// Maximum characters to return (defaults to the server's configured limit).
    #[serde(default)]
    pub max_chars: Option<usize>,
    /// Logged-in browsing. Omit to use a saved session for the site if there is one; `true`
    /// to require being logged in (logs in with saved credentials if needed); `false` to
    /// fetch anonymously.
    #[serde(default)]
    pub use_login: Option<bool>,
}

/// Arguments for the `fetch_image` tool.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ImageArgs {
    /// Absolute http(s) URL of the image (e.g. an `<img src>` from a fetched page).
    pub url: String,
    /// Same as `fetch_url`'s `use_login`.
    #[serde(default)]
    pub use_login: Option<bool>,
}

/// Arguments for the `site_login` tool.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LoginArgs {
    /// The site's login page URL (best), or just its domain (e.g. `example.com`).
    pub site: String,
    /// Username or email. Omit to use the login saved for this site in the web-mcp admin UI.
    #[serde(default)]
    pub username: Option<String>,
    /// Password. Omit to use the saved login. Only pass one the user gave you for this purpose.
    #[serde(default)]
    pub password: Option<String>,
    /// Save the given username/password for future logins (default false).
    #[serde(default)]
    pub save_credentials: bool,
}

/// One or several email addresses. Models pass either form.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum Addresses {
    /// A single address, or several separated by commas.
    One(String),
    /// A list of addresses.
    Many(Vec<String>),
}

impl Default for Addresses {
    fn default() -> Self {
        Self::Many(Vec::new())
    }
}

impl From<Addresses> for Vec<String> {
    fn from(addresses: Addresses) -> Self {
        match addresses {
            Addresses::One(one) => vec![one],
            Addresses::Many(many) => many,
        }
    }
}

/// One attachment for `send_email`: exactly one of `text`, `base64`, or `url`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AttachmentArgs {
    /// File name shown to the recipient, e.g. `report.csv`. Optional for `url` attachments
    /// (defaults to the last part of the URL).
    #[serde(default)]
    pub filename: Option<String>,
    /// MIME type, e.g. `text/csv`. Usually unnecessary: it is detected from the download or
    /// guessed from the file name.
    #[serde(default)]
    pub content_type: Option<String>,
    /// File contents as text (for CSV, Markdown, JSON, iCalendar, source code, …).
    #[serde(default)]
    pub text: Option<String>,
    /// File contents, base64-encoded (for binary files you have the bytes of).
    #[serde(default)]
    pub base64: Option<String>,
    /// URL to download the file from (through the proxy, logged in if a session exists),
    /// e.g. a PDF or image found while browsing.
    #[serde(default)]
    pub url: Option<String>,
}

/// Arguments for the `send_email` tool.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EmailArgs {
    /// Recipient address(es), e.g. `"Ann <ann@example.com>"` or a list.
    pub to: Addresses,
    /// Carbon-copy recipients.
    #[serde(default)]
    pub cc: Addresses,
    /// Blind-copy recipients.
    #[serde(default)]
    pub bcc: Addresses,
    /// Reply-to address, if replies should not go to the sender.
    #[serde(default)]
    pub reply_to: Option<String>,
    /// Subject line.
    pub subject: String,
    /// Plain-text body.
    pub body: String,
    /// Optional HTML version of the body; `body` is still required as the plain-text version.
    #[serde(default)]
    pub html_body: Option<String>,
    /// Files to attach (25 MB total).
    #[serde(default)]
    pub attachments: Vec<AttachmentArgs>,
}

/// MCP server handler. Cheap to clone; the HTTP transport creates one per session.
#[derive(Clone)]
pub struct WebMcp {
    sites: Sites,
    /// Outgoing email; `None` hides the `send_email` tool.
    mailer: Option<Mailer>,
    /// Caller used when the transport carries no authentication (stdio).
    fallback: Option<Principal>,
    tool_router: ToolRouter<Self>,
}

impl WebMcp {
    /// A handler for authenticated HTTP requests. Without a `mailer` there is no
    /// `send_email` tool.
    pub fn new(sites: Sites, mailer: Option<Mailer>) -> Self {
        let mut tool_router = Self::tool_router();
        if mailer.is_none() {
            tool_router.remove_route("send_email");
        }
        Self {
            sites,
            mailer,
            fallback: None,
            tool_router,
        }
    }

    /// A handler that acts as `principal` for every call (stdio mode).
    pub fn acting_as(sites: Sites, mailer: Option<Mailer>, principal: Principal) -> Self {
        Self {
            fallback: Some(principal),
            ..Self::new(sites, mailer)
        }
    }

    /// Turns tool arguments into an attachment, downloading `url` sources as `user`. A
    /// download may use at most `budget` bytes (what is left of the attachment limit).
    async fn attachment(
        &self,
        user: &Principal,
        args: AttachmentArgs,
        budget: usize,
    ) -> Result<Attachment, String> {
        let named = |fallback: &str| {
            args.filename
                .clone()
                .filter(|f| !f.trim().is_empty())
                .unwrap_or_else(|| fallback.to_owned())
        };
        let content_type = args.content_type.as_deref();
        let built = match (args.text, args.base64, args.url) {
            (Some(text), None, None) => Attachment::new(
                &named("attachment.txt"),
                content_type,
                None,
                text.into_bytes(),
            ),
            (None, Some(encoded), None) => {
                let data = STANDARD
                    .decode(encoded.split_whitespace().collect::<String>())
                    .map_err(|e| {
                        format!("attachment {}: invalid base64: {e}", named("attachment"))
                    })?;
                Attachment::new(&named("attachment"), content_type, None, data)
            }
            (None, None, Some(url)) => {
                let download = self
                    .sites
                    .download(user, &url, LoginMode::Auto, budget)
                    .await
                    .map_err(|e| report(&e, "send_email", &url))?;
                let fallback = url::Url::parse(&download.url)
                    .ok()
                    .and_then(|u| {
                        u.path_segments()
                            .and_then(|mut segments| segments.next_back().map(str::to_owned))
                    })
                    .filter(|name| !name.is_empty())
                    .unwrap_or_else(|| "download".to_owned());
                Attachment::new(
                    &named(&fallback),
                    content_type,
                    download.content_type.as_deref(),
                    download.body,
                )
            }
            _ => {
                return Err(
                    "each attachment needs exactly one of `text`, `base64`, or `url`".into(),
                );
            }
        };
        built.map_err(|e| e.to_string())
    }

    /// The caller of the current request.
    fn caller(&self, ctx: &RequestContext<RoleServer>) -> Result<Principal, String> {
        ctx.extensions
            .get::<axum::http::request::Parts>()
            .and_then(|parts| parts.extensions.get::<Principal>().cloned())
            .or_else(|| self.fallback.clone())
            .ok_or_else(|| "unauthenticated request".to_owned())
    }
}

#[tool_router]
impl WebMcp {
    /// Search the web and return a numbered list of results.
    #[tool(
        description = "Search the web (privately, through the user's proxy). Returns a numbered list of results with title, URL and snippet. Follow up with fetch_url to read a result."
    )]
    async fn web_search(&self, Parameters(args): Parameters<SearchArgs>) -> Result<String, String> {
        let limit = args.max_results.unwrap_or(10).clamp(1, MAX_SEARCH_RESULTS);
        let hits = self
            .sites
            .web()
            .search(&args.query, limit)
            .await
            .map_err(|e| report(&SiteError::Web(e), "web_search", &args.query))?;
        Ok(hits
            .iter()
            .enumerate()
            .map(|(i, hit)| {
                format!(
                    "{}. {}\n   {}\n   {}",
                    i + 1,
                    hit.title,
                    hit.url,
                    hit.snippet
                )
            })
            .collect::<Vec<_>>()
            .join("\n\n"))
    }

    /// Fetch a URL and return its readable content.
    #[tool(
        description = "Fetch a web page (through the user's proxy, with browser impersonation) and return its main content as markdown (default), plain text or HTML. Uses the user's saved login session for the site automatically if there is one. Long pages are truncated; the response says which `start` offset to request next. Image URLs in the markdown can be viewed with fetch_image."
    )]
    async fn fetch_url(
        &self,
        Parameters(args): Parameters<FetchArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<String, String> {
        let user = self.caller(&ctx)?;
        let url = args.url.clone();
        let request = PageRequest {
            url: args.url,
            format: args.format,
            selector: args.css_selector.filter(|s| !s.trim().is_empty()),
            start: args.start.unwrap_or(0),
            max_chars: args.max_chars,
        };
        self.sites
            .fetch_page(&user, request, LoginMode::from_flag(args.use_login))
            .await
            .map(|page| page.to_string())
            .map_err(|e| report(&e, "fetch_url", &url))
    }

    /// Fetch an image so the model can see it.
    #[tool(
        description = "Download an image (through the user's proxy, logged in if a session exists) and return it so you can see it. Large images are downscaled to 1568px; SVGs are returned as markup."
    )]
    async fn fetch_image(
        &self,
        Parameters(args): Parameters<ImageArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, String> {
        let user = self.caller(&ctx)?;
        let fetched = self
            .sites
            .fetch_image(&user, &args.url, LoginMode::from_flag(args.use_login))
            .await
            .map_err(|e| report(&e, "fetch_image", &args.url))?;
        let content = match fetched.image {
            Prepared::Raster(image) => {
                let resized = image
                    .resized_from
                    .map(|(w, h)| format!(", downscaled from {w}×{h}"))
                    .unwrap_or_default();
                let caption = format!(
                    "Image from {} ({}×{}, {}{resized}; original {} KB)",
                    fetched.url,
                    image.width,
                    image.height,
                    image.mime,
                    fetched.source_bytes.div_ceil(1024)
                );
                vec![
                    ContentBlock::image(STANDARD.encode(&image.data), image.mime),
                    ContentBlock::text(caption),
                ]
            }
            Prepared::Svg(markup) => vec![ContentBlock::text(format!(
                "SVG image from {}:\n\n{markup}",
                fetched.url
            ))],
        };
        Ok(CallToolResult::success(content))
    }

    /// Log in to a website with a username/password form.
    #[tool(
        description = "Log in to a website so later fetch_url/fetch_image calls see logged-in pages. Uses the username/password saved by the user in the web-mcp admin UI for that site unless you pass them. Works for normal HTML login forms; for JavaScript/CAPTCHA/2FA logins the user must import browser cookies in the admin UI instead. Check list_site_logins first."
    )]
    async fn site_login(
        &self,
        Parameters(args): Parameters<LoginArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<String, String> {
        let user = self.caller(&ctx)?;
        let credentials = match (args.username, args.password) {
            (Some(username), Some(password)) => Some(Credentials { username, password }),
            (None, None) => None,
            _ => {
                return Err(
                    "pass both username and password, or neither to use the saved login".into(),
                );
            }
        };
        self.sites
            .login(&user, &args.site, credentials, args.save_credentials)
            .await
            .map(|outcome| outcome.to_string())
            .map_err(|e| report(&e, "site_login", &args.site))
    }

    /// Send an email from the operator's account.
    #[tool(
        description = "Send an email (with optional attachments) from the user's own email account. Only send when the user asked you to, to recipients they named or confirmed; never invent addresses. Attachments can be text you write (`text`), base64 bytes (`base64`), or files downloaded from a URL (`url`, e.g. a PDF you found). Returns the recipients and Message-ID.",
        annotations(
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn send_email(
        &self,
        Parameters(args): Parameters<EmailArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<String, String> {
        let user = self.caller(&ctx)?;
        let mailer = self
            .mailer
            .as_ref()
            .ok_or("email is not configured on this server")?;
        if !user.can_email {
            tracing::info!(user = %user.name, "email not allowed for this user");
            return Err("this user is not allowed to send email; the admin can allow it in the web-mcp admin UI".into());
        }
        let mut attachments = Vec::with_capacity(args.attachments.len());
        let mut used = 0;
        for attachment in args.attachments {
            let budget = mailer.max_attachment_bytes().saturating_sub(used);
            let attachment = self.attachment(&user, attachment, budget).await?;
            used += attachment.data.len();
            if used > mailer.max_attachment_bytes() {
                return Err(report_mail(&mailer.too_large(used), &user));
            }
            attachments.push(attachment);
        }
        let email = Email {
            to: args.to.into(),
            cc: args.cc.into(),
            bcc: args.bcc.into(),
            reply_to: args.reply_to,
            subject: args.subject,
            text: args.body,
            html: args.html_body,
            attachments,
        };
        let sent = mailer
            .send(email)
            .await
            .map_err(|e| report_mail(&e, &user))?;
        tracing::info!(
            user = %user.name,
            recipients = %sent.recipients.join(", "),
            attachments = sent.attachments,
            attachment_bytes = sent.attachment_bytes,
            message_id = %sent.message_id,
            "sent email"
        );
        Ok(format!(
            "Sent from {} to {} ({} attachment(s), {} KB attached; saved in Sent). Message-ID: {}",
            sent.from,
            sent.recipients.join(", "),
            sent.attachments,
            sent.attachment_bytes.div_ceil(1024),
            sent.message_id
        ))
    }

    /// List the caller's saved site logins and sessions.
    #[tool(
        description = "List the sites the user has saved logins or active sessions for (no passwords are shown). fetch_url uses these sessions automatically."
    )]
    async fn list_site_logins(&self, ctx: RequestContext<RoleServer>) -> Result<String, String> {
        let user = self.caller(&ctx)?;
        let sites = self
            .sites
            .list(&user)
            .await
            .map_err(|e| report(&e, "list_site_logins", &user.name))?;
        if sites.is_empty() {
            return Ok("No saved site logins. The user can add them (or import browser cookies) in the web-mcp admin UI at /admin, or you can call site_login with a username and password.".into());
        }
        Ok(sites
            .iter()
            .map(|site| {
                let login = match (&site.username, site.has_password) {
                    (Some(user), true) => format!("saved login for {user}"),
                    _ => "no saved password".to_owned(),
                };
                let session = match site.cookie_count {
                    0 => "not logged in".to_owned(),
                    n => format!(
                        "session active ({n} cookies, from {})",
                        site.cookies_source.as_deref().unwrap_or("login")
                    ),
                };
                format!("- {}: {login}; {session}", site.domain)
            })
            .collect::<Vec<_>>()
            .join("\n"))
    }
}

/// Logs a failed `send_email` and converts it into the error text returned to the model.
fn report_mail(error: &MailError, user: &Principal) -> String {
    if error.is_bad_input() {
        tracing::info!(user = %user.name, %error, "rejected email");
    } else {
        tracing::error!(user = %user.name, %error, "sending email failed");
    }
    error.to_string()
}

/// Logs a failed tool call and converts it into the error text returned to the model.
fn report(error: &SiteError, tool: &str, target: &str) -> String {
    error.log(tool, target);
    error.to_string()
}

#[tool_handler(
    router = self.tool_router,
    name = "web-mcp",
    instructions = "Web access through a private proxy. Use web_search to find pages, fetch_url to read them, and fetch_image to view images. For sites that need an account, check list_site_logins and use site_login; sessions then apply automatically. If send_email is available, it sends mail from the user's account; only use it when asked."
)]
impl ServerHandler for WebMcp {}

/// Serves [`WebMcp`] over stdin/stdout, acting as `principal`, until the client disconnects.
///
/// # Errors
///
/// Fails if the MCP handshake fails or the transport task panics.
pub async fn serve_stdio(
    sites: Sites,
    mailer: Option<Mailer>,
    principal: Principal,
) -> anyhow::Result<()> {
    let server = WebMcp::acting_as(sites, mailer, principal)
        .serve(rmcp::transport::stdio())
        .await?;
    server.waiting().await?;
    Ok(())
}

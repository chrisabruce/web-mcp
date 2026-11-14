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

/// MCP server handler. Cheap to clone; the HTTP transport creates one per session.
#[derive(Clone)]
pub struct WebMcp {
    sites: Sites,
    /// Caller used when the transport carries no authentication (stdio).
    fallback: Option<Principal>,
    tool_router: ToolRouter<Self>,
}

impl WebMcp {
    /// A handler for authenticated HTTP requests.
    pub fn new(sites: Sites) -> Self {
        Self {
            sites,
            fallback: None,
            tool_router: Self::tool_router(),
        }
    }

    /// A handler that acts as `principal` for every call (stdio mode).
    pub fn acting_as(sites: Sites, principal: Principal) -> Self {
        Self {
            fallback: Some(principal),
            ..Self::new(sites)
        }
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

/// Logs a failed tool call and converts it into the error text returned to the model.
fn report(error: &SiteError, tool: &str, target: &str) -> String {
    error.log(tool, target);
    error.to_string()
}

#[tool_handler(
    router = self.tool_router,
    name = "web-mcp",
    instructions = "Web access through a private proxy. Use web_search to find pages, fetch_url to read them, and fetch_image to view images. For sites that need an account, check list_site_logins and use site_login; sessions then apply automatically."
)]
impl ServerHandler for WebMcp {}

/// Serves [`WebMcp`] over stdin/stdout, acting as `principal`, until the client disconnects.
///
/// # Errors
///
/// Fails if the MCP handshake fails or the transport task panics.
pub async fn serve_stdio(sites: Sites, principal: Principal) -> anyhow::Result<()> {
    let server = WebMcp::acting_as(sites, principal)
        .serve(rmcp::transport::stdio())
        .await?;
    server.waiting().await?;
    Ok(())
}

//! The MCP tool surface exposed to Claude.
//!
//! [`WebMcp`] implements [`rmcp::ServerHandler`] with two tools:
//!
//! * `web_search` — search the web and return ranked results (title, URL, snippet).
//! * `fetch_url` — fetch a page and return its main content as Markdown/text/HTML, with
//!   paging for long documents.
//!
//! Both delegate to [`WebClient`], so all traffic goes through the configured proxy.
//!
//! The same handler is served over stdio ([`serve_stdio`]) or Streamable HTTP
//! ([`crate::http`]); transport is not this module's concern.

use rmcp::{
    ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    tool, tool_handler, tool_router,
};
use serde::Deserialize;

use crate::web::{Format, PageRequest, WebClient, WebError};

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
}

/// MCP server handler holding the shared web client.
///
/// Cheap to clone; the Streamable HTTP transport creates one instance per session.
#[derive(Clone)]
pub struct WebMcp {
    web: WebClient,
    tool_router: ToolRouter<Self>,
}

impl WebMcp {
    /// Creates a handler whose tools use `web` for all network access.
    pub fn new(web: WebClient) -> Self {
        Self {
            web,
            tool_router: Self::tool_router(),
        }
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
            .web
            .search(&args.query, limit)
            .await
            .map_err(|e| report(&e, "web_search", &args.query))?;
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
        description = "Fetch a web page (through the user's proxy, with browser impersonation) and return its main content as markdown (default), plain text or HTML. Long pages are truncated; the response says which `start` offset to request next."
    )]
    async fn fetch_url(&self, Parameters(args): Parameters<FetchArgs>) -> Result<String, String> {
        let url = args.url.clone();
        let request = PageRequest {
            url: args.url,
            format: args.format,
            selector: args.css_selector.filter(|s| !s.trim().is_empty()),
            start: args.start.unwrap_or(0),
            max_chars: args.max_chars,
        };
        self.web
            .fetch_page(request)
            .await
            .map(|page| page.to_string())
            .map_err(|e| report(&e, "fetch_url", &url))
    }
}

/// Logs a failed tool call and converts it into the error text returned to the model.
fn report(error: &WebError, tool: &str, target: &str) -> String {
    error.log(tool, target);
    error.to_string()
}

#[tool_handler(
    router = self.tool_router,
    name = "web-mcp",
    instructions = "Web access through a private proxy. Use web_search to find pages, then fetch_url to read them."
)]
impl ServerHandler for WebMcp {}

/// Serves [`WebMcp`] over stdin/stdout until the client disconnects.
///
/// Used when a client launches the binary directly as a stdio MCP server.
///
/// # Errors
///
/// Fails if the MCP handshake fails or the transport task panics.
pub async fn serve_stdio(web: WebClient) -> anyhow::Result<()> {
    let server = WebMcp::new(web).serve(rmcp::transport::stdio()).await?;
    server.waiting().await?;
    Ok(())
}

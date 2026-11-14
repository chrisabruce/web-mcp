//! `web-mcp` — an MCP server that gives Claude web search and page reading through a proxy.
//!
//! # Architecture
//!
//! ```text
//!  Claude ──MCP over HTTPS (/mcp, bearer or OAuth token) or stdio──▶ mcp::WebMcp
//!                                                              │
//!                                     web::WebClient ◀─────────┘
//!                                       │        └─▶ search::SearchEngine (result parsers)
//!                                       └──SOCKS proxy──▶ the web
//! ```
//!
//! | Module | Responsibility |
//! |---|---|
//! | [`block`] | Heuristic detection of anti-bot challenges, CAPTCHAs, and WAF denials. |
//! | [`admin`] | Web UI: user keys (admin) and per-user site logins / cookie import. |
//! | [`auth`] | Resolving master token, user keys, and OAuth tokens to a [`auth::Principal`]. |
//! | [`config`] | Flags/env/`.env` settings, proxy URL and token validation. |
//! | [`cookies`] | Per-site cookie jars and browser cookie import formats. |
//! | [`http`] | Streamable HTTP server: `/mcp` (auth, `Host` allowlist) and `/health`. |
//! | [`images`] | Downscaling/converting fetched images for the model. |
//! | [`mcp`] | MCP tool definitions (`web_search`, `fetch_url`) and stdio transport. |
//! | [`oauth`] | Stateless OAuth 2.1 server for Claude Desktop / claude.ai connectors. |
//! | [`search`] | Pure search-result page parsers for each engine. |
//! | [`sites`] | Logged-in browsing: sessions per user and site, automatic form logins. |
//! | [`store`] | SQLite: users, saved logins, sessions; secrets encrypted at rest. |
//! | [`token`] | Stateless HMAC-signed tokens (OAuth, UI sessions). |
//! | [`web`] | All network I/O: fetching, content extraction, search fallback, SSRF guard. |
//!
//! Run `web-mcp --help` for subcommands; without one, the HTTP server starts.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod admin;
mod auth;
mod block;
mod config;
mod cookies;
mod http;
mod images;
mod mcp;
mod oauth;
mod search;
mod sites;
mod store;
mod token;
mod web;

use std::future::Future;

use anyhow::Context as _;
use clap::{Parser, Subcommand};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

use crate::{
    config::Config,
    http::Services,
    store::Store,
    web::{Format, PageRequest, WebClient},
};

/// Command-line interface. Every [`Config`] field is also a global flag.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    #[command(flatten)]
    config: Config,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Serve MCP over Streamable HTTP at `http://BIND/mcp` until SIGINT/SIGTERM (default).
    Serve,
    /// Serve MCP over stdin/stdout (for clients that spawn the server themselves).
    Stdio,
    /// Run a web search and print the results (useful for testing the proxy).
    Search {
        /// Search terms.
        #[arg(required = true)]
        query: Vec<String>,
        /// Maximum number of results.
        #[arg(short = 'n', long, default_value_t = 10)]
        limit: usize,
    },
    /// Fetch a page and print its content (useful for testing the proxy).
    Fetch {
        /// URL to fetch.
        url: String,
        /// Output format.
        #[arg(short, long, value_enum, default_value_t)]
        format: Format,
        /// CSS selector restricting the output.
        #[arg(short, long)]
        selector: Option<String>,
    },
}

fn main() -> anyhow::Result<()> {
    let env_files = config::load_env_files();
    let cli = Cli::parse();
    init_tracing();
    for file in &env_files {
        tracing::info!(file = %file.display(), "loaded environment file");
    }

    let config = cli.config;
    let web = WebClient::new(&config).context("configuring HTTP client")?;

    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => block_on(serve(services(config, web)?)),
        Command::Stdio => {
            let services = services(config, web)?;
            let admin = services.auth.admin();
            block_on(mcp::serve_stdio(services.sites, admin))
        }
        Command::Search { query, limit } => block_on(async move {
            let hits = web.search(&query.join(" "), limit).await?;
            println!("{}", serde_json::to_string_pretty(&hits)?);
            Ok(())
        }),
        Command::Fetch {
            url,
            format,
            selector,
        } => block_on(async move {
            let request = PageRequest {
                url,
                format,
                selector,
                start: 0,
                max_chars: Some(usize::MAX),
            };
            println!("{}", web.fetch_page(request, None).await?);
            Ok(())
        }),
    }
}

/// Opens the database and wires the shared services (requires the master token).
fn services(config: Config, web: WebClient) -> anyhow::Result<Services> {
    let master = config.master_token()?;
    let store = Store::open(&config.data_dir, &master)
        .with_context(|| format!("opening database in {}", config.data_dir.display()))?;
    Ok(Services::new(config, master, web, store))
}

/// HTTP mode (the container entry point): serve until SIGINT/SIGTERM, then drain.
async fn serve(services: Services) -> anyhow::Result<()> {
    let bind = services.config.bind;
    let shutdown = CancellationToken::new();
    tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            if let Err(err) = shutdown_signal().await {
                tracing::error!(%err, "signal handling failed; shutting down");
            }
            shutdown.cancel();
        }
    });
    http::serve(services, shutdown)
        .await
        .with_context(|| format!("serving on {bind}"))
}

/// Resolves on Ctrl-C, or on SIGTERM (what `docker stop` sends) on Unix.
async fn shutdown_signal() -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut terminate =
            signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
        tokio::select! {
            ctrl_c = tokio::signal::ctrl_c() => ctrl_c.context("waiting for Ctrl-C")?,
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c()
        .await
        .context("waiting for Ctrl-C")?;
    tracing::info!("shutting down");
    Ok(())
}

/// Runs `future` to completion on a fresh multi-threaded Tokio runtime.
fn block_on(future: impl Future<Output = anyhow::Result<()>>) -> anyhow::Result<()> {
    tokio::runtime::Runtime::new()
        .context("creating Tokio runtime")?
        .block_on(future)
}

/// Logs to stderr (stdout is reserved for the stdio MCP transport); filter via `RUST_LOG`.
fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();
}

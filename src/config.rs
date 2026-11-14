//! Runtime configuration, sourced from CLI flags, the process environment, and `.env` files.
//!
//! Every setting is declared exactly once, on [`Config`], with its flag name, environment
//! variable, and default. `clap` reads flags first and falls back to the environment, so the
//! `.env` loader in [`load_env_files`] only has to populate the environment *before* argument
//! parsing — no other module knows where a value came from.
//!
//! # `.env` resolution order
//!
//! `dotenvy` never overwrites variables that are already set, so real environment variables
//! (e.g. from Docker/Dokploy) always win. Files are then tried in this order:
//!
//! 1. The path in `WEB_MCP_ENV_FILE`, if set.
//! 2. `./.env` in the current working directory (handy for `cargo run`).

use std::{ffi::OsStr, fmt, marker::PhantomData, net::SocketAddr, path::PathBuf, str::FromStr};

use url::Url;

use crate::search::SearchEngine;

/// URL schemes accepted for the outbound proxy.
///
/// `socks5h` resolves DNS on the proxy side (no local DNS leaks) and is the recommended choice.
const PROXY_SCHEMES: &[&str] = &["socks5", "socks5h", "socks4", "socks4a", "http", "https"];

/// All tunable settings for the server, shared by every subcommand.
///
/// Constructed by `clap` from flags or environment variables; see the crate-level docs for the
/// `.env` loading rules. The struct is cheap to clone and is handed to
/// [`WebClient::new`](crate::web::WebClient::new) and the HTTP
/// [`http`](crate::http) server.
#[derive(Debug, Clone, clap::Args)]
pub struct Config {
    /// Outbound proxy for all web traffic, e.g. `socks5h://user:pass@127.0.0.1:1080`.
    ///
    /// When unset, requests go out directly.
    ///
    /// The provider format `socks5h://host:port:user:pass` is also accepted.
    #[arg(
        long,
        env = "SOCKS_PROXY",
        hide_env_values = true,
        value_parser = SecretParser::<ProxyUrl>::new(),
        global = true
    )]
    pub proxy: Option<ProxyUrl>,

    /// Address the Streamable HTTP MCP endpoint listens on (served at `/mcp`).
    #[arg(
        long,
        env = "WEB_MCP_BIND",
        default_value = "127.0.0.1:8787",
        global = true
    )]
    pub bind: SocketAddr,

    /// Per-request timeout in seconds, covering connect, TLS, and body download.
    #[arg(
        long,
        env = "WEB_MCP_TIMEOUT_SECS",
        default_value_t = 30,
        global = true
    )]
    pub timeout_secs: u64,

    /// Total attempts per request (1 disables retries).
    #[arg(long, env = "WEB_MCP_RETRIES", default_value_t = 2, global = true)]
    pub retries: u32,

    /// Default cap on characters returned to the model per page.
    #[arg(
        long,
        env = "WEB_MCP_MAX_CHARS",
        default_value_t = 40_000,
        global = true
    )]
    pub max_chars: usize,

    /// Browser whose TLS/HTTP2 fingerprint is impersonated (`chrome`, `firefox`, `safari`, `none`).
    #[arg(
        long,
        env = "WEB_MCP_IMPERSONATE",
        default_value = "chrome",
        global = true
    )]
    pub impersonate: String,

    /// Search engines to try, in order, until one returns results (comma-separated).
    #[arg(
        long,
        env = "WEB_MCP_SEARCH_ENGINES",
        value_delimiter = ',',
        default_value = "duckduckgo-lite,bing,duckduckgo-html",
        global = true
    )]
    pub search_engines: Vec<SearchEngine>,

    /// Bearer token clients must send (`Authorization: Bearer <token>`) to use `/mcp`.
    ///
    /// Required for `serve` and `stdio`; at least 32 characters. Also the admin's key for the
    /// web UI and the root of the encryption key for stored site logins.
    /// Generate one with `openssl rand -hex 32`.
    #[arg(
        long,
        env = "WEB_MCP_AUTH_TOKEN",
        hide_env_values = true,
        value_parser = SecretParser::<Secret>::new(),
        global = true
    )]
    pub auth_token: Option<Secret>,

    /// `Host` header values accepted on `/mcp` (DNS-rebinding protection), comma-separated.
    ///
    /// Behind a reverse proxy, set this to your public domain. `*` disables the check.
    #[arg(
        long,
        env = "WEB_MCP_ALLOWED_HOSTS",
        value_delimiter = ',',
        default_value = "localhost,127.0.0.1,::1",
        global = true
    )]
    pub allowed_hosts: Vec<String>,

    /// Public base URL of this server, e.g. `https://mcp.example.com`.
    ///
    /// Setting it (together with `auth_token`) enables OAuth so Claude Desktop / claude.ai
    /// custom connectors can sign in, and adds its host to `allowed_hosts`.
    #[arg(long, env = "WEB_MCP_PUBLIC_URL", value_parser = parse_public_url, global = true)]
    pub public_url: Option<Url>,

    /// Directory for the SQLite database (user keys, saved site logins, sessions).
    #[arg(long, env = "WEB_MCP_DATA_DIR", default_value = "data", global = true)]
    pub data_dir: PathBuf,
}

impl Config {
    /// Returns the master token, which every serving mode requires: it authenticates the
    /// admin and keys the encryption of stored site passwords and cookies.
    ///
    /// # Errors
    ///
    /// [`ConfigError::AuthRequired`] if `WEB_MCP_AUTH_TOKEN` is not set.
    pub fn master_token(&self) -> Result<Secret, ConfigError> {
        self.auth_token.clone().ok_or(ConfigError::AuthRequired)
    }

    /// The MCP endpoint URL clients should use: under the public URL if set, else the bind
    /// address.
    pub fn public_mcp_url(&self) -> String {
        match &self.public_url {
            Some(url) => format!("{}/mcp", url.as_str().trim_end_matches('/')),
            None => format!("http://{}/mcp", self.bind),
        }
    }

    /// `Host` header values accepted on `/mcp`: the configured list plus the public URL's host.
    pub fn effective_allowed_hosts(&self) -> Vec<String> {
        let public = self
            .public_url
            .iter()
            .filter_map(|url| url.host_str().map(str::to_owned));
        self.allowed_hosts
            .iter()
            .map(|h| h.trim().to_owned())
            .chain(public)
            .collect()
    }
}

/// Accepts an absolute `http(s)` URL with a host and no query or fragment.
fn parse_public_url(input: &str) -> Result<Url, String> {
    let url = Url::parse(input.trim()).map_err(|e| e.to_string())?;
    let valid = matches!(url.scheme(), "http" | "https")
        && url.host_str().is_some()
        && url.query().is_none()
        && url.fragment().is_none();
    valid
        .then_some(url)
        .ok_or_else(|| "expected an http(s) base URL such as https://mcp.example.com".into())
}

/// Invalid combinations of settings, detected after parsing.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The master token is missing.
    #[error(
        "WEB_MCP_AUTH_TOKEN is required: it is the admin login and encrypts stored site \
         logins. Generate one with `openssl rand -hex 32`"
    )]
    AuthRequired,
}

/// Minimum accepted length for [`Secret`] tokens.
const MIN_SECRET_LEN: usize = 32;

/// A bearer token that never appears in logs or `Debug` output.
#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    /// The raw secret, for key derivation. Never log the result.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Compares `candidate` with the secret in constant time (with respect to content).
    pub fn matches(&self, candidate: &str) -> bool {
        use subtle::ConstantTimeEq as _;
        self.0.as_bytes().ct_eq(candidate.as_bytes()).into()
    }
}

impl FromStr for Secret {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.len() < MIN_SECRET_LEN {
            return Err(format!(
                "token must be at least {MIN_SECRET_LEN} characters"
            ));
        }
        Ok(Self(s.to_owned()))
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***)")
    }
}

/// A validated proxy URL whose scheme is one of [`PROXY_SCHEMES`].
///
/// Credentials embedded in the URL are kept for the HTTP client but redacted by the
/// [`Display`](fmt::Display) impl, so the value is always safe to log.
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyUrl(Url);

impl ProxyUrl {
    /// The full URL, including credentials, for handing to the HTTP client.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Reasons a proxy URL can be rejected.
#[derive(Debug, thiserror::Error)]
pub enum ProxyUrlError {
    /// The string is not a URL at all.
    #[error("invalid proxy URL: {0}")]
    Parse(#[from] url::ParseError),
    /// The scheme is not a supported proxy protocol.
    #[error("unsupported proxy scheme `{0}` (expected one of: {schemes})", schemes = PROXY_SCHEMES.join(", "))]
    Scheme(String),
    /// No host was given.
    #[error("proxy URL is missing a host")]
    MissingHost,
}

impl FromStr for ProxyUrl {
    type Err = ProxyUrlError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let url = match from_provider_format(s) {
            Some(url) => url,
            None => Url::parse(s)?,
        };
        if !PROXY_SCHEMES.contains(&url.scheme()) {
            return Err(ProxyUrlError::Scheme(url.scheme().to_owned()));
        }
        if url.host_str().is_none_or(str::is_empty) {
            return Err(ProxyUrlError::MissingHost);
        }
        Ok(Self(url))
    }
}

/// Converts the `scheme://host:port:user:pass` format used by many proxy providers into a
/// standard `scheme://user:pass@host:port` URL. Returns `None` if `s` is not in that format.
fn from_provider_format(s: &str) -> Option<Url> {
    let (scheme, rest) = s.split_once("://")?;
    if rest.contains('@') {
        return None;
    }
    let mut parts = rest.splitn(4, ':');
    let (host, port, user, pass) = (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut url = Url::parse(&format!("{scheme}://{host}:{port}")).ok()?;
    url.set_username(user).ok()?;
    url.set_password(Some(pass)).ok()?;
    Some(url)
}

/// A clap value parser for settings that contain credentials.
///
/// clap's default errors quote the rejected value (`invalid value '<value>' for …`), which
/// would write passwords into container logs. This parser reports the setting and the reason
/// only.
#[derive(Debug)]
struct SecretParser<T>(PhantomData<fn() -> T>);

impl<T> SecretParser<T> {
    const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<T> Clone for SecretParser<T> {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl<T> clap::builder::TypedValueParser for SecretParser<T>
where
    T: FromStr + Clone + Send + Sync + 'static,
    T::Err: fmt::Display,
{
    type Value = T;

    fn parse_ref(
        &self,
        _cmd: &clap::Command,
        arg: Option<&clap::Arg>,
        value: &OsStr,
    ) -> Result<T, clap::Error> {
        let setting = arg.map_or_else(String::new, |arg| {
            let flag = arg.get_long().map(|l| format!("--{l}")).unwrap_or_default();
            match arg.get_env() {
                Some(env) => format!("{} / {flag}", env.to_string_lossy()),
                None => flag,
            }
        });
        value
            .to_str()
            .ok_or_else(|| "not valid UTF-8".to_owned())
            .and_then(|text| text.parse::<T>().map_err(|e| e.to_string()))
            .map_err(|reason| {
                clap::Error::raw(
                    clap::error::ErrorKind::ValueValidation,
                    format!("invalid {setting} (value hidden): {reason}\n"),
                )
            })
    }
}

impl fmt::Display for ProxyUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut redacted = self.0.clone();
        if redacted.password().is_some() {
            // Setting a password on a URL that already has a host cannot fail.
            let _ = redacted.set_password(Some("***"));
        }
        f.write_str(redacted.as_str())
    }
}

impl fmt::Debug for ProxyUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProxyUrl({self})")
    }
}

/// Loads `.env` files into the process environment, in the order described in the module docs.
///
/// Must run before [`clap::Parser::parse`] so that `env = "..."` fallbacks see the values.
/// Returns the files that were actually loaded, for logging once tracing is initialised.
pub fn load_env_files() -> Vec<PathBuf> {
    let explicit = std::env::var_os("WEB_MCP_ENV_FILE").map(PathBuf::from);
    let candidates = explicit.into_iter().chain(Some(PathBuf::from(".env")));

    candidates
        .filter(|path| dotenvy::from_path(path).is_ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_socks_schemes() {
        for url in [
            "socks5://127.0.0.1:1080",
            "socks5h://u:p@proxy:9050",
            "http://p:8080",
        ] {
            assert!(url.parse::<ProxyUrl>().is_ok(), "{url}");
        }
    }

    #[test]
    fn rejects_unknown_scheme() {
        assert!(matches!(
            "ftp://proxy:21".parse::<ProxyUrl>(),
            Err(ProxyUrlError::Scheme(s)) if s == "ftp"
        ));
    }

    #[test]
    fn secret_is_redacted_and_compared() {
        let token = "a".repeat(MIN_SECRET_LEN);
        let secret: Secret = token.parse().unwrap();
        assert!(secret.matches(&token));
        assert!(!secret.matches("a"));
        assert!(!format!("{secret:?}").contains(&token));
        assert!("short".parse::<Secret>().is_err());
    }

    #[test]
    fn accepts_provider_format() {
        let proxy: ProxyUrl = "socks5h://gate.example.com:10010:user1:p=ss:word"
            .parse()
            .unwrap();
        assert_eq!(
            proxy.as_str(),
            "socks5h://user1:p%3Dss%3Aword@gate.example.com:10010"
        );
        assert_eq!(
            proxy.to_string(),
            "socks5h://user1:***@gate.example.com:10010"
        );
    }

    #[test]
    fn errors_never_echo_secrets() {
        use clap::Parser;
        #[derive(Debug, Parser)]
        struct Cli {
            #[command(flatten)]
            config: Config,
        }
        for args in [
            [
                "test",
                "--proxy",
                "socks5h://host:notaport:user:hunter2hunter2",
            ],
            ["test", "--auth-token", "hunter2hunter2"],
        ] {
            let err = Cli::try_parse_from(args).unwrap_err().to_string();
            assert!(!err.contains("hunter2"), "{err}");
            assert!(err.contains("value hidden"), "{err}");
        }
    }

    #[test]
    fn display_redacts_password() {
        let proxy: ProxyUrl = "socks5h://alice:hunter2@proxy:1080".parse().unwrap();
        let shown = proxy.to_string();
        assert!(!shown.contains("hunter2"));
        assert!(shown.contains("alice:***@proxy"));
        assert!(proxy.as_str().contains("hunter2"));
    }
}

//! The Streamable HTTP transport: an axum server exposing the MCP endpoint.
//!
//! Routes:
//!
//! | Path | Auth | Purpose |
//! |---|---|---|
//! | `/mcp` | `Authorization: Bearer <token>` when a token is configured | MCP Streamable HTTP endpoint serving [`WebMcp`]. |
//! | `/health` | none | Liveness probe for container health checks; returns `ok`. |
//!
//! `/mcp` is additionally protected by rmcp's `Host` header allowlist
//! ([`Config::allowed_hosts`]) against DNS rebinding. [`serve`] runs until its
//! [`CancellationToken`] is cancelled, then drains in-flight requests.

use std::sync::Arc;

use axum::{
    Router,
    extract::{Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::{
    config::{Config, Secret},
    mcp::WebMcp,
    oauth::OAuth,
    web::WebClient,
};

/// Binds [`Config::bind`] and serves until `shutdown` is cancelled.
///
/// # Errors
///
/// Fails if the address cannot be bound or the server hits a fatal I/O error.
pub async fn serve(
    config: &Config,
    web: WebClient,
    shutdown: CancellationToken,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(config.bind).await?;
    info!(addr = %listener.local_addr()?, "MCP endpoint listening on /mcp");
    let app = router(config, web, shutdown.child_token());
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown.cancelled_owned())
        .await?;
    info!("MCP endpoint stopped");
    Ok(())
}

/// Builds the application router. Cancelling `cancel` closes all MCP sessions.
fn router(config: &Config, web: WebClient, cancel: CancellationToken) -> Router {
    let mcp = StreamableHttpService::new(
        move || Ok(WebMcp::new(web.clone())),
        Arc::new(LocalSessionManager::default()),
        mcp_transport_config(config, cancel),
    );

    let oauth = match (&config.public_url, &config.auth_token) {
        (Some(public_url), Some(token)) => {
            info!(%public_url, "OAuth enabled for Claude Desktop / claude.ai connectors");
            Some(Arc::new(OAuth::new(public_url, token)))
        }
        _ => None,
    };
    let auth = Arc::new(Auth {
        token: config.auth_token.clone(),
        oauth: oauth.clone(),
    });

    let mut router = Router::new().nest_service("/mcp", mcp);
    if auth.token.is_some() {
        router = router.layer(middleware::from_fn_with_state(auth, require_auth));
    }
    // Merged after the auth layer: discovery, login, and health need no token.
    if let Some(oauth) = oauth {
        router = router.merge(oauth.routes());
    }
    router.route("/health", get(|| async { "ok" }))
}

/// rmcp transport settings: `Host` allowlist (`*` disables it) and shutdown token.
fn mcp_transport_config(config: &Config, cancel: CancellationToken) -> StreamableHttpServerConfig {
    let base = StreamableHttpServerConfig::default().with_cancellation_token(cancel);
    let hosts = config.effective_allowed_hosts();
    if hosts.iter().any(|host| host == "*") {
        base.disable_allowed_hosts()
    } else {
        base.with_allowed_hosts(hosts)
    }
}

/// Credentials accepted on `/mcp`.
struct Auth {
    /// Static bearer token (Claude Code and other header-capable clients).
    token: Option<Secret>,
    /// OAuth access tokens (Claude Desktop / claude.ai connectors), when enabled.
    oauth: Option<Arc<OAuth>>,
}

impl Auth {
    fn accepts(&self, bearer: &str) -> bool {
        self.token.as_ref().is_some_and(|t| t.matches(bearer))
            || self
                .oauth
                .as_ref()
                .is_some_and(|o| o.verify_access_token(bearer))
    }
}

/// Middleware rejecting requests without a valid `Authorization: Bearer` credential.
///
/// With OAuth enabled the 401 advertises the resource metadata URL, which is how MCP clients
/// discover where to sign in.
async fn require_auth(State(auth): State<Arc<Auth>>, request: Request, next: Next) -> Response {
    let authorized = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|bearer| auth.accepts(bearer.trim()));
    if authorized {
        return next.run(request).await;
    }
    let challenge = match &auth.oauth {
        Some(oauth) => format!(
            r#"Bearer resource_metadata="{}""#,
            oauth.resource_metadata_url()
        ),
        None => "Bearer".to_owned(),
    };
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, challenge)],
        "unauthorized\n",
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        config: Config,
    }

    /// Starts the router on an ephemeral port and returns its address.
    async fn spawn_app() -> (std::net::SocketAddr, CancellationToken) {
        let config = TestCli::parse_from(["test", "--auth-token", TOKEN]).config;
        let web = WebClient::new(&config).unwrap();
        let cancel = CancellationToken::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = router(&config, web, cancel.child_token());
        let shutdown = cancel.clone();
        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown.cancelled_owned())
                .await
        });
        (addr, cancel)
    }

    /// Sends a raw HTTP/1.0 request and returns the full response text.
    async fn request(
        addr: std::net::SocketAddr,
        method: &str,
        path: &str,
        auth: Option<&str>,
    ) -> String {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let auth = auth
            .map(|t| format!("Authorization: Bearer {t}\r\n"))
            .unwrap_or_default();
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
        let req = format!(
            "{method} {path} HTTP/1.0\r\nHost: localhost\r\n{auth}Content-Type: application/json\r\n\
             Accept: application/json, text/event-stream\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    }

    #[tokio::test]
    async fn health_is_public_and_mcp_requires_token() {
        let (addr, cancel) = spawn_app().await;

        let health = request(addr, "GET", "/health", None).await;
        assert!(
            health.starts_with("HTTP/1.0 200") && health.ends_with("ok"),
            "{health}"
        );

        let anonymous = request(addr, "POST", "/mcp", None).await;
        assert!(anonymous.starts_with("HTTP/1.0 401"), "{anonymous}");

        let wrong = request(addr, "POST", "/mcp", Some("not-the-token")).await;
        assert!(wrong.starts_with("HTTP/1.0 401"), "{wrong}");

        let authorized = request(addr, "POST", "/mcp", Some(TOKEN)).await;
        assert!(!authorized.starts_with("HTTP/1.0 401"), "{authorized}");

        cancel.cancel();
    }

    mod oauth_flow {
        use super::*;
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use http_body_util::BodyExt as _;
        use sha2::{Digest as _, Sha256};
        use tower::ServiceExt as _;

        const PUBLIC: &str = "https://mcp.example.com";
        const REDIRECT: &str = "https://claude.ai/api/mcp/auth_callback";
        const VERIFIER: &str = "a-sufficiently-long-pkce-code-verifier-0123456789";

        fn app() -> Router {
            let config =
                TestCli::parse_from(["test", "--auth-token", TOKEN, "--public-url", PUBLIC]).config;
            let web = WebClient::new(&config).unwrap();
            router(&config, web, CancellationToken::new())
        }

        async fn send(
            app: &Router,
            req: Request<Body>,
        ) -> (StatusCode, axum::http::HeaderMap, String) {
            let res = app.clone().oneshot(req).await.unwrap();
            let (parts, body) = res.into_parts();
            let bytes = body.collect().await.unwrap().to_bytes();
            (
                parts.status,
                parts.headers,
                String::from_utf8_lossy(&bytes).into_owned(),
            )
        }

        fn form(path: &str, body: String) -> Request<Body> {
            Request::post(path)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap()
        }

        fn mcp_ping(bearer: &str) -> Request<Body> {
            Request::post("/mcp")
                .header("host", "mcp.example.com")
                .header("authorization", format!("Bearer {bearer}"))
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
                ))
                .unwrap()
        }

        fn enc(value: &str) -> String {
            url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
        }

        /// Extracts `name="request" value="…"` from the login page.
        fn hidden_request(html: &str) -> String {
            let start = html.find(r#"name="request" value=""#).unwrap() + 22;
            html[start..].split('"').next().unwrap().to_owned()
        }

        #[tokio::test]
        async fn claude_connector_flow() {
            let app = app();

            // 1. Unauthenticated /mcp points at the resource metadata.
            let (status, headers, _) = send(&app, mcp_ping("nope")).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            let challenge = headers["www-authenticate"].to_str().unwrap();
            assert!(
                challenge.contains("https://mcp.example.com/.well-known/oauth-protected-resource")
            );

            // 2. Discovery documents.
            let (_, _, prm) = send(
                &app,
                Request::get("/.well-known/oauth-protected-resource")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert!(
                prm.contains(r#""authorization_servers":["https://mcp.example.com"]"#),
                "{prm}"
            );
            let (_, _, asm) = send(
                &app,
                Request::get("/.well-known/oauth-authorization-server")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert!(
                asm.contains(r#""token_endpoint":"https://mcp.example.com/token""#),
                "{asm}"
            );

            // 3. Dynamic client registration.
            let reg = Request::post("/register")
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"client_name":"Claude <b>","redirect_uris":["{REDIRECT}"]}}"#
                )))
                .unwrap();
            let (status, _, body) = send(&app, reg).await;
            assert_eq!(status, StatusCode::CREATED, "{body}");
            let client: serde_json::Value = serde_json::from_str(&body).unwrap();
            let client_id = client["client_id"].as_str().unwrap().to_owned();

            // 4. Login page (client name is escaped).
            let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER));
            let authorize = format!(
                "/authorize?response_type=code&client_id={}&redirect_uri={}&code_challenge={challenge}&code_challenge_method=S256&state=xyz",
                enc(&client_id),
                enc(REDIRECT)
            );
            let (status, _, page) =
                send(&app, Request::get(&authorize).body(Body::empty()).unwrap()).await;
            assert_eq!(status, StatusCode::OK, "{page}");
            assert!(page.contains("Claude &lt;b&gt;") && page.contains("claude.ai"));
            let request = hidden_request(&page);

            // 5. Wrong password is rejected; the right one redirects with a code.
            let (status, _, _) = send(
                &app,
                form(
                    "/authorize",
                    format!("request={}&password=wrong", enc(&request)),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            let (status, headers, _) = send(
                &app,
                form(
                    "/authorize",
                    format!("request={}&password={TOKEN}", enc(&request)),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::SEE_OTHER);
            let location = url::Url::parse(headers["location"].to_str().unwrap()).unwrap();
            assert!(location.as_str().starts_with(REDIRECT));
            let param = |name: &str| {
                location
                    .query_pairs()
                    .find(|(k, _)| k == name)
                    .unwrap()
                    .1
                    .into_owned()
            };
            assert_eq!(param("state"), "xyz");
            let code = param("code");

            // 6. Token exchange: bad verifier fails, good verifier succeeds.
            let exchange = |verifier: &str| {
                form(
                    "/token",
                    format!(
                        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&code_verifier={verifier}",
                        enc(&code),
                        enc(REDIRECT),
                        enc(&client_id)
                    ),
                )
            };
            let (status, _, _) = send(&app, exchange("wrong-verifier")).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            let (status, _, body) = send(&app, exchange(VERIFIER)).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let tokens: serde_json::Value = serde_json::from_str(&body).unwrap();
            let access = tokens["access_token"].as_str().unwrap();
            let refresh = tokens["refresh_token"].as_str().unwrap();

            // 7. The access token opens /mcp; a refresh token or client_id does not.
            let (status, _, body) = send(&app, mcp_ping(access)).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            for not_access in [refresh, client_id.as_str(), code.as_str()] {
                let (status, _, _) = send(&app, mcp_ping(not_access)).await;
                assert_eq!(status, StatusCode::UNAUTHORIZED);
            }

            // 8. Refresh yields a working access token.
            let (status, _, body) = send(
                &app,
                form(
                    "/token",
                    format!("grant_type=refresh_token&refresh_token={}", enc(refresh)),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let renewed: serde_json::Value = serde_json::from_str(&body).unwrap();
            let (status, _, _) =
                send(&app, mcp_ping(renewed["access_token"].as_str().unwrap())).await;
            assert_eq!(status, StatusCode::OK);

            // 9. The static token still works (Claude Code).
            let (status, _, _) = send(&app, mcp_ping(TOKEN)).await;
            assert_eq!(status, StatusCode::OK);
        }

        #[tokio::test]
        async fn rejects_unregistered_redirect() {
            let app = app();
            let reg = Request::post("/register")
                .header("content-type", "application/json")
                .body(Body::from(format!(r#"{{"redirect_uris":["{REDIRECT}"]}}"#)))
                .unwrap();
            let (_, _, body) = send(&app, reg).await;
            let client: serde_json::Value = serde_json::from_str(&body).unwrap();
            let authorize = format!(
                "/authorize?response_type=code&client_id={}&redirect_uri={}&code_challenge=abc&code_challenge_method=S256",
                enc(client["client_id"].as_str().unwrap()),
                enc("https://evil.example/steal")
            );
            let (status, _, _) =
                send(&app, Request::get(&authorize).body(Body::empty()).unwrap()).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);

            let insecure = Request::post("/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"redirect_uris":["http://evil.example/cb"]}"#,
                ))
                .unwrap();
            let (status, _, _) = send(&app, insecure).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }
    }
}

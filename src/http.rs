//! The Streamable HTTP transport: an axum server exposing the MCP endpoint.
//!
//! Routes:
//!
//! | Path | Auth | Purpose |
//! |---|---|---|
//! | `/mcp` | bearer: master token, user key, or OAuth access token | MCP Streamable HTTP endpoint serving [`WebMcp`]. |
//! | `/admin/…` | UI session cookie | User keys and site logins ([`crate::admin`]). |
//! | `/.well-known/…`, `/register`, `/authorize`, `/token` | none | OAuth, when `WEB_MCP_PUBLIC_URL` is set ([`crate::oauth`]). |
//! | `/health` | none | Liveness probe for container health checks; returns `ok`. |
//!
//! `/mcp` is additionally protected by rmcp's `Host` header allowlist
//! ([`Config::allowed_hosts`]) against DNS rebinding. [`serve`] runs until its
//! [`CancellationToken`] is cancelled, then drains in-flight requests.

use std::sync::Arc;

use axum::{Router, middleware, routing::get};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::{
    admin::{self, AdminState},
    auth::{Authenticator, McpAuth, require_auth},
    config::{Config, Secret},
    mcp::WebMcp,
    oauth::OAuth,
    sites::Sites,
    store::Store,
    web::WebClient,
};

/// Everything the server needs, built once at startup and shared by all routes.
#[derive(Clone)]
pub struct Services {
    /// Settings.
    pub config: Arc<Config>,
    /// Credential resolution (master token, user keys, OAuth tokens).
    pub auth: Authenticator,
    /// Logged-in and anonymous browsing.
    pub sites: Sites,
}

impl Services {
    /// Wires the services together. `master` is the validated `WEB_MCP_AUTH_TOKEN`.
    pub fn new(config: Config, master: Secret, web: WebClient, store: Store) -> Self {
        Self {
            auth: Authenticator::new(master, store.clone()),
            sites: Sites::new(web, store),
            config: Arc::new(config),
        }
    }
}

/// Binds [`Config::bind`] and serves until `shutdown` is cancelled.
///
/// # Errors
///
/// Fails if the address cannot be bound or the server hits a fatal I/O error.
pub async fn serve(services: Services, shutdown: CancellationToken) -> std::io::Result<()> {
    let listener = TcpListener::bind(services.config.bind).await?;
    info!(addr = %listener.local_addr()?, "MCP endpoint on /mcp, admin UI on /admin");
    let app = router(&services, shutdown.child_token());
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown.cancelled_owned())
        .await?;
    info!("MCP endpoint stopped");
    Ok(())
}

/// Builds the application router. Cancelling `cancel` closes all MCP sessions.
fn router(services: &Services, cancel: CancellationToken) -> Router {
    let config = &services.config;
    let sites = services.sites.clone();
    let mcp = StreamableHttpService::new(
        move || Ok(WebMcp::new(sites.clone())),
        Arc::new(LocalSessionManager::default()),
        mcp_transport_config(config, cancel),
    );

    let oauth = config.public_url.as_ref().map(|public_url| {
        info!(%public_url, "OAuth enabled for Claude Desktop / claude.ai connectors");
        Arc::new(OAuth::new(public_url, services.auth.clone()))
    });
    let mcp_auth = Arc::new(McpAuth {
        auth: services.auth.clone(),
        resource_metadata: oauth.as_ref().map(|o| o.resource_metadata_url()),
    });
    let admin = Arc::new(AdminState {
        auth: services.auth.clone(),
        sites: services.sites.clone(),
        secure_cookies: config
            .public_url
            .as_ref()
            .is_some_and(|u| u.scheme() == "https"),
        mcp_url: config.public_mcp_url(),
    });

    let mut router = Router::new()
        .nest_service("/mcp", mcp)
        .layer(middleware::from_fn_with_state(mcp_auth, require_auth));
    // Merged after the auth layer: OAuth, the UI (own cookie auth), and health need no bearer.
    if let Some(oauth) = oauth {
        router = router.merge(oauth.routes());
    }
    router
        .merge(admin::routes(admin))
        .route("/health", get(|| async { "ok" }))
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

    /// Services over an in-memory store, with extra CLI `args`.
    fn services(args: &[&str]) -> Services {
        let argv = ["test", "--auth-token", TOKEN].iter().chain(args).copied();
        let config = TestCli::parse_from(argv).config;
        let master: Secret = TOKEN.parse().unwrap();
        let web = WebClient::new(&config).unwrap();
        Services::new(config, master.clone(), web, Store::in_memory(&master))
    }

    /// Starts the router on an ephemeral port and returns its address.
    async fn spawn_app() -> (std::net::SocketAddr, CancellationToken) {
        let cancel = CancellationToken::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = router(&services(&[]), cancel.child_token());
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
            router(
                &services(&["--public-url", PUBLIC]),
                CancellationToken::new(),
            )
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

        // ---- admin UI and user keys -------------------------------------------------------

        /// A same-origin form POST carrying the UI session `cookie`.
        fn ui_post(path: &str, body: String, cookie: &str) -> Request<Body> {
            Request::post(path)
                .header("host", "mcp.example.com")
                // Exactly what browsers send for a form POST from a same-origin page.
                .header("origin", "null")
                .header("sec-fetch-site", "same-origin")
                .header("cookie", cookie)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap()
        }

        fn ui_get(path: &str, cookie: &str) -> Request<Body> {
            Request::get(path)
                .header("cookie", cookie)
                .body(Body::empty())
                .unwrap()
        }

        /// Signs in to the UI with `key`; returns the `name=value` session cookie.
        async fn ui_sign_in(app: &Router, key: &str) -> String {
            let (status, headers, _) = send(
                app,
                ui_post("/admin/login", format!("key={}", enc(key)), ""),
            )
            .await;
            assert_eq!(status, StatusCode::SEE_OTHER);
            let set = headers["set-cookie"].to_str().unwrap();
            assert!(
                set.contains("HttpOnly")
                    && set.contains("SameSite=Strict")
                    && set.contains("Secure")
            );
            set.split(';').next().unwrap().to_owned()
        }

        #[tokio::test]
        async fn admin_creates_keys_users_stay_private_and_revocation_is_immediate() {
            let services = services(&["--public-url", PUBLIC]);
            let app = router(&services, CancellationToken::new());

            // Unauthenticated UI access redirects to sign-in; a bad key is rejected.
            let (status, headers, _) = send(&app, ui_get("/admin", "")).await;
            assert_eq!(
                (status, headers["location"].to_str().unwrap()),
                (StatusCode::SEE_OTHER, "/admin/login")
            );
            let (status, _, _) = send(&app, ui_post("/admin/login", "key=wrong".into(), "")).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);

            // The admin creates a key for alice; it is shown once.
            let admin = ui_sign_in(&app, TOKEN).await;
            let (status, _, page) =
                send(&app, ui_post("/admin/users", "name=alice".into(), &admin)).await;
            assert_eq!(status, StatusCode::OK);
            let start = page.find("wmk_").expect("new key shown");
            let mut alice_key = page[start..start + 68].to_owned();

            // Cross-origin form posts are refused even with a valid session.
            let mut forged = ui_post("/admin/users", "name=mallory".into(), &admin);
            forged
                .headers_mut()
                .insert("sec-fetch-site", "cross-site".parse().unwrap());
            assert_eq!(send(&app, forged).await.0, StatusCode::FORBIDDEN);

            // Alice's key works on /mcp and in the UI, without the admin section.
            assert_eq!(send(&app, mcp_ping(&alice_key)).await.0, StatusCode::OK);
            let alice = ui_sign_in(&app, &alice_key).await;
            let (_, _, alice_page) = send(&app, ui_get("/admin", &alice)).await;
            assert!(alice_page.contains("Signed in as <strong>alice</strong>"));
            assert!(!alice_page.contains("User keys"));
            assert_eq!(
                send(&app, ui_post("/admin/users", "name=x".into(), &alice))
                    .await
                    .0,
                StatusCode::FORBIDDEN
            );

            // Alice imports cookies; they are hers alone.
            let body = format!(
                "domain={}&cookies={}",
                enc("https://www.craigslist.org/"),
                enc("cl_session=abc; theme=dark")
            );
            let (status, headers, _) =
                send(&app, ui_post("/admin/sites/cookies", body, &alice)).await;
            assert_eq!(
                (status, headers["location"].to_str().unwrap()),
                (StatusCode::SEE_OTHER, "/admin?m=cookies-imported")
            );
            let store = services.auth.store();
            let alice_id = services.auth.by_key(&alice_key).await.unwrap().id;
            let record = store
                .site_for_host(alice_id, "sfbay.craigslist.org")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(record.jar.unwrap().len(), 2);
            assert!(
                store
                    .site_for_host(store.admin_id(), "craigslist.org")
                    .await
                    .unwrap()
                    .is_none()
            );
            let (_, _, alice_page) = send(&app, ui_get("/admin", &alice)).await;
            assert!(
                alice_page.contains("craigslist.org") && alice_page.contains("2 cookies (import)")
            );
            assert!(
                !alice_page.contains("abc"),
                "cookie values must never be rendered"
            );

            // The admin can view alice's key later; alice's own page never shows keys.
            let (_, _, admin_page) = send(&app, ui_get("/admin", &admin)).await;
            assert!(
                admin_page.contains(&alice_key),
                "admin should be able to view the key"
            );
            assert!(!alice_page.contains("wmk_"));

            // "New key" replaces alice's key: the old one stops working immediately.
            let (status, _, page) = send(
                &app,
                ui_post(
                    &format!("/admin/users/{alice_id}/regenerate"),
                    String::new(),
                    &admin,
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let start = page.find("wmk_").expect("new key shown");
            let old_key = std::mem::replace(&mut alice_key, page[start..start + 68].to_owned());
            assert_ne!(old_key, alice_key);
            assert_eq!(
                send(&app, mcp_ping(&old_key)).await.0,
                StatusCode::UNAUTHORIZED
            );
            assert_eq!(send(&app, mcp_ping(&alice_key)).await.0, StatusCode::OK);
            // Regenerating is admin-only.
            let attempt = ui_post(
                &format!("/admin/users/{alice_id}/regenerate"),
                String::new(),
                &alice,
            );
            assert_eq!(send(&app, attempt).await.0, StatusCode::FORBIDDEN);

            // Alice signs in to Claude Desktop with her key (OAuth) and gets her own token.
            let access = oauth_access_token(&app, &alice_key).await;
            assert_eq!(send(&app, mcp_ping(&access.0)).await.0, StatusCode::OK);

            // Revoking alice cuts off her key, her OAuth tokens, and her UI session.
            let (status, _, _) = send(
                &app,
                ui_post(
                    &format!("/admin/users/{alice_id}/revoke"),
                    String::new(),
                    &admin,
                ),
            )
            .await;
            assert_eq!(status, StatusCode::SEE_OTHER);
            assert_eq!(
                send(&app, mcp_ping(&alice_key)).await.0,
                StatusCode::UNAUTHORIZED
            );
            assert_eq!(
                send(&app, mcp_ping(&access.0)).await.0,
                StatusCode::UNAUTHORIZED
            );
            let refresh = form(
                "/token",
                format!("grant_type=refresh_token&refresh_token={}", enc(&access.1)),
            );
            let (status, _, body) = send(&app, refresh).await;
            assert!(
                status == StatusCode::BAD_REQUEST && body.contains("revoked"),
                "{body}"
            );
            assert_eq!(
                send(&app, ui_get("/admin", &alice)).await.0,
                StatusCode::SEE_OTHER
            );
            // The admin is unaffected.
            assert_eq!(send(&app, mcp_ping(TOKEN)).await.0, StatusCode::OK);
        }

        /// Runs the OAuth flow signing in with `key`; returns (access, refresh) tokens.
        async fn oauth_access_token(app: &Router, key: &str) -> (String, String) {
            let reg = Request::post("/register")
                .header("content-type", "application/json")
                .body(Body::from(format!(r#"{{"redirect_uris":["{REDIRECT}"]}}"#)))
                .unwrap();
            let (_, _, body) = send(app, reg).await;
            let client: serde_json::Value = serde_json::from_str(&body).unwrap();
            let client_id = client["client_id"].as_str().unwrap();
            let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER));
            let authorize = format!(
                "/authorize?response_type=code&client_id={}&redirect_uri={}&code_challenge={challenge}&code_challenge_method=S256",
                enc(client_id),
                enc(REDIRECT)
            );
            let (_, _, page) =
                send(app, Request::get(&authorize).body(Body::empty()).unwrap()).await;
            let request = hidden_request(&page);
            let (_, headers, _) = send(
                app,
                form(
                    "/authorize",
                    format!("request={}&password={}", enc(&request), enc(key)),
                ),
            )
            .await;
            let location = url::Url::parse(headers["location"].to_str().unwrap()).unwrap();
            let code = location
                .query_pairs()
                .find(|(k, _)| k == "code")
                .unwrap()
                .1
                .into_owned();
            let exchange = format!(
                "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&code_verifier={VERIFIER}",
                enc(&code),
                enc(REDIRECT),
                enc(client_id)
            );
            let (_, _, body) = send(app, form("/token", exchange)).await;
            let tokens: serde_json::Value = serde_json::from_str(&body).unwrap();
            (
                tokens["access_token"].as_str().unwrap().into(),
                tokens["refresh_token"].as_str().unwrap().into(),
            )
        }
    }
}

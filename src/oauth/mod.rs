//! A minimal OAuth 2.1 authorization server so Claude Desktop / claude.ai can connect.
//!
//! Claude's custom connectors follow the MCP authorization spec:
//!
//! 1. `POST /mcp` without a token → `401` with `WWW-Authenticate: Bearer resource_metadata=…`
//!    (emitted by [`crate::http`]).
//! 2. Client reads [`protected_resource`] metadata, then [`authorization_server`] metadata.
//! 3. Client self-registers at `/register` ([`register`], RFC 7591).
//! 4. Browser opens `/authorize` ([`authorize_page`]); the user enters their access key on
//!    the login page ([`authorize_submit`]) and is redirected back with a code.
//! 5. Client exchanges the code + PKCE verifier at `/token` ([`token()`]) for an access token
//!    (1 h) and refresh token (30 days), then calls `/mcp` with the access token.
//!
//! Users sign in with `WEB_MCP_AUTH_TOKEN` (the admin) or a user key from the admin UI; issued
//! tokens carry the user id and are re-checked against the store on every use. All OAuth state lives in
//! signed tokens (see [`crate::token`]), so nothing about OAuth is stored server-side.

use std::{sync::Arc, time::Duration};

use axum::{
    Form, Json, Router,
    extract::{Query, State},
    http::{StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{info, warn};
use url::Url;

use crate::{
    auth::Authenticator,
    store::UserId,
    token::{self, Claims, Signer, expires_in, pkce_matches},
};

/// Lifetime of the signed login-form request.
const REQUEST_TTL: Duration = Duration::from_secs(10 * 60);
/// Lifetime of authorization codes.
const CODE_TTL: Duration = Duration::from_secs(5 * 60);
/// Lifetime of access tokens.
const ACCESS_TTL: Duration = Duration::from_secs(60 * 60);
/// Lifetime of refresh tokens.
const REFRESH_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// The login page; `{{…}}` placeholders are filled by [`login_page`].
const LOGIN_HTML: &str = include_str!("login.html");

/// Shared state for the OAuth endpoints and `/mcp` token validation.
pub struct OAuth {
    /// Checks sign-in keys and signs tokens.
    auth: Authenticator,
    /// Issuer identifier: the public base URL without a trailing slash.
    issuer: String,
}

impl OAuth {
    /// Creates the authorization server for `public_url`.
    ///
    /// Users sign in with the master token or their own user key; issued tokens act for that
    /// user and stop working when the user is revoked.
    pub fn new(public_url: &Url, auth: Authenticator) -> Self {
        Self {
            auth,
            issuer: public_url.as_str().trim_end_matches('/').to_owned(),
        }
    }

    fn signer(&self) -> &Signer {
        self.auth.signer()
    }

    /// URL of the protected-resource metadata, advertised in `WWW-Authenticate` on 401s.
    pub fn resource_metadata_url(&self) -> String {
        format!("{}/.well-known/oauth-protected-resource", self.issuer)
    }

    /// The OAuth discovery, registration, authorization, and token routes.
    pub fn routes(self: Arc<Self>) -> Router {
        Router::new()
            .route(
                "/.well-known/oauth-protected-resource",
                get(protected_resource),
            )
            .route(
                "/.well-known/oauth-protected-resource/mcp",
                get(protected_resource),
            )
            .route(
                "/.well-known/oauth-authorization-server",
                get(authorization_server),
            )
            .route("/register", post(register))
            .route("/authorize", get(authorize_page).post(authorize_submit))
            .route("/token", post(token))
            .with_state(self)
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.issuer)
    }

    fn issue_tokens(&self, uid: UserId, client_id: String) -> Response {
        let access = self.signer().sign(&Claims::Access {
            uid,
            exp: expires_in(ACCESS_TTL),
        });
        let refresh = self.signer().sign(&Claims::Refresh {
            uid,
            client_id,
            exp: expires_in(REFRESH_TTL),
        });
        let body = json!({
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": ACCESS_TTL.as_secs(),
            "refresh_token": refresh,
        });
        ([(header::CACHE_CONTROL, "no-store")], Json(body)).into_response()
    }
}

/// RFC 9728 protected-resource metadata: which authorization server guards `/mcp`.
async fn protected_resource(State(oauth): State<Arc<OAuth>>) -> Json<serde_json::Value> {
    Json(json!({
        "resource": oauth.url("/mcp"),
        "authorization_servers": [oauth.issuer],
        "bearer_methods_supported": ["header"],
    }))
}

/// RFC 8414 authorization-server metadata.
async fn authorization_server(State(oauth): State<Arc<OAuth>>) -> Json<serde_json::Value> {
    Json(json!({
        "issuer": oauth.issuer,
        "authorization_endpoint": oauth.url("/authorize"),
        "token_endpoint": oauth.url("/token"),
        "registration_endpoint": oauth.url("/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
    }))
}

/// OAuth error body (RFC 6749 §5.2), returned as `400` JSON.
#[derive(Debug, Serialize)]
struct OAuthError {
    error: &'static str,
    error_description: String,
}

impl OAuthError {
    fn new(error: &'static str, description: impl Into<String>) -> Self {
        Self {
            error,
            error_description: description.into(),
        }
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        (
            StatusCode::BAD_REQUEST,
            [(header::CACHE_CONTROL, "no-store")],
            Json(self),
        )
            .into_response()
    }
}

/// Dynamic client registration request (RFC 7591); unknown fields are ignored.
#[derive(Debug, Deserialize)]
struct RegisterRequest {
    #[serde(default)]
    redirect_uris: Vec<String>,
    client_name: Option<String>,
}

/// Registers a public client. The returned `client_id` is a signed record of its redirect URIs.
async fn register(
    State(oauth): State<Arc<OAuth>>,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), OAuthError> {
    if req.redirect_uris.is_empty() {
        return Err(OAuthError::new(
            "invalid_redirect_uri",
            "at least one redirect_uri is required",
        ));
    }
    if let Some(bad) = req
        .redirect_uris
        .iter()
        .find(|uri| !is_acceptable_redirect(uri))
    {
        return Err(OAuthError::new(
            "invalid_redirect_uri",
            format!("redirect_uri must be https (or http on loopback): {bad}"),
        ));
    }
    let name = req
        .client_name
        .map(|n| n.chars().take(100).collect::<String>());
    let client_id = oauth.signer().sign(&Claims::Client {
        redirect_uris: req.redirect_uris.clone(),
        name: name.clone(),
    });
    info!(
        client = name.as_deref().unwrap_or("unnamed"),
        "registered OAuth client"
    );
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "client_id": client_id,
            "client_id_issued_at": token::now(),
            "client_name": name,
            "redirect_uris": req.redirect_uris,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        })),
    ))
}

/// Redirect URIs must be absolute `https`, or `http` to a loopback host (native apps).
fn is_acceptable_redirect(uri: &str) -> bool {
    let Ok(url) = Url::parse(uri) else {
        return false;
    };
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    url.fragment().is_none() && (url.scheme() == "https" || (url.scheme() == "http" && loopback))
}

/// Query parameters of `GET /authorize`; all optional so we can report what is missing.
#[derive(Debug, Deserialize)]
struct AuthorizeQuery {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    state: Option<String>,
}

/// Validates the authorization request and shows the login page.
async fn authorize_page(
    State(oauth): State<Arc<OAuth>>,
    Query(q): Query<AuthorizeQuery>,
) -> Response {
    match validate_authorize(&oauth, q) {
        Ok((request, client_name)) => {
            login_page(StatusCode::OK, &oauth, &request, &client_name, None)
        }
        Err(message) => error_page(StatusCode::BAD_REQUEST, &message),
    }
}

/// Checks client, redirect URI, and PKCE; returns the signed request and display name.
fn validate_authorize(oauth: &OAuth, q: AuthorizeQuery) -> Result<(String, String), String> {
    let client_id = q.client_id.ok_or("missing client_id")?;
    let Some(Claims::Client {
        redirect_uris,
        name,
    }) = oauth.signer().verify(&client_id)
    else {
        return Err("unknown client — remove and re-add the connector".into());
    };
    let redirect_uri = match (q.redirect_uri, redirect_uris.as_slice()) {
        (Some(uri), registered) if registered.contains(&uri) => uri,
        (None, [only]) => only.clone(),
        _ => return Err("redirect_uri does not match the client registration".into()),
    };
    if q.response_type.as_deref() != Some("code") {
        return Err("response_type must be `code`".into());
    }
    let code_challenge = q
        .code_challenge
        .filter(|c| !c.is_empty())
        .ok_or("PKCE code_challenge is required")?;
    if q.code_challenge_method.as_deref() != Some("S256") {
        return Err("code_challenge_method must be S256".into());
    }

    let client_name = name.unwrap_or_else(|| "An MCP client".into());
    let request = oauth.signer().sign(&Claims::Request {
        client_id,
        redirect_uri,
        code_challenge,
        state: q.state,
        exp: expires_in(REQUEST_TTL),
    });
    Ok((request, client_name))
}

/// The login form submission.
#[derive(Debug, Deserialize)]
struct LoginForm {
    request: String,
    password: String,
}

/// Checks the password and redirects back to the client with an authorization code.
async fn authorize_submit(
    State(oauth): State<Arc<OAuth>>,
    Form(form): Form<LoginForm>,
) -> Response {
    let Some(Claims::Request {
        client_id,
        redirect_uri,
        code_challenge,
        state,
        ..
    }) = oauth.signer().verify(&form.request)
    else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "This sign-in request expired. Start again from Claude.",
        );
    };
    let Some(principal) = oauth.auth.by_key(&form.password).await else {
        warn!("OAuth login failed: wrong or revoked access key");
        let client_name = match oauth.signer().verify(&client_id) {
            Some(Claims::Client {
                name: Some(name), ..
            }) => name,
            _ => "An MCP client".into(),
        };
        let error = Some("That access key is not correct.");
        return login_page(
            StatusCode::UNAUTHORIZED,
            &oauth,
            &form.request,
            &client_name,
            error,
        );
    };

    let code = oauth.signer().sign(&Claims::Code {
        uid: principal.id,
        client_id,
        redirect_uri: redirect_uri.clone(),
        code_challenge,
        exp: expires_in(CODE_TTL),
    });
    let mut target = Url::parse(&redirect_uri).expect("validated at /authorize");
    target
        .query_pairs_mut()
        .append_pair("code", &code)
        .extend_pairs(state.map(|s| ("state", s)));
    info!(user = %principal.name, redirect = %target.host_str().unwrap_or_default(), "OAuth login succeeded");
    Redirect::to(target.as_str()).into_response()
}

/// `POST /token` form parameters for both supported grants.
#[derive(Debug, Deserialize)]
struct TokenRequest {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
}

/// Exchanges an authorization code or refresh token for a new token pair.
async fn token(
    State(oauth): State<Arc<OAuth>>,
    Form(req): Form<TokenRequest>,
) -> Result<Response, OAuthError> {
    let invalid_grant = |why: &str| OAuthError::new("invalid_grant", why);
    let client_matches = |expected: &str| {
        req.client_id
            .as_deref()
            .is_none_or(|given| given == expected)
    };

    match req.grant_type.as_str() {
        "authorization_code" => {
            let code = req
                .code
                .as_deref()
                .ok_or_else(|| OAuthError::new("invalid_request", "missing code"))?;
            let Some(Claims::Code {
                uid,
                client_id,
                redirect_uri,
                code_challenge,
                ..
            }) = oauth.signer().verify(code)
            else {
                return Err(invalid_grant("authorization code is invalid or expired"));
            };
            if !client_matches(&client_id)
                || req
                    .redirect_uri
                    .as_deref()
                    .is_some_and(|uri| uri != redirect_uri)
            {
                return Err(invalid_grant(
                    "client_id or redirect_uri does not match the code",
                ));
            }
            let verifier = req
                .code_verifier
                .as_deref()
                .ok_or_else(|| OAuthError::new("invalid_request", "missing code_verifier"))?;
            if !pkce_matches(verifier, &code_challenge) {
                return Err(invalid_grant("PKCE verification failed"));
            }
            Ok(oauth.issue_tokens(uid, client_id))
        }
        "refresh_token" => {
            let refresh = req
                .refresh_token
                .as_deref()
                .ok_or_else(|| OAuthError::new("invalid_request", "missing refresh_token"))?;
            let Some(Claims::Refresh { uid, client_id, .. }) = oauth.signer().verify(refresh)
            else {
                return Err(invalid_grant("refresh token is invalid or expired"));
            };
            if !client_matches(&client_id) {
                return Err(invalid_grant("client_id does not match the refresh token"));
            }
            if oauth.auth.by_id(uid).await.is_none() {
                return Err(invalid_grant("this access key has been revoked"));
            }
            Ok(oauth.issue_tokens(uid, client_id))
        }
        other => Err(OAuthError::new(
            "unsupported_grant_type",
            format!("unsupported grant_type `{other}`"),
        )),
    }
}

/// Renders the login page for a signed `request`.
fn login_page(
    status: StatusCode,
    oauth: &OAuth,
    request: &str,
    client_name: &str,
    error: Option<&str>,
) -> Response {
    let redirect_host = match oauth.signer().verify(request) {
        Some(Claims::Request { redirect_uri, .. }) => Url::parse(&redirect_uri)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned))
            .unwrap_or_default(),
        _ => String::new(),
    };
    let error_html = error
        .map(|e| format!(r#"<p class="error">{}</p>"#, escape_html(e)))
        .unwrap_or_default();
    let html = LOGIN_HTML
        .replace("{{client}}", &escape_html(client_name))
        .replace("{{redirect_host}}", &escape_html(&redirect_host))
        .replace("{{request}}", &escape_html(request))
        .replace("{{error}}", &error_html);
    (status, [(header::CACHE_CONTROL, "no-store")], Html(html)).into_response()
}

/// A minimal standalone error page for invalid authorization requests.
fn error_page(status: StatusCode, message: &str) -> Response {
    let html = format!(
        "<!doctype html><meta charset=utf-8><title>web-mcp</title><body style=\"font:16px system-ui;margin:4rem auto;max-width:28rem\"><h1>Can't sign in</h1><p>{}</p>",
        escape_html(message)
    );
    (status, Html(html)).into_response()
}

/// Escapes text for safe inclusion in HTML content and attribute values.
fn escape_html(text: &str) -> String {
    text.chars()
        .fold(String::with_capacity(text.len()), |mut out, c| {
            match c {
                '&' => out.push_str("&amp;"),
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                '"' => out.push_str("&quot;"),
                '\'' => out.push_str("&#39;"),
                c => out.push(c),
            }
            out
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_uri_policy() {
        assert!(is_acceptable_redirect(
            "https://claude.ai/api/mcp/auth_callback"
        ));
        assert!(is_acceptable_redirect("http://localhost:33418/callback"));
        assert!(is_acceptable_redirect("http://127.0.0.1:8080/cb"));
        assert!(!is_acceptable_redirect("http://evil.example/cb"));
        assert!(!is_acceptable_redirect("https://claude.ai/cb#frag"));
        assert!(!is_acceptable_redirect("javascript:alert(1)"));
    }

    #[test]
    fn escapes_html() {
        assert_eq!(
            escape_html(r#"<a href="x">'&'</a>"#),
            "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;"
        );
    }
}

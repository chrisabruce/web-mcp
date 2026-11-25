//! The web UI at `/admin`: user keys (admin only) and per-user site logins.
//!
//! Anyone with a key signs in here: the master token as the built-in admin, or a user key
//! as that user. Everyone manages their own site logins (saved passwords, imported browser
//! cookies, sessions); the admin additionally creates and revokes user keys.
//!
//! # Security
//!
//! * The session is a signed [`Claims::UiSession`] in an `HttpOnly; SameSite=Strict` cookie
//!   scoped to `/admin` (`Secure` when the public URL is HTTPS), valid for
//!   [`SESSION_TTL`]. Each request re-checks that the user still exists and is not revoked.
//! * State-changing requests are POSTs and must be same-origin ([`same_origin`]), on top of
//!   `SameSite=Strict`, which together prevent cross-site request forgery.
//! * Templates are rendered with Askama, which HTML-escapes every interpolated value.
//! * Passwords and cookies are never rendered back; only metadata is shown.

use std::{sync::Arc, time::Duration};

use askama::Template;
use axum::{
    Form, Router,
    extract::{FromRequestParts, Path, Query, State},
    http::{HeaderMap, StatusCode, header, request::Parts},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use serde::Deserialize;
use tracing::{error, info, warn};

use crate::{
    auth::{Authenticator, Principal},
    cookies::{normalize_domain, parse_import},
    sites::Sites,
    store::{CookieSource, KeyView, StoreError, UserId, UserListing},
    token::{Claims, expires_in, now},
};

/// Name of the session cookie.
const COOKIE: &str = "wmcp_session";

/// How long a UI sign-in lasts.
const SESSION_TTL: Duration = Duration::from_secs(12 * 60 * 60);

/// Shared state for the UI handlers.
pub struct AdminState {
    /// Resolves keys and session cookies.
    pub auth: Authenticator,
    /// Performs "log in now" from the UI.
    pub sites: Sites,
    /// Whether to mark the session cookie `Secure` (public URL is HTTPS).
    pub secure_cookies: bool,
    /// The MCP endpoint URL, shown with newly created keys.
    pub mcp_url: String,
    /// The `From` address of outgoing email, if email is configured.
    pub mail_from: Option<String>,
}

type AppState = State<Arc<AdminState>>;

/// The `/admin` routes.
pub fn routes(state: Arc<AdminState>) -> Router {
    Router::new()
        .route("/admin", get(dashboard))
        .route("/admin/login", get(login_page).post(login))
        .route("/admin/logout", post(logout))
        .route("/admin/users", post(create_user))
        .route("/admin/users/{id}/revoke", post(revoke_user))
        .route("/admin/users/{id}/regenerate", post(regenerate_key))
        .route("/admin/users/{id}/email", post(set_email_permission))
        .route("/admin/sites", post(save_site))
        .route("/admin/sites/cookies", post(import_cookies))
        .route("/admin/sites/login", post(site_login))
        .route("/admin/sites/logout", post(end_session))
        .route("/admin/sites/delete", post(delete_site))
        .with_state(state)
}

/// A signed-in UI user, extracted from the session cookie. Redirects to the sign-in page
/// otherwise, and rejects cross-origin POSTs.
struct UiUser(Principal);

impl FromRequestParts<Arc<AdminState>> for UiUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AdminState>,
    ) -> Result<Self, Response> {
        if parts.method != axum::http::Method::GET && !same_origin(&parts.headers) {
            warn!("rejected cross-origin admin request");
            return Err((StatusCode::FORBIDDEN, "cross-origin request rejected").into_response());
        }
        let uid = session_cookie(&parts.headers).and_then(|value| {
            match state.auth.signer().verify(&value) {
                Some(Claims::UiSession { uid, .. }) => Some(uid),
                _ => None,
            }
        });
        let principal = match uid {
            Some(uid) => state.auth.by_id(uid).await,
            None => None,
        };
        principal
            .map(UiUser)
            .ok_or_else(|| Redirect::to("/admin/login").into_response())
    }
}

/// Whether a state-changing request comes from this site.
///
/// Modern browsers send `Sec-Fetch-Site`, which pages cannot forge: it alone decides
/// (`same-origin`, or `none` for user-initiated navigation). Only when it is absent (older
/// browsers, non-browser clients) is `Origin` compared with `Host`; a missing `Origin` is
/// allowed, but an opaque `Origin: null` is not. `SameSite=Strict` on the session cookie is a
/// second, independent defence.
fn same_origin(headers: &HeaderMap) -> bool {
    let get = |name| headers.get(name).and_then(|v| v.to_str().ok());
    if let Some(site) = get("sec-fetch-site") {
        return matches!(site, "same-origin" | "none");
    }
    match (get("origin"), get("host")) {
        (Some(origin), Some(host)) => url::Url::parse(origin)
            .ok()
            .and_then(|u| u.host_str().map(|h| (h.to_owned(), u.port())))
            .is_some_and(|(origin_host, port)| {
                let origin_authority =
                    port.map_or(origin_host.clone(), |p| format!("{origin_host}:{p}"));
                origin_authority.eq_ignore_ascii_case(host)
                    || origin_host.eq_ignore_ascii_case(host)
            }),
        _ => true,
    }
}

fn session_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, _)| *name == COOKIE)
        .map(|(_, value)| value.to_owned())
}

// ---- views -------------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "admin_login.html")]
struct LoginTemplate {
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "admin.html")]
struct DashboardTemplate {
    user_name: String,
    is_admin: bool,
    mcp_url: String,
    message: Option<String>,
    error: Option<String>,
    created_key: Option<(String, String)>,
    /// `From` address of outgoing email, if configured.
    mail_from: Option<String>,
    /// Whether the signed-in user may send email.
    can_email: bool,
    sites: Vec<SiteRow>,
    users: Vec<UserRow>,
}

struct SiteRow {
    domain: String,
    login_url: Option<String>,
    login: String,
    session: String,
    updated: String,
    can_login: bool,
    has_session: bool,
}

struct UserRow {
    id: UserId,
    name: String,
    /// Short prefix shown in the table.
    key_prefix: String,
    /// The full key, if it can be shown.
    full_key: Option<String>,
    /// Why the full key cannot be shown, otherwise.
    key_note: &'static str,
    created: String,
    last_used: String,
    status: &'static str,
    revocable: bool,
    /// Whether the user may send email.
    can_email: bool,
}

/// Optional extras for rendering the dashboard.
#[derive(Default)]
struct Flash {
    message: Option<String>,
    error: Option<String>,
    created_key: Option<(String, String)>,
}

fn render(template: &impl Template) -> Response {
    match template.render() {
        Ok(html) => ([(header::CACHE_CONTROL, "no-store")], Html(html)).into_response(),
        Err(err) => {
            error!(%err, "template rendering failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "template error").into_response()
        }
    }
}

async fn render_dashboard(state: &AdminState, user: &Principal, flash: Flash) -> Response {
    let store = state.auth.store();
    let sites = match store.sites(user.id).await {
        Ok(sites) => sites,
        Err(err) => return store_failure(&err),
    };
    let users = if user.is_admin {
        match store.list_users().await {
            Ok(users) => users,
            Err(err) => return store_failure(&err),
        }
    } else {
        Vec::new()
    };
    render(&DashboardTemplate {
        user_name: user.name.clone(),
        is_admin: user.is_admin,
        mcp_url: state.mcp_url.clone(),
        message: flash.message,
        error: flash.error,
        created_key: flash.created_key,
        mail_from: state.mail_from.clone(),
        can_email: user.can_email,
        sites: sites
            .into_iter()
            .map(|s| SiteRow {
                login: match (&s.username, s.has_password) {
                    (Some(u), true) => u.clone(),
                    (Some(u), false) => format!("{u} (no password)"),
                    _ => "—".into(),
                },
                session: match s.cookie_count {
                    0 => "none".into(),
                    n => format!(
                        "{n} cookies ({})",
                        s.cookies_source.as_deref().unwrap_or("login")
                    ),
                },
                updated: ago(s.updated_at),
                can_login: s.has_password,
                has_session: s.cookie_count > 0,
                login_url: s.login_url,
                domain: s.domain,
            })
            .collect(),
        users: users.into_iter().map(user_row).collect(),
    })
}

/// Builds the user-table row for one listing.
fn user_row(UserListing { user: u, key }: UserListing) -> UserRow {
    let (full_key, key_note) = match key {
        KeyView::Visible(key) => (Some(key), ""),
        KeyView::Master => (None, "the WEB_MCP_AUTH_TOKEN environment variable"),
        KeyView::NotStored => (
            None,
            "not stored (created before keys were viewable); use New key",
        ),
        KeyView::Unreadable => (
            None,
            "unreadable since WEB_MCP_AUTH_TOKEN changed; use New key",
        ),
    };
    let active = !u.is_admin() && u.revoked_at.is_none();
    UserRow {
        revocable: active,
        can_email: u.is_admin() || u.can_email,
        status: match (u.is_admin(), u.revoked_at) {
            (true, _) => "master token",
            (false, Some(_)) => "revoked",
            (false, None) => "active",
        },
        key_prefix: u
            .key_prefix
            .clone()
            .map_or_else(|| "master".into(), |p| format!("{p}…")),
        full_key: full_key.filter(|_| active),
        key_note: if active || u.is_admin() {
            key_note
        } else {
            "revoked"
        },
        created: ago(u.created_at),
        last_used: u.last_used_at.map_or_else(|| "never".into(), ago),
        id: u.id,
        name: u.name,
    }
}

/// "5 min ago"-style relative time.
fn ago(ts: u64) -> String {
    let secs = now().saturating_sub(ts);
    match secs {
        0..60 => "just now".into(),
        60..3_600 => format!("{} min ago", secs / 60),
        3_600..86_400 => format!("{} h ago", secs / 3_600),
        _ => format!("{} d ago", secs / 86_400),
    }
}

fn store_failure(err: &StoreError) -> Response {
    error!(%err, "admin UI database failure");
    (StatusCode::INTERNAL_SERVER_ERROR, "database error").into_response()
}

/// Redirects back to the dashboard with a fixed message (no user text in URLs).
fn done(message: &'static str) -> Response {
    Redirect::to(&format!("/admin?m={message}")).into_response()
}

#[derive(Deserialize)]
struct DashboardQuery {
    m: Option<String>,
}

/// Maps a redirect message code to its text.
fn message_text(code: &str) -> Option<&'static str> {
    Some(match code {
        "user-revoked" => "Key revoked. Its Claude sessions stop working immediately.",
        "email-allowed" => "Email sending allowed for that user.",
        "email-forbidden" => "Email sending turned off for that user.",
        "site-saved" => "Login saved.",
        "cookies-imported" => "Cookies imported. Claude will use this session for the site.",
        "session-ended" => "Session ended.",
        "site-deleted" => "Site deleted.",
        _ => return None,
    })
}

// ---- handlers ----------------------------------------------------------------------------

async fn dashboard(
    State(state): AppState,
    UiUser(user): UiUser,
    Query(q): Query<DashboardQuery>,
) -> Response {
    let message = q.m.as_deref().and_then(message_text).map(str::to_owned);
    render_dashboard(
        &state,
        &user,
        Flash {
            message,
            ..Flash::default()
        },
    )
    .await
}

async fn login_page() -> Response {
    render(&LoginTemplate { error: None })
}

#[derive(Deserialize)]
struct LoginForm {
    key: String,
}

async fn login(
    State(state): AppState,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    if !same_origin(&headers) {
        return (StatusCode::FORBIDDEN, "cross-origin request rejected").into_response();
    }
    let Some(user) = state.auth.by_key(&form.key).await else {
        warn!("admin UI sign-in failed");
        let page = render(&LoginTemplate {
            error: Some("That access key is not valid.".into()),
        });
        return (StatusCode::UNAUTHORIZED, page).into_response();
    };
    info!(user = %user.name, "admin UI sign-in");
    let token = state.auth.signer().sign(&Claims::UiSession {
        uid: user.id,
        exp: expires_in(SESSION_TTL),
    });
    let secure = if state.secure_cookies { "; Secure" } else { "" };
    let cookie = format!(
        "{COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/admin; Max-Age={}{secure}",
        SESSION_TTL.as_secs()
    );
    ([(header::SET_COOKIE, cookie)], Redirect::to("/admin")).into_response()
}

async fn logout(_user: UiUser) -> Response {
    let cookie = format!("{COOKIE}=; HttpOnly; SameSite=Strict; Path=/admin; Max-Age=0");
    ([(header::SET_COOKIE, cookie)], Redirect::to("/admin/login")).into_response()
}

#[derive(Deserialize)]
struct CreateUserForm {
    name: String,
}

async fn create_user(
    State(state): AppState,
    UiUser(user): UiUser,
    Form(form): Form<CreateUserForm>,
) -> Response {
    if !user.is_admin {
        return (StatusCode::FORBIDDEN, "admin only").into_response();
    }
    let flash = match state.auth.store().create_user(&form.name).await {
        Ok((created, key)) => {
            info!(admin = %user.name, user = %created.name, "created user key");
            Flash {
                created_key: Some((created.name, key)),
                ..Flash::default()
            }
        }
        Err(err @ (StoreError::NameTaken(_) | StoreError::InvalidName)) => Flash {
            error: Some(err.to_string()),
            ..Flash::default()
        },
        Err(err) => return store_failure(&err),
    };
    render_dashboard(&state, &user, flash).await
}

async fn revoke_user(
    State(state): AppState,
    UiUser(user): UiUser,
    Path(id): Path<i64>,
) -> Response {
    if !user.is_admin {
        return (StatusCode::FORBIDDEN, "admin only").into_response();
    }
    match state.auth.store().revoke_user(UserId(id)).await {
        Ok(()) => {
            info!(admin = %user.name, user_id = id, "revoked user key");
            done("user-revoked")
        }
        Err(err @ StoreError::CannotRevokeAdmin) => {
            show_error(&state, &user, err.to_string()).await
        }
        Err(err) => store_failure(&err),
    }
}

async fn regenerate_key(
    State(state): AppState,
    UiUser(user): UiUser,
    Path(id): Path<i64>,
) -> Response {
    if !user.is_admin {
        return (StatusCode::FORBIDDEN, "admin only").into_response();
    }
    match state.auth.store().regenerate_key(UserId(id)).await {
        Ok((changed, key)) => {
            info!(admin = %user.name, user = %changed.name, "regenerated user key");
            let flash = Flash {
                created_key: Some((changed.name, key)),
                message: Some("New key issued. The old key no longer works; Claude Desktop sign-ins made with it continue until they expire or the user is revoked.".into()),
                ..Flash::default()
            };
            render_dashboard(&state, &user, flash).await
        }
        Err(err @ (StoreError::UnknownUser | StoreError::CannotRevokeAdmin)) => {
            show_error(&state, &user, err.to_string()).await
        }
        Err(err) => store_failure(&err),
    }
}

#[derive(Deserialize)]
struct EmailPermissionForm {
    allow: bool,
}

async fn set_email_permission(
    State(state): AppState,
    UiUser(user): UiUser,
    Path(id): Path<i64>,
    Form(form): Form<EmailPermissionForm>,
) -> Response {
    if !user.is_admin {
        return (StatusCode::FORBIDDEN, "admin only").into_response();
    }
    match state
        .auth
        .store()
        .set_can_email(UserId(id), form.allow)
        .await
    {
        Ok(()) => {
            info!(admin = %user.name, user_id = id, allowed = form.allow, "changed email permission");
            done(if form.allow {
                "email-allowed"
            } else {
                "email-forbidden"
            })
        }
        Err(err @ StoreError::UnknownUser) => show_error(&state, &user, err.to_string()).await,
        Err(err) => store_failure(&err),
    }
}

/// Re-renders the dashboard with an error message.
async fn show_error(state: &AdminState, user: &Principal, error: impl Into<String>) -> Response {
    let flash = Flash {
        error: Some(error.into()),
        ..Flash::default()
    };
    render_dashboard(state, user, flash).await
}

/// Validates a domain form field.
fn parse_domain(input: &str) -> Result<String, String> {
    normalize_domain(input)
        .ok_or_else(|| format!("`{input}` is not a valid domain (e.g. craigslist.org)."))
}

#[derive(Deserialize)]
struct SiteForm {
    domain: String,
    #[serde(default)]
    login_url: String,
    username: String,
    #[serde(default)]
    password: String,
}

async fn save_site(
    State(state): AppState,
    UiUser(user): UiUser,
    Form(form): Form<SiteForm>,
) -> Response {
    let domain = match parse_domain(&form.domain) {
        Ok(domain) => domain,
        Err(error) => return show_error(&state, &user, error).await,
    };
    let login_url = Some(form.login_url.trim().to_owned()).filter(|u| !u.is_empty());
    if let Some(url) = &login_url
        && crate::web::parse_http_url(url).is_err()
    {
        let error = format!("`{url}` is not a valid public http(s) URL.");
        return show_error(&state, &user, error).await;
    }
    let password = Some(form.password.as_str()).filter(|p| !p.is_empty());
    match state
        .auth
        .store()
        .save_credentials(user.id, &domain, login_url, form.username.trim(), password)
        .await
    {
        Ok(()) => {
            info!(user = %user.name, %domain, "saved site login");
            done("site-saved")
        }
        Err(err) => store_failure(&err),
    }
}

#[derive(Deserialize)]
struct CookiesForm {
    domain: String,
    cookies: String,
}

async fn import_cookies(
    State(state): AppState,
    UiUser(user): UiUser,
    Form(form): Form<CookiesForm>,
) -> Response {
    let domain = match parse_domain(&form.domain) {
        Ok(domain) => domain,
        Err(error) => return show_error(&state, &user, error).await,
    };
    let jar = match parse_import(&form.cookies, &domain) {
        Ok(jar) => jar,
        Err(err) => {
            return show_error(&state, &user, err.to_string()).await;
        }
    };
    match state
        .auth
        .store()
        .save_cookies(user.id, &domain, &jar, CookieSource::Import)
        .await
    {
        Ok(()) => {
            info!(user = %user.name, %domain, cookies = jar.len(), "imported site cookies");
            done("cookies-imported")
        }
        Err(err) => store_failure(&err),
    }
}

#[derive(Deserialize)]
struct DomainForm {
    domain: String,
}

async fn site_login(
    State(state): AppState,
    UiUser(user): UiUser,
    Form(form): Form<DomainForm>,
) -> Response {
    let flash = match state.sites.login(&user, &form.domain, None, false).await {
        Ok(outcome) => Flash {
            message: Some(outcome.to_string()),
            ..Flash::default()
        },
        Err(err) => {
            err.log("admin_site_login", &form.domain);
            Flash {
                error: Some(err.to_string()),
                ..Flash::default()
            }
        }
    };
    render_dashboard(&state, &user, flash).await
}

async fn end_session(
    State(state): AppState,
    UiUser(user): UiUser,
    Form(form): Form<DomainForm>,
) -> Response {
    match state
        .auth
        .store()
        .clear_cookies(user.id, &form.domain)
        .await
    {
        Ok(()) => done("session-ended"),
        Err(err) => store_failure(&err),
    }
}

async fn delete_site(
    State(state): AppState,
    UiUser(user): UiUser,
    Form(form): Form<DomainForm>,
) -> Response {
    match state.auth.store().delete_site(user.id, &form.domain).await {
        Ok(()) => {
            info!(user = %user.name, domain = %form.domain, "deleted site");
            done("site-deleted")
        }
        Err(err) => store_failure(&err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        pairs
            .iter()
            .map(|(k, v)| (header::HeaderName::from_static(k), v.parse().unwrap()))
            .collect()
    }

    #[test]
    fn same_origin_checks() {
        assert!(same_origin(&headers(&[
            ("host", "mcp.example.com"),
            ("origin", "https://mcp.example.com")
        ])));
        assert!(same_origin(&headers(&[
            ("host", "localhost:8787"),
            ("origin", "http://localhost:8787")
        ])));
        assert!(same_origin(&headers(&[("host", "mcp.example.com")])));
        assert!(!same_origin(&headers(&[
            ("host", "mcp.example.com"),
            ("origin", "https://evil.example")
        ])));
        assert!(!same_origin(&headers(&[
            ("host", "mcp.example.com"),
            ("sec-fetch-site", "cross-site")
        ])));
        assert!(!same_origin(&headers(&[
            ("host", "mcp.example.com"),
            ("sec-fetch-site", "same-site")
        ])));
        // What a real browser sends for a form POST from a no-referrer page.
        assert!(same_origin(&headers(&[
            ("host", "mcp.example.com"),
            ("origin", "null"),
            ("sec-fetch-site", "same-origin")
        ])));
        // Without Sec-Fetch-Site, an opaque origin is refused.
        assert!(!same_origin(&headers(&[
            ("host", "mcp.example.com"),
            ("origin", "null")
        ])));
    }

    #[test]
    fn reads_session_cookie() {
        let h = headers(&[("cookie", "a=1; wmcp_session=tok.sig; b=2")]);
        assert_eq!(session_cookie(&h).as_deref(), Some("tok.sig"));
        assert_eq!(session_cookie(&headers(&[("cookie", "a=1")])), None);
    }
}

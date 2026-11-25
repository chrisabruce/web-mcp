//! Logged-in browsing: per-user site sessions and automatic form logins.
//!
//! [`Sites`] sits between the MCP tools and [`WebClient`]. For each request it looks up the
//! caller's saved site (by the longest matching domain), sends its cookies, and saves any
//! cookies the site updates. Sessions come from two places:
//!
//! * **Form login** ([`Sites::login`]): fetch the login page, find the form with a single
//!   password field ([`find_login_form`]), fill in username and password while keeping hidden
//!   fields such as CSRF tokens, submit it, and keep the resulting cookies. Credentials come
//!   from the tool call or from the user's saved logins (admin UI).
//! * **Cookie import** (admin UI): for sites whose login needs JavaScript, CAPTCHAs, or 2FA,
//!   users paste cookies from their own logged-in browser.
//!
//! Everything is scoped to the calling [`Principal`]; users never see each other's sessions.

use scrapling::selector::Selector;
use tracing::{error, info, warn};
use url::Url;

use crate::{
    auth::Principal,
    cookies::{CookieJar, normalize_domain},
    store::{CookieSource, Credentials, SiteSummary, Store, StoreError},
    web::{Download, FetchedImage, FormPost, Page, PageRequest, SiteSession, WebClient, WebError},
};

/// Whether a request should use the caller's saved session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LoginMode {
    /// Use saved cookies for the site if there are any; otherwise fetch anonymously.
    #[default]
    Auto,
    /// Require a session: use saved cookies, or log in with saved credentials first.
    Required,
    /// Never send saved cookies.
    Anonymous,
}

impl LoginMode {
    /// Maps the tools' optional `use_login` flag.
    pub fn from_flag(flag: Option<bool>) -> Self {
        match flag {
            None => Self::Auto,
            Some(true) => Self::Required,
            Some(false) => Self::Anonymous,
        }
    }
}

/// Result of a successful login.
#[derive(Debug, Clone)]
pub struct LoginOutcome {
    /// Domain the session applies to.
    pub domain: String,
    /// Page reached after logging in.
    pub landed_on: String,
    /// Its title, if any.
    pub title: Option<String>,
    /// Cookies now held for the site.
    pub cookie_count: usize,
    /// Whether the credentials were saved for future use.
    pub saved_credentials: bool,
}

impl std::fmt::Display for LoginOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Logged in to {} ({} session cookies). Landed on {}",
            self.domain, self.cookie_count, self.landed_on
        )?;
        if let Some(title) = &self.title {
            write!(f, " — \"{title}\"")?;
        }
        write!(
            f,
            ". fetch_url and fetch_image now use this session automatically.{}",
            if self.saved_credentials {
                " Credentials were saved for future logins."
            } else {
                ""
            }
        )
    }
}

/// Failures of logged-in operations.
#[derive(Debug, thiserror::Error)]
pub enum SiteError {
    /// Fetching failed (network, block, bad URL, …).
    #[error(transparent)]
    Web(#[from] WebError),
    /// The database failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The target was neither a URL nor a domain.
    #[error("`{0}` is not a valid site URL or domain")]
    NotADomain(String),
    /// No credentials were given and none are saved.
    #[error(
        "no saved login for {0}. Pass username and password to site_login, or have the user add \
         the login (or import browser cookies) in the web-mcp admin UI"
    )]
    NoCredentials(String),
    /// The login page has no recognisable password form.
    #[error(
        "no login form found at {0}. The site probably logs in with JavaScript; ask the user to \
         import their browser cookies for it in the web-mcp admin UI"
    )]
    NoLoginForm(String),
    /// The form was submitted but the site still shows a login form.
    #[error(
        "login to {domain} did not succeed: the site still shows a password form at {url} \
         (wrong credentials, a CAPTCHA, or a 2FA step). If it keeps failing, ask the user to \
         import browser cookies in the web-mcp admin UI"
    )]
    LoginFailed {
        /// Site domain.
        domain: String,
        /// Page reached after submitting.
        url: String,
    },
}

impl SiteError {
    /// Logs this failure once, at a level that matches its cause (see [`WebError::log`]).
    pub fn log(&self, operation: &str, target: &str) {
        match self {
            Self::Web(err) => err.log(operation, target),
            Self::Store(_) => error!(operation, target, error = %self, "database failure"),
            Self::NoLoginForm(_) | Self::LoginFailed { .. } => {
                warn!(operation, target, error = %self, "site login failed")
            }
            Self::NotADomain(_) | Self::NoCredentials(_) => {
                info!(operation, target, error = %self, "rejected request")
            }
        }
    }
}

/// Per-user logged-in browsing. Cheap to clone.
#[derive(Clone)]
pub struct Sites {
    web: WebClient,
    store: Store,
}

impl Sites {
    /// Combines the web client with the session store.
    pub fn new(web: WebClient, store: Store) -> Self {
        Self { web, store }
    }

    /// The underlying anonymous web client (search does not use sessions).
    pub fn web(&self) -> &WebClient {
        &self.web
    }

    /// Fetches a page, using `user`'s session for the site according to `mode`.
    pub async fn fetch_page(
        &self,
        user: &Principal,
        req: PageRequest,
        mode: LoginMode,
    ) -> Result<Page, SiteError> {
        let mut session = self.session_for(user, &req.url, mode).await?;
        let result = self.web.fetch_page(req, session.as_mut()).await;
        self.persist(user, session.as_ref()).await;
        Ok(result?)
    }

    /// Fetches an image, using `user`'s session for the site according to `mode`.
    pub async fn fetch_image(
        &self,
        user: &Principal,
        url: &str,
        mode: LoginMode,
    ) -> Result<FetchedImage, SiteError> {
        let mut session = self.session_for(user, url, mode).await?;
        let result = self.web.fetch_image(url, session.as_mut()).await;
        self.persist(user, session.as_ref()).await;
        Ok(result?)
    }

    /// Downloads a file of at most `max_bytes`, using `user`'s session for the site
    /// according to `mode`.
    pub async fn download(
        &self,
        user: &Principal,
        url: &str,
        mode: LoginMode,
        max_bytes: usize,
    ) -> Result<Download, SiteError> {
        let mut session = self.session_for(user, url, mode).await?;
        let result = self.web.download(url, session.as_mut(), max_bytes).await;
        self.persist(user, session.as_ref()).await;
        Ok(result?)
    }

    /// The caller's saved sites, without secrets.
    pub async fn list(&self, user: &Principal) -> Result<Vec<SiteSummary>, SiteError> {
        Ok(self.store.sites(user.id).await?)
    }

    /// Logs in to the site at `target` (a login-page URL or a domain) with a form login.
    ///
    /// Uses `credentials` if given (saving them when `save` is set), else the saved ones. The
    /// login page is `target` when it is a URL, else the saved login URL, else
    /// `https://<domain>/login`.
    pub async fn login(
        &self,
        user: &Principal,
        target: &str,
        credentials: Option<Credentials>,
        save: bool,
    ) -> Result<LoginOutcome, SiteError> {
        let domain =
            normalize_domain(target).ok_or_else(|| SiteError::NotADomain(target.to_owned()))?;
        let target_url = Url::parse(target.trim()).ok().filter(|u| u.path() != "/");
        let saved = self.store.site_for_host(user.id, &domain).await?;
        let login_url = target_url
            .map(|u| u.to_string())
            .or_else(|| saved.as_ref().and_then(|s| s.login_url.clone()))
            .unwrap_or_else(|| format!("https://{domain}/login"));
        let given = credentials.is_some();
        let credentials = credentials
            .or_else(|| saved.and_then(|s| s.credentials))
            .ok_or_else(|| SiteError::NoCredentials(domain.clone()))?;

        let session = self.form_login(&domain, &login_url, &credentials).await?;
        self.store
            .save_cookies(user.id, &domain, &session.jar, CookieSource::Login)
            .await?;
        let saved_credentials = given && save;
        if saved_credentials {
            self.store
                .save_credentials(
                    user.id,
                    &domain,
                    Some(login_url),
                    &credentials.username,
                    Some(&credentials.password),
                )
                .await?;
        }
        info!(user = %user.name, %domain, cookies = session.jar.len(), "site login succeeded");
        Ok(LoginOutcome {
            domain,
            landed_on: session.landed_on,
            title: session.title,
            cookie_count: session.jar.len(),
            saved_credentials,
        })
    }

    /// Performs the form login and returns the resulting session.
    async fn form_login(
        &self,
        domain: &str,
        login_url: &str,
        credentials: &Credentials,
    ) -> Result<LoggedIn, SiteError> {
        let login_url = crate::web::parse_http_url(login_url)?;
        let mut session = SiteSession::new(domain, CookieJar::default());

        let page = self
            .web
            .request(&login_url, None, Some(&mut session))
            .await?;
        let page_url = Url::parse(page.url()).unwrap_or(login_url);
        let html = String::from_utf8_lossy(&page.body).into_owned();
        let form = find_login_form(&html, &page_url)
            .ok_or_else(|| SiteError::NoLoginForm(page_url.to_string()))?;

        let post = FormPost {
            fields: form.fill(credentials),
            referer: page_url,
        };
        let response = self
            .web
            .request(&form.action, Some(&post), Some(&mut session))
            .await?;
        let landed_on = response.url().to_owned();
        let html = String::from_utf8_lossy(&response.body).into_owned();
        let (still_login, title) = tokio::task::spawn_blocking(move || {
            let doc = Selector::from_html(&html);
            let title = doc
                .css("title")
                .first()
                .map(|t| t.text().trim().to_owned())
                .filter(|t| !t.is_empty());
            (!doc.css("input[type=password]").is_empty(), title)
        })
        .await
        .map_err(WebError::from)?;

        if still_login || response.status >= 400 {
            return Err(SiteError::LoginFailed {
                domain: domain.to_owned(),
                url: landed_on,
            });
        }
        Ok(LoggedIn {
            jar: session.jar,
            landed_on,
            title,
        })
    }

    /// Loads the caller's session for the site serving `url`, per `mode`.
    async fn session_for(
        &self,
        user: &Principal,
        url: &str,
        mode: LoginMode,
    ) -> Result<Option<SiteSession>, SiteError> {
        if mode == LoginMode::Anonymous {
            return Ok(None);
        }
        let parsed = crate::web::parse_http_url(url)?;
        let host = parsed.host_str().unwrap_or_default();
        let record = self.store.site_for_host(user.id, host).await?;
        match (record, mode) {
            (Some(record), _) if record.jar.as_ref().is_some_and(|jar| !jar.is_empty()) => {
                Ok(Some(SiteSession::new(
                    record.domain,
                    record.jar.unwrap_or_default(),
                )))
            }
            (Some(record), LoginMode::Required) if record.credentials.is_some() => {
                let outcome = self.login(user, &record.domain, None, false).await?;
                let jar = self
                    .store
                    .site_for_host(user.id, &outcome.domain)
                    .await?
                    .and_then(|r| r.jar)
                    .unwrap_or_default();
                Ok(Some(SiteSession::new(outcome.domain, jar)))
            }
            (_, LoginMode::Required) => Err(SiteError::NoCredentials(
                normalize_domain(host).unwrap_or_else(|| host.to_owned()),
            )),
            _ => Ok(None),
        }
    }

    /// Saves the session's cookies if the site changed them.
    async fn persist(&self, user: &Principal, session: Option<&SiteSession>) {
        let Some(session) = session.filter(|s| s.changed) else {
            return;
        };
        if let Err(err) = self
            .store
            .save_cookies(user.id, &session.domain, &session.jar, CookieSource::Login)
            .await
        {
            error!(%err, domain = %session.domain, "failed to save updated session cookies");
        }
    }
}

/// A session established by [`Sites::form_login`].
struct LoggedIn {
    jar: CookieJar,
    landed_on: String,
    title: Option<String>,
}

/// A login form found on a page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginForm {
    /// Where the form submits to.
    pub action: Url,
    /// All fields to submit, with their default values (hidden fields, checked boxes, …).
    pub fields: Vec<(String, String)>,
    /// Name of the username/email field, if one was identified.
    pub username_field: Option<String>,
    /// Name of the password field.
    pub password_field: String,
}

impl LoginForm {
    /// The fields to submit with the credentials filled in.
    pub fn fill(&self, credentials: &Credentials) -> Vec<(String, String)> {
        self.fields
            .iter()
            .map(|(name, value)| {
                let value = if *name == self.password_field {
                    credentials.password.clone()
                } else if self.username_field.as_deref() == Some(name) {
                    credentials.username.clone()
                } else {
                    value.clone()
                };
                (name.clone(), value)
            })
            .collect()
    }
}

/// Input types that hold free text and might be the username.
const TEXT_INPUTS: &[&str] = &["text", "email", "tel", ""];

/// Name/id/autocomplete hints that identify the username field.
const USERNAME_HINTS: &[&str] = &["user", "email", "login", "account", "ident", "handle"];

/// Finds the login form on a page: the first form with exactly one password field (forms
/// with two are usually sign-up or change-password forms).
pub fn find_login_form(html: &str, page_url: &Url) -> Option<LoginForm> {
    let doc = Selector::from_html(html);
    doc.css("form")
        .iter()
        .find_map(|form| parse_login_form(form, page_url))
}

fn parse_login_form(form: &Selector, page_url: &Url) -> Option<LoginForm> {
    let attr = |el: &Selector, name: &str| el.attrib().get(name).map(|v| v.trim().to_owned());
    if form.css("input[type=password]").len() != 1 {
        return None;
    }

    let mut fields = Vec::new();
    let mut password_field = None;
    let mut text_fields = Vec::new();
    let mut submit = None;
    for input in form.css("input").iter() {
        let Some(name) = attr(input, "name").filter(|n| !n.is_empty()) else {
            continue;
        };
        let kind = attr(input, "type").unwrap_or_default().to_ascii_lowercase();
        let value = attr(input, "value").unwrap_or_default();
        match kind.as_str() {
            "password" => {
                password_field = Some(name.clone());
                fields.push((name, String::new()));
            }
            "checkbox" | "radio" => {
                if input.attrib().contains_key("checked") {
                    fields.push((name, if value.is_empty() { "on".into() } else { value }));
                }
            }
            "submit" | "image" => {
                submit.get_or_insert((name, value));
            }
            "button" | "reset" | "file" => {}
            kind => {
                if TEXT_INPUTS.contains(&kind) {
                    let hints = [
                        Some(name.clone()),
                        attr(input, "id"),
                        attr(input, "autocomplete"),
                    ];
                    text_fields.push((
                        name.clone(),
                        hints
                            .into_iter()
                            .flatten()
                            .collect::<Vec<_>>()
                            .join(" ")
                            .to_ascii_lowercase(),
                    ));
                }
                fields.push((name, value));
            }
        }
    }
    for button in form.css("button").iter() {
        let kind = attr(button, "type").unwrap_or_else(|| "submit".into());
        if let (Some(name), "submit") = (
            attr(button, "name").filter(|n| !n.is_empty()),
            kind.as_str(),
        ) {
            submit.get_or_insert((name, attr(button, "value").unwrap_or_default()));
        }
    }
    fields.extend(submit);

    let username_field = text_fields
        .iter()
        .find(|(_, hints)| USERNAME_HINTS.iter().any(|h| hints.contains(h)))
        .or_else(|| text_fields.first())
        .map(|(name, _)| name.clone());
    let action = attr(form, "action")
        .filter(|a| !a.is_empty())
        .and_then(|a| page_url.join(&a).ok())
        .unwrap_or_else(|| page_url.clone());

    Some(LoginForm {
        action,
        fields,
        username_field,
        password_field: password_field?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page() -> Url {
        Url::parse("https://accounts.example.com/login?next=/home").unwrap()
    }

    #[test]
    fn finds_login_form_with_csrf_and_username() {
        let html = r#"
            <form action="/search"><input name="q"></form>
            <form method="post" action="/login/submit">
              <input type="hidden" name="csrf_token" value="abc123">
              <input type="text" name="nickname" value="">
              <input type="email" name="inputEmailHandle" id="email">
              <input type="password" name="inputPassword">
              <input type="checkbox" name="remember" checked>
              <input type="checkbox" name="newsletter">
              <button type="submit" name="action" value="login">Log in</button>
            </form>"#;
        let form = find_login_form(html, &page()).unwrap();
        assert_eq!(
            form.action.as_str(),
            "https://accounts.example.com/login/submit"
        );
        assert_eq!(form.username_field.as_deref(), Some("inputEmailHandle"));
        assert_eq!(form.password_field, "inputPassword");

        let creds = Credentials {
            username: "me@x.com".into(),
            password: "s3cret".into(),
        };
        let filled = form.fill(&creds);
        let get = |k: &str| filled.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("csrf_token"), Some("abc123"));
        assert_eq!(get("inputEmailHandle"), Some("me@x.com"));
        assert_eq!(get("inputPassword"), Some("s3cret"));
        assert_eq!(get("remember"), Some("on"));
        assert_eq!(get("newsletter"), None);
        assert_eq!(get("action"), Some("login"));
        assert_eq!(get("nickname"), Some(""));
    }

    #[test]
    fn ignores_signup_forms_and_pages_without_forms() {
        let signup = r#"<form><input name="u"><input type="password" name="p1"><input type="password" name="p2"></form>"#;
        assert!(find_login_form(signup, &page()).is_none());
        assert!(
            find_login_form("<div id=app></div><script src=app.js></script>", &page()).is_none()
        );
    }

    #[test]
    fn empty_action_posts_back_to_the_page() {
        let html = r#"<form><input name="login"><input type="password" name="pw"></form>"#;
        let form = find_login_form(html, &page()).unwrap();
        assert_eq!(form.action, page());
        assert_eq!(form.username_field.as_deref(), Some("login"));
    }

    #[test]
    fn login_mode_from_flag() {
        assert_eq!(LoginMode::from_flag(None), LoginMode::Auto);
        assert_eq!(LoginMode::from_flag(Some(true)), LoginMode::Required);
        assert_eq!(LoginMode::from_flag(Some(false)), LoginMode::Anonymous);
    }
}

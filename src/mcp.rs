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
//! | `create_upload` | One-time URL for uploading a workspace file to attach (only when email is configured). |
//!
//! All traffic goes through the configured proxy via [`Sites`]/[`WebClient`](crate::web::WebClient). Each call acts
//! for the authenticated [`Principal`]: over HTTP it is attached to the request by
//! [`crate::auth::require_auth`] and read from the forwarded request parts; over stdio it is
//! the built-in admin. Failures are logged once, in [`report`].

use base64::{
    Engine as _, alphabet,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig, general_purpose::STANDARD},
};
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
    uploads::{UPLOAD_TTL, Uploads},
    web::{Format, PageRequest},
};

/// Prefix of a file reference (`sha256:<hex>:<path>`) that the client app should have replaced
/// with the file's bytes before calling the tool.
const FILE_REFERENCE_PREFIX: &str = "sha256:";

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

/// One attachment for `send_email`: exactly one of `text`, `url`, `content`, `upload_id`, or
/// `base64`.
#[derive(Debug, Default, Deserialize, schemars::JsonSchema)]
pub struct AttachmentArgs {
    /// File name shown to the recipient, e.g. `report.pdf`. Optional for `url` and `upload_id`
    /// attachments (defaults to the URL's last part or the name given to create_upload).
    #[serde(default)]
    pub filename: Option<String>,
    /// MIME type, e.g. `application/pdf`. Usually unnecessary: it is detected from the download
    /// or guessed from the file name.
    #[serde(default, alias = "mimeType", alias = "mime_type")]
    pub content_type: Option<String>,
    /// File contents as text (CSV, Markdown, HTML, JSON, iCalendar, source code, …).
    #[serde(default)]
    pub text: Option<String>,
    /// URL to download the file from (through the proxy, logged in if a session exists),
    /// e.g. a PDF found while browsing.
    #[serde(default)]
    pub url: Option<String>,
    /// File contents, base64-encoded. For a file in your workspace, put a file reference here
    /// instead: `sha256:<64 lowercase hex SHA-256 of the file>:<absolute path>`, e.g.
    /// `sha256:9f86…0f00a08:/mnt/user-data/outputs/report.pdf`. Apps that support file
    /// references replace it with the file's bytes before the call is sent.
    #[serde(default)]
    #[schemars(extend("format" = "byte"))]
    pub content: Option<String>,
    /// Id of a file uploaded with create_upload and curl.
    #[serde(default)]
    pub upload_id: Option<String>,
    /// File contents, base64-encoded and typed into the call. Only practical for small files
    /// (tens of KB); prefer the other sources.
    #[serde(default)]
    pub base64: Option<String>,
}

/// Arguments for the `create_upload` tool.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct UploadArgs {
    /// Absolute path of the file in your workspace, e.g.
    /// `/mnt/user-data/outputs/report.pdf`. Used to fill in the curl command and, if
    /// `filename` is not given, the attachment's name.
    #[serde(default)]
    pub path: Option<String>,
    /// File name the recipient sees, e.g. `report.pdf`. Defaults to the last part of `path`.
    #[serde(default)]
    pub filename: Option<String>,
    /// MIME type, e.g. `application/pdf`. Usually unnecessary: guessed from the file name.
    #[serde(default, alias = "mimeType", alias = "mime_type")]
    pub content_type: Option<String>,
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
    /// Files to attach (25 MB total by default). See the tool description for which source
    /// to use.
    #[serde(default)]
    pub attachments: Vec<AttachmentArgs>,
}

/// MCP server handler. Cheap to clone; the HTTP transport creates one per session.
#[derive(Clone)]
pub struct WebMcp {
    sites: Sites,
    /// Outgoing email; `None` hides the `send_email` and `create_upload` tools.
    mailer: Option<Mailer>,
    /// Upload slots for attachments; `None` (stdio, no HTTP server) hides `create_upload`.
    uploads: Option<Uploads>,
    /// Caller used when the transport carries no authentication (stdio).
    fallback: Option<Principal>,
    tool_router: ToolRouter<Self>,
}

impl WebMcp {
    /// A handler for authenticated HTTP requests. Without a `mailer` there is no
    /// `send_email` tool; without `mailer` and `uploads` there is no `create_upload`.
    pub fn new(sites: Sites, mailer: Option<Mailer>, uploads: Option<Uploads>) -> Self {
        let mut tool_router = Self::tool_router();
        if mailer.is_none() {
            tool_router.remove_route("send_email");
        }
        if mailer.is_none() || uploads.is_none() {
            tool_router.remove_route("create_upload");
        }
        Self {
            sites,
            mailer,
            uploads,
            fallback: None,
            tool_router,
        }
    }

    /// A handler that acts as `principal` for every call (stdio mode).
    pub fn acting_as(sites: Sites, mailer: Option<Mailer>, principal: Principal) -> Self {
        Self {
            fallback: Some(principal),
            ..Self::new(sites, mailer, None)
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
        let sources = [
            args.text.is_some(),
            args.url.is_some(),
            args.content.is_some(),
            args.upload_id.is_some(),
            args.base64.is_some(),
        ];
        if sources.iter().filter(|&&given| given).count() != 1 {
            return Err("each attachment needs exactly one of `text`, `url`, `content`, `upload_id`, or `base64`".into());
        }
        let built = if let Some(text) = args.text {
            Attachment::new(
                &named("attachment.txt"),
                content_type,
                None,
                text.into_bytes(),
            )
        } else if let Some(url) = args.url {
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
        } else if let Some(upload_id) = args.upload_id {
            let uploads = self
                .uploads
                .as_ref()
                .ok_or("`upload_id` attachments need the HTTP server; use another source")?;
            let file = uploads
                .get(user.id, upload_id.trim())
                .map_err(|e| e.to_string())?;
            let content_type = content_type.or(file.content_type.as_deref());
            Attachment::new(&named(&file.filename), content_type, None, file.data)
        } else {
            let (field, encoded) = match (args.content, args.base64) {
                (Some(content), _) => ("content", content),
                (_, Some(encoded)) => ("base64", encoded),
                _ => unreachable!("exactly one source is set"),
            };
            let name = named("attachment");
            let data = decode_attachment(field, &encoded)
                .map_err(|e| format!("attachment {name}: {e}"))?;
            Attachment::new(&name, content_type, None, data)
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
        description = "Send an email (with optional attachments) from the user's own email account. Only send when the user asked you to, to recipients they named or confirmed; never invent addresses. Returns the recipients and Message-ID.\n\nATTACHMENTS: each attachment needs exactly one source. Pick the first one that fits:\n1. `text`: contents you can write out as text (CSV, Markdown, HTML, JSON, .ics, code).\n2. `url`: a file on the web (e.g. a PDF you found); this server downloads it.\n3. A file in your own workspace/sandbox (e.g. /mnt/user-data/outputs/report.pdf). This server is a different machine and cannot read your files, so use one of:\n   a. `content` = a file reference `sha256:<64 lowercase hex SHA-256 of the file>:<absolute path>` (get the hash with `sha256sum`). Some Claude apps replace the reference with the file's bytes before the call is sent, as they do for the Gmail connector. If this tool answers that the reference was not replaced, your app does not support it: use b or c and don't retry a.\n   b. `upload_id`: if you can run shell commands that reach the internet, call create_upload, run the curl command it returns, then pass the upload_id it printed. If curl cannot connect, use c (or ask the user to allow the server's domain in Claude's settings).\n   c. `base64`: the bytes base64-encoded in the call. Only for small files (tens of KB); larger ones are slow and get truncated.\nNever attach a placeholder or a file you have not checked; if no method works, tell the user instead of sending.",
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
        let upload_ids: Vec<String> = args
            .attachments
            .iter()
            .filter_map(|a| a.upload_id.as_ref().map(|id| id.trim().to_owned()))
            .collect();
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
        if let Some(uploads) = &self.uploads {
            uploads.remove(user.id, &upload_ids);
        }
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

    /// Reserve a one-time upload URL for a workspace file to attach to an email.
    #[tool(
        description = "Get a one-time URL for uploading a file from your workspace/sandbox (e.g. a PDF you generated at /mnt/user-data/outputs/report.pdf) so send_email can attach it with `upload_id`. Only useful if you can run shell commands that reach the internet. Steps: 1) call create_upload with the file's `path`; 2) run the curl command it returns; it prints JSON with the upload_id and the file's sha256; 3) call send_email with \"attachments\": [{\"upload_id\": \"upl_…\"}]. The URL accepts one file and expires after an hour. If curl cannot connect (DNS failure, connection refused, or a 403 / 'host not allowed' from your sandbox's egress proxy), your workspace cannot reach this server: say so, and use a `content` file reference or small `base64` attachment instead, or ask the user to add the server's domain to the allowed domains in Claude's settings.",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn create_upload(
        &self,
        Parameters(args): Parameters<UploadArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<String, String> {
        let user = self.caller(&ctx)?;
        let (Some(mailer), Some(uploads)) = (&self.mailer, &self.uploads) else {
            return Err("uploads are not available on this server".into());
        };
        if !user.can_email {
            return Err("this user is not allowed to send email; the admin can allow it in the web-mcp admin UI".into());
        }
        let path = args.path.filter(|p| !p.trim().is_empty());
        let filename = args
            .filename
            .filter(|f| !f.trim().is_empty())
            .or_else(|| {
                path.as_deref()
                    .and_then(|p| p.rsplit(['/', '\\']).next())
                    .filter(|name| !name.is_empty())
                    .map(str::to_owned)
            })
            .ok_or("pass the file's `path` (or at least a `filename`)")?;
        let ticket = uploads
            .create(
                user.id,
                filename.clone(),
                args.content_type,
                mailer.max_attachment_bytes(),
            )
            .map_err(|e| e.to_string())?;
        tracing::info!(user = %user.name, upload_id = %ticket.upload_id, %filename, "created upload slot");
        let file = path
            .as_deref()
            .map_or_else(|| "<path to the file>".to_owned(), shell_quote);
        Ok(format!(
            "Upload slot {id} for `{filename}` (one file, at most {mb} MB, expires in {mins} minutes).\n\n\
             1. Upload the file by running:\n\n   curl -sS --fail-with-body -T {file} {url}\n\n\
             It prints JSON with \"upload_id\": \"{id}\", the byte count and the sha256; check they match your file.\n\
             2. Attach it: send_email with \"attachments\": [{{\"upload_id\": \"{id}\"}}].\n\n\
             If curl cannot connect (DNS failure, refused, or a 403 / \"host not allowed\" from your sandbox's proxy), your workspace cannot reach {host}. \
             Use a `content` file reference or a small `base64` attachment instead, or ask the user to add {host} to the allowed domains in Claude's settings.",
            id = ticket.upload_id,
            mb = ticket.max_bytes / (1024 * 1024),
            mins = UPLOAD_TTL.as_secs() / 60,
            url = shell_quote(&ticket.url),
            host = uploads.host(),
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

/// Decodes a base64 attachment from `field`, rejecting file references the app didn't replace.
fn decode_attachment(field: &str, encoded: &str) -> Result<Vec<u8>, String> {
    let encoded = encoded.trim();
    if encoded.starts_with(FILE_REFERENCE_PREFIX) {
        return Err(format!(
            "`{field}` still holds the file reference `{}`: this app did not replace it with the \
             file's bytes, so file references don't work here. Don't retry it; attach the file \
             with create_upload + `upload_id` if you can run curl with internet access, or as \
             `base64` if it is small.",
            encoded.chars().take(120).collect::<String>()
        ));
    }
    /// Standard or URL-safe alphabet, padding optional, whitespace ignored.
    const LENIENT: GeneralPurposeConfig =
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent);
    let compact: String = encoded.split_whitespace().collect();
    GeneralPurpose::new(&alphabet::STANDARD, LENIENT)
        .decode(&compact)
        .or_else(|_| GeneralPurpose::new(&alphabet::URL_SAFE, LENIENT).decode(&compact))
        .map_err(|e| format!("`{field}` is not valid base64: {e}"))
}

/// Quotes `value` for a POSIX shell.
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
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
    instructions = "Web access through a private proxy. Use web_search to find pages, fetch_url to read them, and fetch_image to view images. For sites that need an account, check list_site_logins and use site_login; sessions then apply automatically. If send_email is available, it sends mail from the user's account; only use it when asked. To attach a file from your own workspace, follow the ATTACHMENTS guide in send_email's description."
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attachment_bytes_decode_leniently_and_refuse_references() {
        assert_eq!(
            decode_attachment("content", "JVBE\nRi0=").unwrap(),
            b"%PDF-"
        );
        assert_eq!(decode_attachment("base64", "JVBERi0").unwrap(), b"%PDF-");
        assert_eq!(decode_attachment("base64", "-_8").unwrap(), [0xfb, 0xff]);
        let error = decode_attachment("content", " sha256:abc:/mnt/x.pdf").unwrap_err();
        assert!(error.contains("did not replace it"), "{error}");
        assert!(decode_attachment("base64", "not base64!").is_err());
    }

    #[test]
    fn shell_quoting_survives_quotes_and_spaces() {
        assert_eq!(shell_quote("/a b/it's.pdf"), r"'/a b/it'\''s.pdf'");
    }
}

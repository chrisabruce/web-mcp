//! Outgoing email: the `send_email` tool's sending side, over JMAP.
//!
//! The server sends from a single account configured by the operator ([`MailConfig`]): a
//! Fastmail API token (or any JMAP server's bearer token). Which callers may use it is decided
//! per user in the admin UI ([`Principal::can_email`](crate::auth::Principal::can_email)); this
//! module only validates and sends messages.
//!
//! # Sending a message over JMAP ([RFC 8620], [RFC 8621])
//!
//! 1. `GET` the session resource for the API and upload URLs and the mail account id.
//! 2. One API call resolves the sending identity (`Identity/get`) and the Drafts and Sent
//!    mailboxes (`Mailbox/query` by role).
//! 3. Each attachment is uploaded as a blob.
//! 4. One API call creates the message in Drafts (`Email/set`) and submits it
//!    (`EmailSubmission/set`); on success the server moves it to Sent and clears `$draft`, so
//!    everything Claude sends appears in the account's Sent folder.
//!
//! The server builds the MIME message, so this module only produces JSON. Mail goes straight to
//! the JMAP server over HTTPS, not through the web proxy: it is the operator's own account, and
//! signing in from proxy exits can trip the provider's fraud checks.
//!
//! [RFC 8620]: https://www.rfc-editor.org/rfc/rfc8620
//! [RFC 8621]: https://www.rfc-editor.org/rfc/rfc8621

use std::{collections::HashMap, fmt, str::FromStr, time::Duration};

use lettre::message::{Mailbox, Mailboxes};
use mime_guess::mime::{self, Mime};
use rand::RngCore as _;
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use tracing::{info, warn};

use crate::config::{MailConfig, Password};

/// Capability URNs used in API calls.
const CORE: &str = "urn:ietf:params:jmap:core";
const MAIL: &str = "urn:ietf:params:jmap:mail";
const SUBMISSION: &str = "urn:ietf:params:jmap:submission";

/// Timeout for each JMAP request (uploads can be tens of megabytes).
const HTTP_TIMEOUT: Duration = Duration::from_secs(120);

/// Bytes per megabyte, for the attachment limit.
const MB: usize = 1024 * 1024;

/// Content type used when none is given and none can be guessed from the file name.
const FALLBACK_CONTENT_TYPE: &str = "application/octet-stream";

/// A message to send.
#[derive(Debug, Clone, Default)]
pub struct Email {
    /// Primary recipients. Each entry may hold several comma-separated addresses.
    pub to: Vec<String>,
    /// Carbon-copy recipients.
    pub cc: Vec<String>,
    /// Blind-copy recipients.
    pub bcc: Vec<String>,
    /// Where replies should go, if not the sender.
    pub reply_to: Option<String>,
    /// Subject line.
    pub subject: String,
    /// Plain-text body.
    pub text: String,
    /// Optional HTML version of the body.
    pub html: Option<String>,
    /// Files to attach.
    pub attachments: Vec<Attachment>,
}

/// A file to attach.
#[derive(Clone)]
pub struct Attachment {
    /// File name shown to the recipient (already sanitised).
    pub filename: String,
    /// MIME type.
    pub content_type: Mime,
    /// File contents.
    pub data: Vec<u8>,
}

impl fmt::Debug for Attachment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Attachment")
            .field("filename", &self.filename)
            .field("content_type", &self.content_type.essence_str())
            .field("bytes", &self.data.len())
            .finish()
    }
}

impl Attachment {
    /// An attachment named `filename` holding `data`.
    ///
    /// The type is `content_type` if given, else `detected` (e.g. a download's
    /// `Content-Type`), else guessed from the file name's extension.
    ///
    /// # Errors
    ///
    /// [`MailError::InvalidAttachment`] if `content_type` is not a valid MIME type.
    pub fn new(
        filename: &str,
        content_type: Option<&str>,
        detected: Option<&str>,
        data: Vec<u8>,
    ) -> Result<Self, MailError> {
        let filename = sanitize_filename(filename);
        let explicit = content_type.map(str::trim).filter(|t| !t.is_empty());
        let detected = detected
            .map(str::trim)
            .filter(|t| !t.is_empty() && !t.starts_with(FALLBACK_CONTENT_TYPE));
        let content_type = match explicit.or(detected) {
            Some(given) => given.parse::<Mime>().map_err(|_| {
                MailError::InvalidAttachment(format!("{filename}: invalid content type `{given}`"))
            })?,
            None => mime_guess::from_path(&filename).first_or_octet_stream(),
        };
        Ok(Self {
            filename,
            content_type,
            data,
        })
    }

    /// The `charset` for a text attachment: the declared one, else UTF-8.
    fn charset(&self) -> Option<String> {
        (self.content_type.type_() == mime::TEXT).then(|| {
            self.content_type
                .get_param(mime::CHARSET)
                .map_or_else(|| "utf-8".to_owned(), |c| c.to_string())
        })
    }
}

/// What was sent, for the tool's reply and the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sent {
    /// The sender, as it appears in `From`.
    pub from: String,
    /// The `Message-ID` header value, with angle brackets.
    pub message_id: String,
    /// Every recipient address the caller gave (to, cc, and bcc).
    pub recipients: Vec<String>,
    /// Number of attachments.
    pub attachments: usize,
    /// Total attachment bytes.
    pub attachment_bytes: usize,
}

/// Why a message could not be sent.
#[derive(Debug, thiserror::Error)]
pub enum MailError {
    /// An address could not be parsed.
    #[error("invalid {field} address `{address}`: {reason}")]
    InvalidAddress {
        /// Which field (`to`, `cc`, `MAIL_FROM`, …).
        field: &'static str,
        /// The rejected input.
        address: String,
        /// Parser error.
        reason: String,
    },
    /// The message has no recipients.
    #[error("the email has no recipients")]
    NoRecipients,
    /// More recipients than `MAIL_MAX_RECIPIENTS`.
    #[error("too many recipients ({count}); at most {max} per email are allowed")]
    TooManyRecipients {
        /// Recipients requested (to + cc + bcc).
        count: usize,
        /// The configured limit.
        max: usize,
    },
    /// An attachment was malformed.
    #[error("invalid attachment: {0}")]
    InvalidAttachment(String),
    /// Attachments exceed `MAIL_MAX_ATTACHMENT_MB`.
    #[error("attachments total {mb} MB; the limit is {max_mb} MB per email")]
    TooLarge {
        /// Total attachment size, rounded up.
        mb: usize,
        /// The configured limit.
        max_mb: usize,
    },
    /// The mail server could not be reached.
    #[error("could not reach the mail server: {0}")]
    Http(#[from] wreq::Error),
    /// The API token was rejected.
    #[error("the mail server rejected FASTMAIL_API_TOKEN (HTTP {0}); check the token")]
    Unauthorized(u16),
    /// The token lacks a needed scope.
    #[error(
        "FASTMAIL_API_TOKEN lacks the {0} capability; create a token with Email and \
         Email submission access"
    )]
    MissingCapability(&'static str),
    /// No identity may send as the requested address.
    #[error("the account cannot send as {wanted}; its sending identities are: {available}")]
    NoIdentity {
        /// The `MAIL_FROM` address, or "any address".
        wanted: String,
        /// The identities that exist.
        available: String,
    },
    /// The server refused a request or answered unexpectedly.
    #[error("the mail server refused the message: {0}")]
    Jmap(String),
}

impl MailError {
    /// Whether this is the caller's mistake rather than a server or configuration failure.
    pub fn is_bad_input(&self) -> bool {
        matches!(
            self,
            Self::InvalidAddress { .. }
                | Self::NoRecipients
                | Self::TooManyRecipients { .. }
                | Self::InvalidAttachment(_)
                | Self::TooLarge { .. }
        )
    }
}

/// Sends email from the configured JMAP account. Cheap to clone.
#[derive(Clone)]
pub struct Mailer {
    http: wreq::Client,
    session_url: String,
    token: Password,
    /// `MAIL_FROM`; `None` sends as the account's primary identity.
    from: Option<Mailbox>,
    /// `MAIL_BCC`: the operator's copy of every message.
    archive: Option<Mailbox>,
    /// Most recipients (to + cc + bcc) per message, so a confused model cannot mass-mail.
    max_recipients: usize,
    /// Largest total attachment size in bytes.
    max_attachment_bytes: usize,
}

impl fmt::Debug for Mailer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mailer")
            .field("session_url", &self.session_url)
            .field("from", &self.sender())
            .finish_non_exhaustive()
    }
}

/// The validated recipients and body of a message.
struct Outgoing {
    to: Vec<Mailbox>,
    cc: Vec<Mailbox>,
    /// The caller's blind copies (the operator's `MAIL_BCC` is added when sending).
    bcc: Vec<Mailbox>,
    reply_to: Option<Mailbox>,
    subject: String,
    text: String,
    html: Option<String>,
    attachments: Vec<Attachment>,
}

/// Where and as whom to send, resolved from the JMAP session.
struct Account {
    api_url: String,
    upload_url: String,
    id: String,
    identity_id: String,
    from: Mailbox,
    drafts: String,
    sent: Option<String>,
}

/// The JMAP session resource (only the fields used).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Session {
    api_url: String,
    upload_url: String,
    primary_accounts: HashMap<String, String>,
    capabilities: HashMap<String, Value>,
}

/// A sending identity.
#[derive(Deserialize)]
struct Identity {
    id: String,
    #[serde(default)]
    name: String,
    email: String,
}

/// A JMAP API response: `[name, arguments, call id]` triples.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiResponse {
    method_responses: Vec<(String, Value, String)>,
}

impl ApiResponse {
    /// The arguments of the response to `call_id`, or the error it reported.
    fn get(&self, call_id: &str) -> Result<&Value, MailError> {
        let (name, args, _) = self
            .method_responses
            .iter()
            .find(|(_, _, id)| id == call_id)
            .ok_or_else(|| MailError::Jmap(format!("no response to `{call_id}`")))?;
        if name == "error" {
            return Err(MailError::Jmap(describe(args)));
        }
        Ok(args)
    }

    /// Fails with the `SetError` if `/set` call `call_id` did not create `key`.
    fn expect_created(&self, call_id: &str, key: &str) -> Result<(), MailError> {
        let args = self.get(call_id)?;
        if let Some(error) = args["notCreated"].get(key) {
            return Err(MailError::Jmap(describe(error)));
        }
        if args["created"].get(key).is_none() {
            return Err(MailError::Jmap(format!(
                "`{call_id}` did not create `{key}`"
            )));
        }
        Ok(())
    }
}

/// `type: description` of a JMAP error or `SetError` object.
fn describe(error: &Value) -> String {
    let kind = error["type"].as_str().unwrap_or("error");
    match error["description"].as_str() {
        Some(description) => format!("{kind}: {description}"),
        None => kind.to_owned(),
    }
}

impl Mailer {
    /// Builds a mailer from `config`, or `None` if `FASTMAIL_API_TOKEN` is not set.
    ///
    /// # Errors
    ///
    /// [`MailError::InvalidAddress`] for an unparsable `MAIL_FROM` or `MAIL_BCC`, and
    /// [`MailError::Http`] if the HTTP client cannot be built.
    pub fn from_config(config: &MailConfig) -> Result<Option<Self>, MailError> {
        let Some(token) = config.api_token.clone() else {
            return Ok(None);
        };
        let optional = |field, value: &Option<String>| {
            value
                .as_deref()
                .filter(|v| !v.trim().is_empty())
                .map(|v| parse_mailbox(field, v))
                .transpose()
        };
        let http = wreq::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .no_proxy()
            .build()?;
        Ok(Some(Self {
            http,
            session_url: config.jmap_session_url.clone(),
            token,
            from: optional("MAIL_FROM", &config.mail_from)?,
            archive: optional("MAIL_BCC", &config.mail_bcc)?,
            max_recipients: config.mail_max_recipients as usize,
            max_attachment_bytes: config.mail_max_attachment_mb as usize * MB,
        }))
    }

    /// The configured sender, for display.
    pub fn sender(&self) -> String {
        self.from.as_ref().map_or_else(
            || "your account's primary address".to_owned(),
            Mailbox::to_string,
        )
    }

    /// Largest total attachment size in bytes (`MAIL_MAX_ATTACHMENT_MB`).
    pub fn max_attachment_bytes(&self) -> usize {
        self.max_attachment_bytes
    }

    /// The error for attachments totalling `bytes`.
    pub fn too_large(&self, bytes: usize) -> MailError {
        MailError::TooLarge {
            mb: bytes.div_ceil(MB),
            max_mb: self.max_attachment_bytes / MB,
        }
    }

    /// Signs in and resolves the sending identity, logging the outcome. Meant to run once at
    /// startup so a bad token or `MAIL_FROM` shows up in the logs before the first send.
    pub async fn check(&self) {
        match self.account().await {
            Ok(account) => info!(from = %account.from, "email enabled"),
            Err(error) => warn!(%error, "email enabled, but the account check failed"),
        }
    }

    /// Sends `email`.
    ///
    /// # Errors
    ///
    /// Bad addresses, too many recipients or attachment bytes, and server failures; see
    /// [`MailError`].
    pub async fn send(&self, email: Email) -> Result<Sent, MailError> {
        let outgoing = self.validate(email)?;
        let account = self.account().await?;
        let mut blobs = Vec::with_capacity(outgoing.attachments.len());
        for attachment in &outgoing.attachments {
            blobs.push(self.upload(&account, attachment).await?);
        }
        let message_id = message_id(&account.from);
        let request = self.submission_request(&account, &outgoing, &blobs, &message_id);
        let response = self.api(&account.api_url, &request).await?;
        response.expect_created("create", "draft")?;
        response.expect_created("submit", "send")?;

        Ok(Sent {
            from: account.from.to_string(),
            message_id: format!("<{message_id}>"),
            recipients: outgoing
                .to
                .iter()
                .chain(&outgoing.cc)
                .chain(&outgoing.bcc)
                .map(|m| m.email.to_string())
                .collect(),
            attachments: outgoing.attachments.len(),
            attachment_bytes: outgoing.attachments.iter().map(|a| a.data.len()).sum(),
        })
    }

    /// Parses addresses and enforces the limits.
    fn validate(&self, email: Email) -> Result<Outgoing, MailError> {
        let to = parse_list("to", &email.to)?;
        let cc = parse_list("cc", &email.cc)?;
        let bcc = parse_list("bcc", &email.bcc)?;
        let count = to.len() + cc.len() + bcc.len();
        if count == 0 {
            return Err(MailError::NoRecipients);
        }
        if count > self.max_recipients {
            return Err(MailError::TooManyRecipients {
                count,
                max: self.max_recipients,
            });
        }
        let attachment_bytes: usize = email.attachments.iter().map(|a| a.data.len()).sum();
        if attachment_bytes > self.max_attachment_bytes {
            return Err(self.too_large(attachment_bytes));
        }
        let reply_to = email
            .reply_to
            .as_deref()
            .filter(|r| !r.trim().is_empty())
            .map(|r| parse_mailbox("reply_to", r))
            .transpose()?;
        Ok(Outgoing {
            to,
            cc,
            bcc,
            reply_to,
            subject: email.subject.trim().to_owned(),
            text: email.text,
            html: email.html.filter(|h| !h.trim().is_empty()),
            attachments: email.attachments,
        })
    }

    /// Fetches the session, then the identity and mailboxes.
    async fn account(&self) -> Result<Account, MailError> {
        let session: Session = self.get_json(&self.session_url).await?;
        for capability in [MAIL, SUBMISSION] {
            if !session.capabilities.contains_key(capability) {
                return Err(MailError::MissingCapability(capability));
            }
        }
        let id = session
            .primary_accounts
            .get(MAIL)
            .cloned()
            .ok_or(MailError::MissingCapability(MAIL))?;
        let request = json!({
            "using": [CORE, MAIL, SUBMISSION],
            "methodCalls": [
                ["Identity/get", {"accountId": id, "ids": null}, "identities"],
                ["Mailbox/query", {"accountId": id, "filter": {"role": "drafts"}}, "drafts"],
                ["Mailbox/query", {"accountId": id, "filter": {"role": "sent"}}, "sent"],
            ],
        });
        let response = self.api(&session.api_url, &request).await?;
        let identities: Vec<Identity> =
            serde_json::from_value(response.get("identities")?["list"].clone())
                .map_err(|e| MailError::Jmap(format!("unexpected Identity/get response: {e}")))?;
        let (identity_id, from) = pick_identity(&identities, self.from.as_ref())?;
        let first_id = |call: &str| -> Result<Option<String>, MailError> {
            Ok(response.get(call)?["ids"][0].as_str().map(str::to_owned))
        };
        let drafts = first_id("drafts")?
            .ok_or_else(|| MailError::Jmap("the account has no Drafts mailbox".into()))?;
        Ok(Account {
            api_url: session.api_url,
            upload_url: session.upload_url.replace("{accountId}", &id),
            id,
            identity_id,
            from,
            drafts,
            sent: first_id("sent")?,
        })
    }

    /// The `Email/set` + `EmailSubmission/set` request that creates and sends the message.
    fn submission_request(
        &self,
        account: &Account,
        outgoing: &Outgoing,
        blobs: &[String],
        message_id: &str,
    ) -> Value {
        let addresses = |list: &[Mailbox]| -> Value {
            list.iter()
                .map(|m| json!({"name": m.name, "email": m.email.to_string()}))
                .collect()
        };
        let bcc: Vec<Mailbox> = outgoing.bcc.iter().chain(&self.archive).cloned().collect();
        let mut email = json!({
            "mailboxIds": {&account.drafts: true},
            "keywords": {"$draft": true, "$seen": true},
            "from": addresses(std::slice::from_ref(&account.from)),
            "to": addresses(&outgoing.to),
            "subject": outgoing.subject,
            "messageId": [message_id],
            "bodyValues": {"text": {"value": outgoing.text}},
            "textBody": [{"partId": "text", "type": "text/plain"}],
        });
        if !outgoing.cc.is_empty() {
            email["cc"] = addresses(&outgoing.cc);
        }
        if !bcc.is_empty() {
            email["bcc"] = addresses(&bcc);
        }
        if let Some(reply_to) = &outgoing.reply_to {
            email["replyTo"] = addresses(std::slice::from_ref(reply_to));
        }
        if let Some(html) = &outgoing.html {
            email["bodyValues"]["html"] = json!({"value": html});
            email["htmlBody"] = json!([{"partId": "html", "type": "text/html"}]);
        }
        if !blobs.is_empty() {
            email["attachments"] = outgoing
                .attachments
                .iter()
                .zip(blobs)
                .map(|(attachment, blob)| {
                    json!({
                        "blobId": blob,
                        "type": attachment.content_type.essence_str(),
                        "charset": attachment.charset(),
                        "name": attachment.filename,
                        "disposition": "attachment",
                    })
                })
                .collect();
        }

        // On success, file the message in Sent (or just un-draft it if there is no Sent box).
        let mut on_success = json!({"keywords/$draft": null});
        if let Some(sent) = &account.sent {
            on_success[format!("mailboxIds/{}", account.drafts)] = Value::Null;
            on_success[format!("mailboxIds/{sent}")] = Value::Bool(true);
        }
        json!({
            "using": [CORE, MAIL, SUBMISSION],
            "methodCalls": [
                ["Email/set", {"accountId": account.id, "create": {"draft": email}}, "create"],
                ["EmailSubmission/set", {
                    "accountId": account.id,
                    "create": {"send": {"identityId": account.identity_id, "emailId": "#draft"}},
                    "onSuccessUpdateEmail": {"#send": on_success},
                }, "submit"],
            ],
        })
    }

    /// Uploads an attachment; returns its blob id.
    async fn upload(
        &self,
        account: &Account,
        attachment: &Attachment,
    ) -> Result<String, MailError> {
        let response = self
            .http
            .post(&account.upload_url)
            .bearer_auth(self.token.expose())
            .header("content-type", attachment.content_type.essence_str())
            .body(attachment.data.clone())
            .send()
            .await?;
        let uploaded: Value = read_json(response).await?;
        uploaded["blobId"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| MailError::Jmap(format!("upload of {} failed", attachment.filename)))
    }

    /// Makes a JMAP API request.
    async fn api(&self, api_url: &str, request: &Value) -> Result<ApiResponse, MailError> {
        let response = self
            .http
            .post(api_url)
            .bearer_auth(self.token.expose())
            .header("content-type", "application/json")
            .body(request.to_string())
            .send()
            .await?;
        read_json(response).await
    }

    async fn get_json<T: DeserializeOwned>(&self, url: &str) -> Result<T, MailError> {
        let response = self
            .http
            .get(url)
            .bearer_auth(self.token.expose())
            .send()
            .await?;
        read_json(response).await
    }
}

/// Decodes a JSON response, mapping auth failures and other error statuses.
async fn read_json<T: DeserializeOwned>(response: wreq::Response) -> Result<T, MailError> {
    let status = response.status().as_u16();
    let body = response.bytes().await?;
    match status {
        200..300 => serde_json::from_slice(&body)
            .map_err(|e| MailError::Jmap(format!("unexpected response: {e}"))),
        401 | 403 => Err(MailError::Unauthorized(status)),
        _ => {
            let text = String::from_utf8_lossy(&body);
            Err(MailError::Jmap(format!(
                "HTTP {status}: {}",
                text.chars().take(300).collect::<String>()
            )))
        }
    }
}

/// Picks the identity to send as: the one matching `wanted` (exactly, or a `*@domain`
/// wildcard identity), else the first ordinary identity.
fn pick_identity(
    identities: &[Identity],
    wanted: Option<&Mailbox>,
) -> Result<(String, Mailbox), MailError> {
    let mailbox = |identity: &Identity| -> Option<Mailbox> {
        let name = Some(identity.name.trim().to_owned()).filter(|n| !n.is_empty());
        identity
            .email
            .parse()
            .ok()
            .map(|email| Mailbox::new(name, email))
    };
    let found = match wanted {
        Some(wanted) => {
            let address = wanted.email.to_string().to_lowercase();
            let wildcard = format!("*@{}", wanted.email.domain().to_lowercase());
            identities
                .iter()
                .find(|i| i.email.to_lowercase() == address)
                .or_else(|| {
                    identities
                        .iter()
                        .find(|i| i.email.to_lowercase() == wildcard)
                })
                .map(|identity| {
                    let name = wanted
                        .name
                        .clone()
                        .or_else(|| mailbox(identity).and_then(|m| m.name));
                    (
                        identity.id.clone(),
                        Mailbox::new(name, wanted.email.clone()),
                    )
                })
        }
        // A `*@domain` identity is a catch-all, not an address to send from.
        None => identities
            .iter()
            .filter(|identity| !identity.email.starts_with('*'))
            .find_map(|identity| Some((identity.id.clone(), mailbox(identity)?))),
    };
    found.ok_or_else(|| MailError::NoIdentity {
        wanted: wanted.map_or_else(|| "any address".to_owned(), |w| w.email.to_string()),
        available: identities
            .iter()
            .map(|i| i.email.as_str())
            .collect::<Vec<_>>()
            .join(", "),
    })
}

/// A unique `Message-ID` (without angle brackets) in the sender's domain.
fn message_id(from: &Mailbox) -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let id: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("{id}@{}", from.email.domain())
}

fn parse_mailbox(field: &'static str, input: &str) -> Result<Mailbox, MailError> {
    input.trim().parse().map_err(
        |e: lettre::address::AddressError| MailError::InvalidAddress {
            field,
            address: input.to_owned(),
            reason: e.to_string(),
        },
    )
}

/// Parses entries that may each hold several comma-separated addresses.
fn parse_list(field: &'static str, entries: &[String]) -> Result<Vec<Mailbox>, MailError> {
    let mut mailboxes = Vec::new();
    for entry in entries.iter().map(|e| e.trim()).filter(|e| !e.is_empty()) {
        let parsed = Mailboxes::from_str(entry).map_err(|e| MailError::InvalidAddress {
            field,
            address: entry.to_owned(),
            reason: e.to_string(),
        })?;
        mailboxes.extend(parsed);
    }
    Ok(mailboxes)
}

/// Keeps only the last path component and drops control and quoting characters.
fn sanitize_filename(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or_default();
    let clean: String = base
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, '"' | '<' | '>'))
        .collect();
    let clean = clean.trim().trim_start_matches('.');
    if clean.is_empty() {
        "attachment".into()
    } else {
        clean.chars().take(200).collect()
    }
}

/// A fake JMAP server for tests, recording what is uploaded and sent.
#[cfg(test)]
pub mod testing {
    use std::sync::{Arc, Mutex};

    use axum::{
        Json, Router,
        body::Bytes,
        extract::State,
        http::{HeaderMap, StatusCode},
        routing::{get, post},
    };
    use serde_json::{Value, json};

    use super::{CORE, MAIL, Mailer, SUBMISSION};
    use crate::config::MailConfig;

    /// The token the fake server accepts.
    const TOKEN: &str = "fmu1-test-token";

    /// What the fake server has received.
    #[derive(Clone, Default)]
    pub struct FakeJmap {
        base: String,
        /// `(content type, bytes)` of each upload.
        pub uploads: Arc<Mutex<Vec<(String, usize)>>>,
        /// Each created email object.
        pub sent: Arc<Mutex<Vec<Value>>>,
        /// Each `EmailSubmission/set` call's arguments.
        pub submissions: Arc<Mutex<Vec<Value>>>,
    }

    impl FakeJmap {
        /// The emails sent so far.
        pub fn sent(&self) -> Vec<Value> {
            self.sent.lock().unwrap().clone()
        }
    }

    fn authorized(headers: &HeaderMap) -> Result<(), StatusCode> {
        let expected = format!("Bearer {TOKEN}");
        headers
            .get("authorization")
            .is_some_and(|v| v == expected.as_str())
            .then_some(())
            .ok_or(StatusCode::UNAUTHORIZED)
    }

    async fn session(
        State(fake): State<FakeJmap>,
        headers: HeaderMap,
    ) -> Result<Json<Value>, StatusCode> {
        authorized(&headers)?;
        Ok(Json(json!({
            "apiUrl": format!("{}/api", fake.base),
            "uploadUrl": format!("{}/upload/{{accountId}}/", fake.base),
            "primaryAccounts": {MAIL: "acc1", SUBMISSION: "acc1"},
            "capabilities": {CORE: {}, MAIL: {}, SUBMISSION: {}},
        })))
    }

    async fn upload(
        State(fake): State<FakeJmap>,
        headers: HeaderMap,
        body: Bytes,
    ) -> Result<Json<Value>, StatusCode> {
        authorized(&headers)?;
        let kind = headers["content-type"].to_str().unwrap().to_owned();
        let mut uploads = fake.uploads.lock().unwrap();
        uploads.push((kind, body.len()));
        Ok(Json(
            json!({"accountId": "acc1", "blobId": format!("blob{}", uploads.len())}),
        ))
    }

    async fn api(
        State(fake): State<FakeJmap>,
        headers: HeaderMap,
        Json(request): Json<Value>,
    ) -> Result<Json<Value>, StatusCode> {
        authorized(&headers)?;
        let responses: Vec<Value> = request["methodCalls"]
            .as_array()
            .unwrap()
            .iter()
            .map(|call| {
                let (name, args, id) = (call[0].as_str().unwrap(), &call[1], &call[2]);
                let result = match name {
                    "Identity/get" => json!({"list": [
                        {"id": "ident-wild", "name": "", "email": "*@example.com"},
                        {"id": "ident-me", "name": "Me", "email": "me@fastmail.com"},
                    ]}),
                    "Mailbox/query" => match args["filter"]["role"].as_str() {
                        Some("drafts") => json!({"ids": ["mb-drafts"]}),
                        _ => json!({"ids": ["mb-sent"]}),
                    },
                    "Email/set" => {
                        fake.sent
                            .lock()
                            .unwrap()
                            .push(args["create"]["draft"].clone());
                        json!({"created": {"draft": {"id": "email1"}}})
                    }
                    "EmailSubmission/set" => {
                        fake.submissions.lock().unwrap().push(args.clone());
                        json!({"created": {"send": {"id": "sub1"}}})
                    }
                    other => panic!("unexpected method {other}"),
                };
                json!([name, result, id])
            })
            .collect();
        Ok(Json(json!({"methodResponses": responses})))
    }

    /// Starts a fake JMAP server; returns a mailer for it (after applying `tweak` to its
    /// configuration) and the recorder.
    pub async fn fake_jmap(tweak: impl FnOnce(&mut MailConfig)) -> (Mailer, FakeJmap) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let fake = FakeJmap {
            base: base.clone(),
            ..FakeJmap::default()
        };
        let app = Router::new()
            .route("/jmap/session", get(session))
            .route("/upload/acc1/", post(upload))
            .route("/api", post(api))
            .layer(axum::extract::DefaultBodyLimit::disable())
            .with_state(fake.clone());
        tokio::spawn(async move { axum::serve(listener, app).await });
        let mut config = MailConfig {
            api_token: Some(TOKEN.parse().unwrap()),
            jmap_session_url: format!("{base}/jmap/session"),
            mail_from: None,
            mail_bcc: None,
            mail_max_recipients: 2,
            mail_max_attachment_mb: 25,
        };
        tweak(&mut config);
        (Mailer::from_config(&config).unwrap().unwrap(), fake)
    }
}

#[cfg(test)]
mod tests {
    use super::{testing::fake_jmap, *};

    fn email(to: &[&str]) -> Email {
        Email {
            to: to.iter().map(|s| (*s).to_owned()).collect(),
            subject: "Hello".into(),
            text: "Plain body".into(),
            ..Email::default()
        }
    }

    #[tokio::test]
    async fn sends_plain_text_as_the_primary_identity_and_files_it_in_sent() {
        let (mailer, fake) = fake_jmap(|_| {}).await;
        let sent = mailer
            .send(email(&["a@example.org, B <b@example.org>"]))
            .await
            .unwrap();
        assert_eq!(sent.recipients, ["a@example.org", "b@example.org"]);
        assert_eq!(sent.from, "Me <me@fastmail.com>");
        assert!(sent.message_id.ends_with("@fastmail.com>"));

        let draft = &fake.sent()[0];
        assert_eq!(
            draft["from"],
            json!([{"name": "Me", "email": "me@fastmail.com"}])
        );
        assert_eq!(
            draft["to"][1],
            json!({"name": "B", "email": "b@example.org"})
        );
        assert_eq!(draft["subject"], "Hello");
        assert_eq!(draft["bodyValues"]["text"]["value"], "Plain body");
        assert_eq!(draft["mailboxIds"], json!({"mb-drafts": true}));
        assert!(draft.get("htmlBody").is_none() && draft.get("attachments").is_none());

        let submission = &fake.submissions.lock().unwrap()[0];
        assert_eq!(submission["create"]["send"]["identityId"], "ident-me");
        assert_eq!(
            submission["onSuccessUpdateEmail"]["#send"],
            json!({"keywords/$draft": null, "mailboxIds/mb-drafts": null, "mailboxIds/mb-sent": true})
        );
    }

    #[tokio::test]
    async fn uploads_attachments_and_honours_from_and_bcc() {
        let (mailer, fake) = fake_jmap(|c| {
            c.mail_from = Some("Chris <chris@example.com>".into());
            c.mail_bcc = Some("archive@example.com".into());
        })
        .await;
        let csv = Attachment::new("../../report.csv", None, None, b"a,b\n1,2\n".to_vec()).unwrap();
        let pdf =
            Attachment::new("scan", None, Some("application/pdf"), b"%PDF-1.4".to_vec()).unwrap();
        let message = Email {
            html: Some("<p>Hi</p>".into()),
            bcc: vec!["secret@example.org".into()],
            attachments: vec![csv, pdf],
            ..email(&["a@example.org"])
        };
        let sent = mailer.send(message).await.unwrap();
        assert_eq!(sent.recipients, ["a@example.org", "secret@example.org"]);
        assert_eq!(
            (sent.attachments, sent.from.as_str()),
            (2, "Chris <chris@example.com>")
        );

        let uploads = fake.uploads.lock().unwrap().clone();
        assert_eq!(
            uploads,
            [("text/csv".into(), 8), ("application/pdf".into(), 8)]
        );
        let draft = &fake.sent()[0];
        assert_eq!(draft["bcc"][0]["email"], "secret@example.org");
        assert_eq!(draft["bcc"][1]["email"], "archive@example.com");
        assert_eq!(draft["htmlBody"][0]["partId"], "html");
        assert_eq!(draft["attachments"][0]["name"], "report.csv");
        assert_eq!(draft["attachments"][0]["charset"], "utf-8");
        assert_eq!(draft["attachments"][1]["type"], "application/pdf");
        assert_eq!(draft["attachments"][1]["blobId"], "blob2");
        // chris@example.com is covered by the account's *@example.com identity.
        assert_eq!(
            fake.submissions.lock().unwrap()[0]["create"]["send"]["identityId"],
            "ident-wild"
        );
    }

    #[tokio::test]
    async fn rejects_bad_input_bad_tokens_and_unknown_senders() {
        let (mailer, fake) = fake_jmap(|_| {}).await;
        assert!(matches!(
            mailer.send(email(&[])).await,
            Err(MailError::NoRecipients)
        ));
        assert!(matches!(
            mailer.send(email(&["not an address"])).await,
            Err(MailError::InvalidAddress { field: "to", .. })
        ));
        let crowd = Email {
            cc: vec!["b@x.org".into()],
            bcc: vec!["c@x.org".into()],
            ..email(&["a@x.org"])
        };
        assert!(matches!(
            mailer.send(crowd).await,
            Err(MailError::TooManyRecipients { count: 3, max: 2 })
        ));
        let big = Attachment::new("big.bin", None, None, vec![0; 25 * MB + 1]).unwrap();
        let heavy = Email {
            attachments: vec![big],
            ..email(&["a@x.org"])
        };
        assert!(matches!(
            mailer.send(heavy).await,
            Err(MailError::TooLarge { mb: 26, max_mb: 25 })
        ));
        assert!(Attachment::new("x", Some("not a type"), None, vec![]).is_err());
        assert!(fake.sent().is_empty());

        let (wrong_token, _) = fake_jmap(|c| c.api_token = Some("nope".parse().unwrap())).await;
        assert!(matches!(
            wrong_token.send(email(&["a@x.org"])).await,
            Err(MailError::Unauthorized(401))
        ));
        let (stranger, _) = fake_jmap(|c| c.mail_from = Some("me@elsewhere.org".into())).await;
        let err = stranger.send(email(&["a@x.org"])).await.unwrap_err();
        assert!(
            err.to_string().contains("cannot send as me@elsewhere.org")
                && err.to_string().contains("me@fastmail.com"),
            "{err}"
        );
    }

    #[test]
    fn mail_is_off_without_a_token_and_the_token_is_not_debug_printed() {
        let mut config = MailConfig {
            api_token: None,
            jmap_session_url: "https://api.fastmail.com/jmap/session".into(),
            mail_from: None,
            mail_bcc: None,
            mail_max_recipients: 5,
            mail_max_attachment_mb: 10,
        };
        assert!(Mailer::from_config(&config).unwrap().is_none());
        config.api_token = Some("fmu1-secret".parse().unwrap());
        let mailer = Mailer::from_config(&config).unwrap().unwrap();
        assert_eq!(
            (mailer.max_recipients, mailer.max_attachment_bytes()),
            (5, 10 * MB)
        );
        assert!(!format!("{mailer:?}").contains("fmu1-secret"));
        config.mail_from = Some("not an address".into());
        assert!(Mailer::from_config(&config).is_err());
    }

    #[test]
    fn filenames_are_sanitized() {
        assert_eq!(sanitize_filename("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_filename("C:\\Users\\x\\a\"b.txt"), "ab.txt");
        assert_eq!(sanitize_filename(".."), "attachment");
        assert_eq!(sanitize_filename(""), "attachment");
    }
}

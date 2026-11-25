//! Short-lived file uploads for `send_email` attachments.
//!
//! Claude's workspace (code execution sandbox) and this server are different machines, so a file
//! Claude generated there can't be attached by path. The `create_upload` tool reserves a slot
//! and returns a single-use URL; Claude `curl`s the file to it (`PUT /uploads/{token}`), then
//! passes the slot's `upload_id` to `send_email`.
//!
//! * The URL token is 32 random bytes and is the only credential for the upload, so no API key
//!   ends up in a shell command. Only its SHA-256 is kept.
//! * Each URL accepts one file, at most the slot's byte limit (the email attachment limit).
//! * `upload_id`s are bound to the user who created them; nobody else can attach the file.
//! * Slots live in memory and expire after [`UPLOAD_TTL`]; a sent file is dropped at once.
//!   A restart forgets pending uploads, which is fine for files minutes old.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::put,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore as _;
use sha2::{Digest as _, Sha256};
use tracing::info;

use crate::store::UserId;

/// How long an upload slot (and the file in it) lives.
pub const UPLOAD_TTL: Duration = Duration::from_secs(60 * 60);

/// Live upload slots one user may hold at a time.
const MAX_SLOTS_PER_USER: usize = 10;

/// Why an upload or a lookup failed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UploadError {
    /// The upload URL is wrong, expired, or was never issued.
    #[error("unknown or expired upload URL; call create_upload again for a new one")]
    UnknownToken,
    /// The upload URL was already used.
    #[error("this upload URL was already used; call create_upload again to upload another file")]
    AlreadyUploaded,
    /// The body was empty.
    #[error("the upload was empty; send the file's bytes as the request body (curl -T <file>)")]
    Empty,
    /// The body was a multipart form instead of the raw file.
    #[error(
        "send the raw file as the request body (curl -T <file> <url>), not a multipart form (-F)"
    )]
    Multipart,
    /// The body was larger than the slot allows.
    #[error("the file is larger than the {max_mb} MB attachment limit")]
    TooLarge {
        /// The limit, in MB.
        max_mb: usize,
    },
    /// Too many open slots for this user.
    #[error(
        "too many pending uploads ({MAX_SLOTS_PER_USER}); send or let the earlier ones expire first"
    )]
    TooMany,
    /// No such `upload_id` for this user.
    #[error("unknown or expired upload_id `{0}`; call create_upload and upload the file again")]
    UnknownId(String),
    /// The slot exists but no file was uploaded to it yet.
    #[error(
        "upload_id `{0}` has no file yet: run the curl command create_upload returned first, and check that it printed the upload_id"
    )]
    NotUploaded(String),
}

impl UploadError {
    /// HTTP status for the upload endpoint.
    fn status(&self) -> StatusCode {
        match self {
            Self::UnknownToken | Self::UnknownId(_) | Self::NotUploaded(_) => StatusCode::NOT_FOUND,
            Self::AlreadyUploaded => StatusCode::CONFLICT,
            Self::Empty => StatusCode::BAD_REQUEST,
            Self::Multipart => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::TooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
            Self::TooMany => StatusCode::TOO_MANY_REQUESTS,
        }
    }
}

/// A reserved upload slot, as reported to the model.
#[derive(Debug, Clone)]
pub struct Ticket {
    /// What `send_email` takes to attach the file.
    pub upload_id: String,
    /// Where to `PUT` the file. Contains the secret token.
    pub url: String,
    /// Largest accepted file.
    pub max_bytes: usize,
}

/// A file that arrived in a slot.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Received {
    /// The slot's id, for `send_email`.
    pub upload_id: String,
    /// The file name the attachment will get.
    pub filename: String,
    /// Size of the file.
    pub bytes: usize,
    /// Hex SHA-256 of the file, so the uploader can check it.
    pub sha256: String,
    /// What to do next.
    pub next: String,
}

/// An uploaded file, ready to attach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredFile {
    /// File name given to `create_upload`.
    pub filename: String,
    /// MIME type given to `create_upload`, if any.
    pub content_type: Option<String>,
    /// The bytes.
    pub data: Vec<u8>,
}

#[derive(Debug)]
struct Slot {
    upload_id: String,
    owner: UserId,
    filename: String,
    content_type: Option<String>,
    max_bytes: usize,
    expires: Instant,
    data: Option<Vec<u8>>,
}

/// The upload slots, shared by the MCP handlers and the upload endpoint. Cheap to clone.
#[derive(Debug, Clone)]
pub struct Uploads {
    /// Public base URL the upload links are built on, without a trailing slash.
    base: String,
    /// Slots keyed by the SHA-256 of their URL token.
    slots: Arc<Mutex<HashMap<[u8; 32], Slot>>>,
}

impl Uploads {
    /// An empty store whose upload links start with `base` (e.g. `https://mcp.example.com`).
    pub fn new(base: &str) -> Self {
        Self {
            base: base.trim_end_matches('/').to_owned(),
            slots: Arc::default(),
        }
    }

    /// The host name upload links point at, for "allow this domain" advice.
    pub fn host(&self) -> &str {
        let rest = self
            .base
            .split_once("://")
            .map_or(&*self.base, |(_, rest)| rest);
        rest.split(['/', ':']).next().unwrap_or(rest)
    }

    /// Reserves a slot for `owner` that accepts one file of up to `max_bytes`.
    ///
    /// # Errors
    ///
    /// [`UploadError::TooMany`] when `owner` already holds [`MAX_SLOTS_PER_USER`] live slots.
    pub fn create(
        &self,
        owner: UserId,
        filename: String,
        content_type: Option<String>,
        max_bytes: usize,
    ) -> Result<Ticket, UploadError> {
        let mut slots = self.lock();
        if slots.values().filter(|s| s.owner == owner).count() >= MAX_SLOTS_PER_USER {
            return Err(UploadError::TooMany);
        }
        let token = URL_SAFE_NO_PAD.encode(random::<32>());
        let upload_id = format!("upl_{}", hex(&random::<9>()));
        slots.insert(
            digest(&token),
            Slot {
                upload_id: upload_id.clone(),
                owner,
                filename,
                content_type,
                max_bytes,
                expires: Instant::now() + UPLOAD_TTL,
                data: None,
            },
        );
        Ok(Ticket {
            upload_id,
            url: format!("{}/uploads/{token}", self.base),
            max_bytes,
        })
    }

    /// Byte limit of the slot behind `token`.
    fn limit(&self, token: &str) -> Result<usize, UploadError> {
        let slots = self.lock();
        let slot = slots.get(&digest(token)).ok_or(UploadError::UnknownToken)?;
        match slot.data {
            Some(_) => Err(UploadError::AlreadyUploaded),
            None => Ok(slot.max_bytes),
        }
    }

    /// Stores `data` in the slot behind `token`.
    fn fill(&self, token: &str, data: Vec<u8>) -> Result<Received, UploadError> {
        if data.is_empty() {
            return Err(UploadError::Empty);
        }
        let mut slots = self.lock();
        let slot = slots
            .get_mut(&digest(token))
            .ok_or(UploadError::UnknownToken)?;
        if slot.data.is_some() {
            return Err(UploadError::AlreadyUploaded);
        }
        if data.len() > slot.max_bytes {
            return Err(UploadError::TooLarge {
                max_mb: slot.max_bytes / (1024 * 1024),
            });
        }
        let received = Received {
            upload_id: slot.upload_id.clone(),
            filename: slot.filename.clone(),
            bytes: data.len(),
            sha256: hex(&Sha256::digest(&data)),
            next: format!(
                "Attach it with send_email: \"attachments\": [{{\"upload_id\": \"{}\"}}]",
                slot.upload_id
            ),
        };
        slot.data = Some(data);
        Ok(received)
    }

    /// A copy of `owner`'s uploaded file `upload_id`. The slot stays until [`Self::remove`],
    /// so a failed send can be retried.
    ///
    /// # Errors
    ///
    /// [`UploadError::UnknownId`] for an id that is unknown, expired, or someone else's;
    /// [`UploadError::NotUploaded`] when the file hasn't arrived yet.
    pub fn get(&self, owner: UserId, upload_id: &str) -> Result<StoredFile, UploadError> {
        let slots = self.lock();
        let slot = slots
            .values()
            .find(|s| s.owner == owner && s.upload_id == upload_id)
            .ok_or_else(|| UploadError::UnknownId(upload_id.to_owned()))?;
        let data = slot
            .data
            .clone()
            .ok_or_else(|| UploadError::NotUploaded(upload_id.to_owned()))?;
        Ok(StoredFile {
            filename: slot.filename.clone(),
            content_type: slot.content_type.clone(),
            data,
        })
    }

    /// Drops `owner`'s slots `upload_ids` (after they were sent).
    pub fn remove(&self, owner: UserId, upload_ids: &[String]) {
        self.lock()
            .retain(|_, s| !(s.owner == owner && upload_ids.contains(&s.upload_id)));
    }

    /// Locks the slots after dropping expired ones.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<[u8; 32], Slot>> {
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        slots.retain(|_, s| s.expires > now);
        slots
    }

    /// The `PUT`/`POST /uploads/{token}` route. Needs no bearer token: the URL is the credential.
    pub fn routes(self) -> Router {
        Router::new()
            .route("/uploads/{token}", put(receive).post(receive))
            // The handler enforces each slot's own limit while reading.
            .layer(DefaultBodyLimit::disable())
            .with_state(self)
    }
}

/// Receives one file into the slot named by the URL token.
async fn receive(
    State(uploads): State<Uploads>,
    Path(token): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let result = async {
        let max_bytes = uploads.limit(&token)?;
        let multipart = headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("multipart/"));
        if multipart {
            return Err(UploadError::Multipart);
        }
        let data = to_bytes(body, max_bytes)
            .await
            .map_err(|_| UploadError::TooLarge {
                max_mb: max_bytes / (1024 * 1024),
            })?;
        uploads.fill(&token, data.to_vec())
    }
    .await;
    match result {
        Ok(received) => {
            info!(
                upload_id = %received.upload_id,
                bytes = received.bytes,
                "received upload"
            );
            (StatusCode::CREATED, Json(received)).into_response()
        }
        Err(error) => {
            info!(%error, "rejected upload");
            (
                error.status(),
                Json(serde_json::json!({ "error": error.to_string() })),
            )
                .into_response()
        }
    }
}

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}

fn digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: UserId = UserId(1);
    const BOB: UserId = UserId(2);

    fn token(ticket: &Ticket) -> &str {
        ticket.url.rsplit('/').next().unwrap()
    }

    #[test]
    fn upload_once_then_attach_as_owner_only() {
        let uploads = Uploads::new("https://mcp.example.com/");
        assert_eq!(uploads.host(), "mcp.example.com");
        let ticket = uploads.create(ALICE, "cars.pdf".into(), None, 10).unwrap();
        assert!(ticket.url.starts_with("https://mcp.example.com/uploads/"));
        assert_eq!(
            uploads.get(ALICE, &ticket.upload_id),
            Err(UploadError::NotUploaded(ticket.upload_id.clone()))
        );

        assert_eq!(
            uploads.fill(token(&ticket), vec![]),
            Err(UploadError::Empty)
        );
        assert_eq!(
            uploads.fill(token(&ticket), vec![0; 11]),
            Err(UploadError::TooLarge { max_mb: 0 })
        );
        let received = uploads.fill(token(&ticket), b"%PDF".to_vec()).unwrap();
        assert_eq!(received.upload_id, ticket.upload_id);
        assert_eq!(received.bytes, 4);
        assert_eq!(
            uploads.fill(token(&ticket), b"again".to_vec()),
            Err(UploadError::AlreadyUploaded)
        );
        assert_eq!(
            uploads.fill("nope", b"x".to_vec()),
            Err(UploadError::UnknownToken)
        );

        assert!(matches!(
            uploads.get(BOB, &ticket.upload_id),
            Err(UploadError::UnknownId(_))
        ));
        let file = uploads.get(ALICE, &ticket.upload_id).unwrap();
        assert_eq!(
            (file.filename.as_str(), file.data.as_slice()),
            ("cars.pdf", &b"%PDF"[..])
        );

        uploads.remove(ALICE, std::slice::from_ref(&ticket.upload_id));
        assert!(uploads.get(ALICE, &ticket.upload_id).is_err());
    }

    #[test]
    fn slots_per_user_are_capped() {
        let uploads = Uploads::new("http://127.0.0.1:8787");
        for _ in 0..MAX_SLOTS_PER_USER {
            uploads.create(ALICE, "f".into(), None, 1).unwrap();
        }
        assert_eq!(
            uploads.create(ALICE, "f".into(), None, 1).unwrap_err(),
            UploadError::TooMany
        );
        assert!(uploads.create(BOB, "f".into(), None, 1).is_ok());
        assert_eq!(uploads.host(), "127.0.0.1");
    }
}

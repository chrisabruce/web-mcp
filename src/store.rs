//! Persistent state in SQLite: user keys, saved site logins, and per-site cookie jars.
//!
//! # Schema
//!
//! * `users`: one row per access key. Keys are looked up by SHA-256 hash, and also stored
//!   encrypted so the admin can view them in the UI. The built-in `admin` user has no key; it
//!   is authenticated by the master `WEB_MCP_AUTH_TOKEN` instead (see [`crate::auth`]).
//! * `sites`: per user and site domain, an optional saved login (username, encrypted
//!   password, login URL) and an optional encrypted [`CookieJar`] holding the session.
//!
//! # Secrets at rest
//!
//! User keys, site passwords, and cookie jars are encrypted with ChaCha20-Poly1305 under a key derived
//! from the master token ([`crate::token::derive_key`]); the associated data binds each blob
//! to its user, domain, and purpose, so blobs cannot be swapped between rows. A stolen database
//! file is therefore useless without the master token. Rotating the master token makes stored
//! secrets unreadable; they are then treated as absent and must be re-entered. (User keys keep
//! *working*, since authentication uses the hash, but can no longer be displayed.)
//!
//! # Concurrency
//!
//! `rusqlite` is synchronous, so every operation runs on Tokio's blocking pool via
//! [`Store::call`], holding the connection mutex only for the duration of the query.

use std::{
    path::Path,
    sync::{Arc, Mutex, PoisonError},
};

use chacha20poly1305::{
    ChaCha20Poly1305, Key, KeyInit as _, Nonce,
    aead::{Aead as _, Payload},
};
use rand::RngCore as _;
use rusqlite::{Connection, OptionalExtension as _, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tracing::{info, warn};

use crate::{
    config::Secret,
    cookies::{CookieJar, domain_matches},
    token::{derive_key, now},
};

/// Name of the built-in administrator, authenticated by the master token.
pub const ADMIN_NAME: &str = "admin";

/// Prefix of generated user keys, so they are recognisable in configs and logs.
const KEY_PREFIX: &str = "wmk_";

/// Domain-separation label for the storage encryption key.
const STORAGE_KEY_CONTEXT: &[u8] = b"web-mcp storage encryption key v1";

/// `users.last_used_at` is only rewritten when older than this, to avoid a write per request.
const LAST_USED_RESOLUTION_SECS: u64 = 60;

/// Schema migrations; entry `n` upgrades `user_version` `n` to `n + 1`.
const MIGRATIONS: &[&str] = &[
    SCHEMA_V1,
    "ALTER TABLE users ADD COLUMN key_enc BLOB;",
    "ALTER TABLE users ADD COLUMN can_email INTEGER NOT NULL DEFAULT 0;",
];

const SCHEMA_V1: &str = "
CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY,
    name         TEXT    NOT NULL UNIQUE,
    key_hash     BLOB    UNIQUE,
    key_prefix   TEXT,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER,
    revoked_at   INTEGER
);
CREATE TABLE IF NOT EXISTS sites (
    user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    domain         TEXT    NOT NULL,
    login_url      TEXT,
    username       TEXT,
    password       BLOB,
    cookies        BLOB,
    cookies_source TEXT,
    updated_at     INTEGER NOT NULL,
    PRIMARY KEY (user_id, domain)
);
";

/// Database id of a user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserId(pub i64);

impl std::fmt::Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// A user and its key metadata (never the key itself).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    /// Database id.
    pub id: UserId,
    /// Display name, unique.
    pub name: String,
    /// First characters of the key, for recognising it in the UI; `None` for the admin.
    pub key_prefix: Option<String>,
    /// Creation time (Unix seconds).
    pub created_at: u64,
    /// Last authenticated use (Unix seconds, ~1 minute resolution).
    pub last_used_at: Option<u64>,
    /// Revocation time, if revoked.
    pub revoked_at: Option<u64>,
    /// Whether the admin allowed this user to send email (the admin always may).
    pub can_email: bool,
}

impl User {
    /// Whether this is the built-in administrator.
    pub fn is_admin(&self) -> bool {
        self.key_prefix.is_none()
    }
}

/// A user row plus its key, for the admin's user list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserListing {
    /// The user.
    pub user: User,
    /// Its key, as far as it can be shown.
    pub key: KeyView,
}

/// Whether a user's key can be displayed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyView {
    /// The built-in admin, whose key is `WEB_MCP_AUTH_TOKEN`.
    Master,
    /// The decrypted key.
    Visible(String),
    /// Created before keys were stored encrypted; regenerate it to view.
    NotStored,
    /// Stored, but encrypted under a previous `WEB_MCP_AUTH_TOKEN`.
    Unreadable,
}

/// How a site's cookie jar was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookieSource {
    /// Captured by an automatic form login.
    Login,
    /// Pasted by the user from their browser.
    Import,
}

impl CookieSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Import => "import",
        }
    }
}

/// A saved site, without secrets, for listings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SiteSummary {
    /// Site domain the login and cookies apply to (including subdomains).
    pub domain: String,
    /// Login page URL, if one was saved.
    pub login_url: Option<String>,
    /// Saved username, if any.
    pub username: Option<String>,
    /// Whether a password is saved.
    pub has_password: bool,
    /// Number of session cookies held.
    pub cookie_count: usize,
    /// `"login"` or `"import"`, if cookies are held.
    pub cookies_source: Option<String>,
    /// Last change (Unix seconds).
    pub updated_at: u64,
}

/// Saved username and password for a site.
#[derive(Clone)]
pub struct Credentials {
    /// Username or email.
    pub username: String,
    /// Plain-text password (decrypted in memory only when logging in).
    pub password: String,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .field("password", &"***")
            .finish()
    }
}

/// Everything saved for the site that covers a given host.
#[derive(Debug, Clone)]
pub struct SiteRecord {
    /// The saved domain that matched.
    pub domain: String,
    /// Saved login page URL.
    pub login_url: Option<String>,
    /// Saved credentials, if any (and decryptable).
    pub credentials: Option<Credentials>,
    /// Saved session cookies, if any (and decryptable).
    pub jar: Option<CookieJar>,
}

/// Store failures.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// SQLite error.
    #[error("database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// The data directory could not be created.
    #[error("cannot create data directory: {0}")]
    Io(#[from] std::io::Error),
    /// The blocking task panicked.
    #[error("database task failed: {0}")]
    Task(#[from] tokio::task::JoinError),
    /// A user with that name exists.
    #[error("a user named `{0}` already exists")]
    NameTaken(String),
    /// The user name is empty, too long, reserved, or has odd characters.
    #[error("user names must be 1-64 letters, digits, spaces, `.`, `_`, `-`, `@`, and not `admin`")]
    InvalidName,
    /// No active user has that id.
    #[error("no active user with that id")]
    UnknownUser,
    /// The built-in admin cannot be revoked.
    #[error("the built-in admin cannot be revoked; rotate WEB_MCP_AUTH_TOKEN instead")]
    CannotRevokeAdmin,
}

/// Handle to the database; cheap to clone.
#[derive(Clone)]
pub struct Store {
    conn: Arc<Mutex<Connection>>,
    cipher: Arc<Cipher>,
    admin: UserId,
}

impl Store {
    /// Opens (creating if needed) `web-mcp.db` in `data_dir` and applies migrations.
    ///
    /// # Errors
    ///
    /// Fails if the directory or database cannot be created or migrated.
    pub fn open(data_dir: &Path, secret: &Secret) -> Result<Self, StoreError> {
        std::fs::create_dir_all(data_dir)?;
        let path = data_dir.join("web-mcp.db");
        let conn = Connection::open(&path)?;
        let admin = init(&conn)?;
        info!(path = %path.display(), "opened database");
        Ok(Self::from_connection(conn, secret, admin))
    }

    /// An in-memory store, for tests.
    #[cfg(test)]
    pub fn in_memory(secret: &Secret) -> Self {
        let conn = Connection::open_in_memory().expect("in-memory database");
        let admin = init(&conn).expect("schema");
        Self::from_connection(conn, secret, admin)
    }

    fn from_connection(conn: Connection, secret: &Secret, admin: UserId) -> Self {
        Self {
            conn: Arc::new(Mutex::new(conn)),
            cipher: Arc::new(Cipher::new(secret)),
            admin,
        }
    }

    /// Id of the built-in admin user.
    pub fn admin_id(&self) -> UserId {
        self.admin
    }

    /// Runs `f` against the connection on the blocking pool.
    async fn call<T, F>(&self, f: F) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(&Connection, &Cipher) -> Result<T, StoreError> + Send + 'static,
    {
        let (conn, cipher) = (Arc::clone(&self.conn), Arc::clone(&self.cipher));
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap_or_else(PoisonError::into_inner);
            f(&conn, &cipher)
        })
        .await?
    }

    // ---- users ---------------------------------------------------------------------------

    /// Creates a user and returns it with its newly generated key, shown to the admin once.
    pub async fn create_user(&self, name: &str) -> Result<(User, String), StoreError> {
        let name = name.trim().to_owned();
        if !valid_user_name(&name) {
            return Err(StoreError::InvalidName);
        }
        let key = generate_key();
        let (hash, prefix) = (hash_key(&key), key[..KEY_PREFIX.len() + 6].to_owned());
        let stored_key = key.clone();
        self.call(move |conn, cipher| {
            let created = now();
            let inserted = conn.execute(
                "INSERT INTO users (name, key_hash, key_prefix, created_at) VALUES (?1, ?2, ?3, ?4)",
                params![name, hash, prefix, created],
            );
            match inserted {
                Err(rusqlite::Error::SqliteFailure(e, _))
                    if e.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    return Err(StoreError::NameTaken(name));
                }
                other => other?,
            };
            let id = UserId(conn.last_insert_rowid());
            store_key(conn, cipher, id, &stored_key)?;
            let user = User {
                id,
                name,
                key_prefix: Some(prefix),
                created_at: created,
                last_used_at: None,
                revoked_at: None,
                can_email: false,
            };
            Ok((user, key))
        })
        .await
    }

    /// All users with their (decrypted) keys, admin first, then by creation. Admin only.
    pub async fn list_users(&self) -> Result<Vec<UserListing>, StoreError> {
        self.call(|conn, cipher| {
            let mut stmt = conn.prepare(&format!(
                "{USER_COLUMNS}, key_enc FROM users ORDER BY key_prefix IS NOT NULL, created_at"
            ))?;
            let rows = stmt.query_map([], |row| {
                Ok((user_from_row(row)?, row.get::<_, Option<Vec<u8>>>(7)?))
            })?;
            let mut listings = Vec::new();
            for row in rows {
                let (user, sealed) = row?;
                let key = match (user.is_admin(), sealed) {
                    (true, _) => KeyView::Master,
                    (false, None) => KeyView::NotStored,
                    (false, Some(blob)) => cipher
                        .open_text(&blob, Purpose::UserKey, user.id, "")
                        .map_or(KeyView::Unreadable, KeyView::Visible),
                };
                listings.push(UserListing { user, key });
            }
            Ok(listings)
        })
        .await
    }

    /// Replaces an active user's key with a new one (the old key stops working at once;
    /// existing OAuth sign-ins continue). Returns the user and the new key.
    pub async fn regenerate_key(&self, id: UserId) -> Result<(User, String), StoreError> {
        if id == self.admin {
            return Err(StoreError::CannotRevokeAdmin);
        }
        let key = generate_key();
        let (hash, prefix) = (hash_key(&key), key[..KEY_PREFIX.len() + 6].to_owned());
        let stored_key = key.clone();
        self.call(move |conn, cipher| {
            let changed = conn.execute(
                "UPDATE users SET key_hash = ?1, key_prefix = ?2 WHERE id = ?3 AND revoked_at IS NULL",
                params![hash, prefix, id.0],
            )?;
            if changed == 0 {
                return Err(StoreError::UnknownUser);
            }
            store_key(conn, cipher, id, &stored_key)?;
            let user = conn.query_row(&format!("{USER_COLUMNS} FROM users WHERE id = ?1"), params![id.0], user_from_row)?;
            Ok((user, stored_key))
        })
        .await
    }

    /// Revokes a user's key. Its OAuth sessions stop working on their next request.
    pub async fn revoke_user(&self, id: UserId) -> Result<(), StoreError> {
        if id == self.admin {
            return Err(StoreError::CannotRevokeAdmin);
        }
        self.call(move |conn, _| {
            conn.execute(
                "UPDATE users SET revoked_at = ?1 WHERE id = ?2 AND revoked_at IS NULL",
                params![now(), id.0],
            )?;
            Ok(())
        })
        .await
    }

    /// Allows or forbids a user to send email. The admin always may.
    pub async fn set_can_email(&self, id: UserId, allowed: bool) -> Result<(), StoreError> {
        if id == self.admin {
            return Ok(());
        }
        self.call(move |conn, _| {
            match conn.execute(
                "UPDATE users SET can_email = ?1 WHERE id = ?2",
                params![allowed, id.0],
            )? {
                0 => Err(StoreError::UnknownUser),
                _ => Ok(()),
            }
        })
        .await
    }

    /// The active (non-revoked) user owning `key`, recording the use.
    pub async fn user_by_key(&self, key: &str) -> Result<Option<User>, StoreError> {
        if !key.starts_with(KEY_PREFIX) {
            return Ok(None);
        }
        let hash = hash_key(key);
        self.call(move |conn, _| {
            let user = conn
                .query_row(
                    &format!(
                        "{USER_COLUMNS} FROM users WHERE key_hash = ?1 AND revoked_at IS NULL"
                    ),
                    params![hash],
                    user_from_row,
                )
                .optional()?;
            if let Some(user) = &user {
                touch(conn, user.id)?;
            }
            Ok(user)
        })
        .await
    }

    /// The user with `id` if it exists and is not revoked, recording the use.
    pub async fn active_user(&self, id: UserId) -> Result<Option<User>, StoreError> {
        self.call(move |conn, _| {
            let user = conn
                .query_row(
                    &format!("{USER_COLUMNS} FROM users WHERE id = ?1 AND revoked_at IS NULL"),
                    params![id.0],
                    user_from_row,
                )
                .optional()?;
            if user.is_some() {
                touch(conn, id)?;
            }
            Ok(user)
        })
        .await
    }

    // ---- sites ---------------------------------------------------------------------------

    /// A user's saved sites, without secrets.
    pub async fn sites(&self, uid: UserId) -> Result<Vec<SiteSummary>, StoreError> {
        self.call(move |conn, cipher| {
            let mut stmt = conn.prepare(
                "SELECT domain, login_url, username, password IS NOT NULL, cookies, cookies_source, updated_at
                 FROM sites WHERE user_id = ?1 ORDER BY domain",
            )?;
            let rows = stmt.query_map(params![uid.0], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            })?;
            let mut sites = Vec::new();
            for row in rows {
                let (domain, login_url, username, has_password, cookies, cookies_source, updated_at) = row?;
                let cookie_count = cookies
                    .and_then(|blob| cipher.open_jar(&blob, uid, &domain))
                    .map_or(0, |jar| jar.len());
                sites.push(SiteSummary {
                    domain,
                    login_url,
                    username,
                    has_password,
                    cookie_count,
                    cookies_source,
                    updated_at,
                });
            }
            Ok(sites)
        })
        .await
    }

    /// The saved site covering `host` (longest matching domain), with secrets decrypted.
    pub async fn site_for_host(
        &self,
        uid: UserId,
        host: &str,
    ) -> Result<Option<SiteRecord>, StoreError> {
        let host = host.to_ascii_lowercase();
        self.call(move |conn, cipher| {
            let mut stmt = conn.prepare(
                "SELECT domain, login_url, username, password, cookies FROM sites WHERE user_id = ?1",
            )?;
            let rows = stmt.query_map(params![uid.0], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                ))
            })?;
            let best = rows
                .filter_map(Result::ok)
                .filter(|(domain, ..)| domain_matches(domain, &host))
                .max_by_key(|(domain, ..)| domain.len());
            Ok(best.map(|(domain, login_url, username, password, cookies)| {
                let password = password.and_then(|blob| cipher.open_text(&blob, Purpose::Password, uid, &domain));
                let credentials = username
                    .zip(password)
                    .map(|(username, password)| Credentials { username, password });
                let jar = cookies.and_then(|blob| cipher.open_jar(&blob, uid, &domain));
                SiteRecord { domain, login_url, credentials, jar }
            }))
        })
        .await
    }

    /// Saves (or replaces) a login for `domain`. A `None` password keeps the existing one.
    pub async fn save_credentials(
        &self,
        uid: UserId,
        domain: &str,
        login_url: Option<String>,
        username: &str,
        password: Option<&str>,
    ) -> Result<(), StoreError> {
        let (domain, username) = (domain.to_owned(), username.to_owned());
        let password = password.map(str::to_owned);
        self.call(move |conn, cipher| {
            let sealed =
                password.map(|p| cipher.seal(p.as_bytes(), Purpose::Password, uid, &domain));
            conn.execute(
                "INSERT INTO sites (user_id, domain, login_url, username, password, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT (user_id, domain) DO UPDATE SET
                   login_url = excluded.login_url,
                   username = excluded.username,
                   password = COALESCE(excluded.password, sites.password),
                   updated_at = excluded.updated_at",
                params![uid.0, domain, login_url, username, sealed, now()],
            )?;
            Ok(())
        })
        .await
    }

    /// Saves (or replaces) the session cookies for `domain`.
    pub async fn save_cookies(
        &self,
        uid: UserId,
        domain: &str,
        jar: &CookieJar,
        source: CookieSource,
    ) -> Result<(), StoreError> {
        let domain = domain.to_owned();
        let json = serde_json::to_vec(jar).expect("cookie jar serializes");
        self.call(move |conn, cipher| {
            let sealed = cipher.seal(&json, Purpose::Cookies, uid, &domain);
            conn.execute(
                "INSERT INTO sites (user_id, domain, cookies, cookies_source, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (user_id, domain) DO UPDATE SET
                   cookies = excluded.cookies,
                   cookies_source = excluded.cookies_source,
                   updated_at = excluded.updated_at",
                params![uid.0, domain, sealed, source.as_str(), now()],
            )?;
            Ok(())
        })
        .await
    }

    /// Forgets the session cookies for `domain`, keeping any saved login.
    pub async fn clear_cookies(&self, uid: UserId, domain: &str) -> Result<(), StoreError> {
        let domain = domain.to_owned();
        self.call(move |conn, _| {
            conn.execute(
                "UPDATE sites SET cookies = NULL, cookies_source = NULL, updated_at = ?3
                 WHERE user_id = ?1 AND domain = ?2",
                params![uid.0, domain, now()],
            )?;
            Ok(())
        })
        .await
    }

    /// Deletes everything saved for `domain`.
    pub async fn delete_site(&self, uid: UserId, domain: &str) -> Result<(), StoreError> {
        let domain = domain.to_owned();
        self.call(move |conn, _| {
            conn.execute(
                "DELETE FROM sites WHERE user_id = ?1 AND domain = ?2",
                params![uid.0, domain],
            )?;
            Ok(())
        })
        .await
    }
}

const USER_COLUMNS: &str =
    "SELECT id, name, key_prefix, created_at, last_used_at, revoked_at, can_email";

fn user_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<User> {
    Ok(User {
        id: UserId(row.get(0)?),
        name: row.get(1)?,
        key_prefix: row.get(2)?,
        created_at: row.get(3)?,
        last_used_at: row.get(4)?,
        revoked_at: row.get(5)?,
        can_email: row.get(6)?,
    })
}

/// Configures the connection, migrates the schema, and returns the admin's id.
fn init(conn: &Connection) -> Result<UserId, StoreError> {
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "busy_timeout", 5_000)?;
    // WAL is unavailable for in-memory databases; ignore the result there.
    let _ = conn.pragma_update(None, "journal_mode", "WAL");

    let version: usize = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    for (index, migration) in MIGRATIONS.iter().enumerate().skip(version) {
        conn.execute_batch(&format!(
            "BEGIN; {migration} PRAGMA user_version = {}; COMMIT;",
            index + 1
        ))?;
        info!(version = index + 1, "migrated database schema");
    }
    conn.execute(
        "INSERT OR IGNORE INTO users (name, key_hash, key_prefix, created_at) VALUES (?1, NULL, NULL, ?2)",
        params![ADMIN_NAME, now()],
    )?;
    let id = conn.query_row(
        "SELECT id FROM users WHERE name = ?1",
        params![ADMIN_NAME],
        |row| row.get(0),
    )?;
    Ok(UserId(id))
}

/// Stores `key` encrypted for user `id`, so the admin can view it later.
fn store_key(conn: &Connection, cipher: &Cipher, id: UserId, key: &str) -> rusqlite::Result<()> {
    let sealed = cipher.seal(key.as_bytes(), Purpose::UserKey, id, "");
    conn.execute(
        "UPDATE users SET key_enc = ?1 WHERE id = ?2",
        params![sealed, id.0],
    )?;
    Ok(())
}

/// Records a use of `id`, at most once per [`LAST_USED_RESOLUTION_SECS`].
fn touch(conn: &Connection, id: UserId) -> rusqlite::Result<()> {
    let now = now();
    conn.execute(
        "UPDATE users SET last_used_at = ?1 WHERE id = ?2 AND (last_used_at IS NULL OR last_used_at < ?3)",
        params![now, id.0, now - LAST_USED_RESOLUTION_SECS],
    )?;
    Ok(())
}

fn valid_user_name(name: &str) -> bool {
    (1..=64).contains(&name.chars().count())
        && !name.eq_ignore_ascii_case(ADMIN_NAME)
        && name
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, ' ' | '.' | '_' | '-' | '@'))
}

/// A new random key: `wmk_` followed by 64 hex characters (256 bits).
fn generate_key() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("{KEY_PREFIX}{hex}")
}

fn hash_key(key: &str) -> Vec<u8> {
    Sha256::digest(key.as_bytes()).to_vec()
}

/// What an encrypted blob holds; part of its associated data.
#[derive(Debug, Clone, Copy)]
enum Purpose {
    Password,
    Cookies,
    UserKey,
}

/// Authenticated encryption for secrets at rest.
struct Cipher(ChaCha20Poly1305);

impl Cipher {
    fn new(secret: &Secret) -> Self {
        let key = derive_key(secret.expose(), STORAGE_KEY_CONTEXT);
        Self(ChaCha20Poly1305::new(Key::from_slice(&key)))
    }

    fn aad(purpose: Purpose, uid: UserId, domain: &str) -> Vec<u8> {
        format!("{purpose:?}:{uid}:{domain}").into_bytes()
    }

    /// Encrypts `plain` as `nonce || ciphertext`.
    fn seal(&self, plain: &[u8], purpose: Purpose, uid: UserId, domain: &str) -> Vec<u8> {
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let aad = Self::aad(purpose, uid, domain);
        let sealed = self
            .0
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plain,
                    aad: &aad,
                },
            )
            .expect("ChaCha20-Poly1305 encryption cannot fail");
        [nonce.as_slice(), &sealed].concat()
    }

    /// Decrypts a blob from [`seal`](Self::seal); `None` (with a warning) if it fails, e.g.
    /// after the master token was rotated.
    fn open(&self, blob: &[u8], purpose: Purpose, uid: UserId, domain: &str) -> Option<Vec<u8>> {
        let (nonce, sealed) = blob.split_at_checked(12)?;
        let aad = Self::aad(purpose, uid, domain);
        let plain = self
            .0
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: sealed,
                    aad: &aad,
                },
            )
            .ok();
        if plain.is_none() {
            warn!(%uid, domain, ?purpose, "cannot decrypt stored secret (was WEB_MCP_AUTH_TOKEN rotated?)");
        }
        plain
    }

    fn open_text(
        &self,
        blob: &[u8],
        purpose: Purpose,
        uid: UserId,
        domain: &str,
    ) -> Option<String> {
        String::from_utf8(self.open(blob, purpose, uid, domain)?).ok()
    }

    fn open_jar(&self, blob: &[u8], uid: UserId, domain: &str) -> Option<CookieJar> {
        serde_json::from_slice(&self.open(blob, Purpose::Cookies, uid, domain)?).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(s: &str) -> Secret {
        format!("{s:0<32}").parse().unwrap()
    }

    #[tokio::test]
    async fn user_lifecycle() {
        let store = Store::in_memory(&secret("master"));
        let (user, key) = store.create_user("alice").await.unwrap();
        assert!(key.starts_with("wmk_") && key.len() == 68);
        assert_eq!(
            store.user_by_key(&key).await.unwrap().map(|u| u.id),
            Some(user.id)
        );
        assert_eq!(store.user_by_key("wmk_nope").await.unwrap(), None);
        assert!(matches!(
            store.create_user("alice").await,
            Err(StoreError::NameTaken(_))
        ));
        assert!(matches!(
            store.create_user("Admin").await,
            Err(StoreError::InvalidName)
        ));

        let listed = store.list_users().await.unwrap();
        assert_eq!(listed[0].key, KeyView::Master);
        assert_eq!(listed[1].key, KeyView::Visible(key.clone()));
        let users: Vec<User> = listed.into_iter().map(|l| l.user).collect();
        assert_eq!(
            users.iter().map(|u| u.name.as_str()).collect::<Vec<_>>(),
            ["admin", "alice"]
        );
        assert!(users[0].is_admin() && !users[1].is_admin());

        store.revoke_user(user.id).await.unwrap();
        assert_eq!(store.user_by_key(&key).await.unwrap(), None);
        assert_eq!(store.active_user(user.id).await.unwrap(), None);
        assert!(matches!(
            store.revoke_user(store.admin_id()).await,
            Err(StoreError::CannotRevokeAdmin)
        ));
    }

    #[tokio::test]
    async fn keys_are_viewable_and_regenerable() {
        let store = Store::in_memory(&secret("master"));
        let (alice, old_key) = store.create_user("alice").await.unwrap();
        let (_, new_key) = store.regenerate_key(alice.id).await.unwrap();
        assert_ne!(old_key, new_key);
        assert_eq!(store.user_by_key(&old_key).await.unwrap(), None);
        assert_eq!(
            store.user_by_key(&new_key).await.unwrap().map(|u| u.id),
            Some(alice.id)
        );
        assert_eq!(
            store.list_users().await.unwrap()[1].key,
            KeyView::Visible(new_key.clone())
        );
        assert!(matches!(
            store.regenerate_key(store.admin_id()).await,
            Err(StoreError::CannotRevokeAdmin)
        ));

        // With a different master token the key still authenticates but cannot be shown.
        let rotated = Store::from_connection(
            Arc::try_unwrap(store.conn)
                .ok()
                .unwrap()
                .into_inner()
                .unwrap(),
            &secret("rotated"),
            store.admin,
        );
        assert_eq!(
            rotated.list_users().await.unwrap()[1].key,
            KeyView::Unreadable
        );
        assert!(rotated.user_by_key(&new_key).await.unwrap().is_some());

        rotated.revoke_user(alice.id).await.unwrap();
        assert!(matches!(
            rotated.regenerate_key(alice.id).await,
            Err(StoreError::UnknownUser)
        ));
    }

    #[test]
    fn migrates_v1_databases_and_marks_legacy_keys_not_stored() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA_V1).unwrap();
        conn.pragma_update(None, "user_version", 1).unwrap();
        conn.execute(
            "INSERT INTO users (name, key_hash, key_prefix, created_at) VALUES ('old', x'00', 'wmk_abcdef', 1)",
            [],
        )
        .unwrap();
        let admin = init(&conn).unwrap();
        let store = Store::from_connection(conn, &secret("master"), admin);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let listed = rt.block_on(store.list_users()).unwrap();
        assert_eq!(
            listed.iter().map(|l| &l.key).collect::<Vec<_>>(),
            [&KeyView::Master, &KeyView::NotStored]
        );
    }

    #[tokio::test]
    async fn sites_are_private_encrypted_and_matched_by_domain() {
        let store = Store::in_memory(&secret("master"));
        let (alice, _) = store.create_user("alice").await.unwrap();
        let (bob, _) = store.create_user("bob").await.unwrap();

        store
            .save_credentials(
                alice.id,
                "craigslist.org",
                Some("https://accounts.craigslist.org/login".into()),
                "a@x.com",
                Some("pw1"),
            )
            .await
            .unwrap();
        let jar = CookieJar::from_pairs([("cl_session".into(), "s".into())]);
        store
            .save_cookies(alice.id, "craigslist.org", &jar, CookieSource::Login)
            .await
            .unwrap();

        let record = store
            .site_for_host(alice.id, "accounts.craigslist.org")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.domain, "craigslist.org");
        assert_eq!(record.credentials.unwrap().password, "pw1");
        assert_eq!(record.jar, Some(jar));
        assert!(
            store
                .site_for_host(bob.id, "craigslist.org")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .site_for_host(alice.id, "example.com")
                .await
                .unwrap()
                .is_none()
        );

        // Updating without a password keeps the old one.
        store
            .save_credentials(alice.id, "craigslist.org", None, "new@x.com", None)
            .await
            .unwrap();
        let creds = store
            .site_for_host(alice.id, "craigslist.org")
            .await
            .unwrap()
            .unwrap()
            .credentials
            .unwrap();
        assert_eq!(
            (creds.username.as_str(), creds.password.as_str()),
            ("new@x.com", "pw1")
        );

        let summary = &store.sites(alice.id).await.unwrap()[0];
        assert_eq!((summary.cookie_count, summary.has_password), (1, true));

        store
            .clear_cookies(alice.id, "craigslist.org")
            .await
            .unwrap();
        assert!(
            store
                .site_for_host(alice.id, "craigslist.org")
                .await
                .unwrap()
                .unwrap()
                .jar
                .is_none()
        );
        store.delete_site(alice.id, "craigslist.org").await.unwrap();
        assert!(store.sites(alice.id).await.unwrap().is_empty());
    }

    #[test]
    fn ciphertext_is_bound_to_key_and_row() {
        let cipher = Cipher::new(&secret("master"));
        let blob = cipher.seal(b"pw", Purpose::Password, UserId(1), "a.com");
        assert_eq!(
            cipher
                .open(&blob, Purpose::Password, UserId(1), "a.com")
                .as_deref(),
            Some(&b"pw"[..])
        );
        assert!(
            cipher
                .open(&blob, Purpose::Password, UserId(2), "a.com")
                .is_none()
        );
        assert!(
            cipher
                .open(&blob, Purpose::Cookies, UserId(1), "a.com")
                .is_none()
        );
        assert!(
            Cipher::new(&secret("rotated"))
                .open(&blob, Purpose::Password, UserId(1), "a.com")
                .is_none()
        );
    }
}

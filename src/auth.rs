//! Who is calling: resolving credentials to a [`Principal`].
//!
//! Three kinds of credential identify a user:
//!
//! | Credential | Used by | Resolves to |
//! |---|---|---|
//! | `WEB_MCP_AUTH_TOKEN` (master) | the operator | the built-in `admin` user |
//! | a user key (`wmk_…`) created in the admin UI | Claude Code bearer header, OAuth sign-in, admin-UI sign-in | that user |
//! | an OAuth access token (signed, carries the user id) | Claude Desktop / claude.ai | that user, if not revoked |
//!
//! [`require_auth`] is the `/mcp` middleware: it resolves the bearer token and stores the
//! [`Principal`] in the request extensions, where MCP tools read it (rmcp forwards the HTTP
//! request parts to tool handlers). Revoking a user takes effect immediately for every
//! credential kind, because each request re-checks the user in the [`Store`].

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use tracing::{error, warn};

use crate::{
    config::Secret,
    store::{Store, User, UserId},
    token::{Claims, Signer},
};

/// An authenticated caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// The user's database id; scopes saved site logins and cookies.
    pub id: UserId,
    /// Display name, for logs and the UI.
    pub name: String,
    /// Whether the caller may manage users.
    pub is_admin: bool,
    /// Whether the caller may send email (always true for the admin).
    pub can_email: bool,
}

impl From<User> for Principal {
    fn from(user: User) -> Self {
        Self {
            is_admin: user.is_admin(),
            can_email: user.is_admin() || user.can_email,
            id: user.id,
            name: user.name,
        }
    }
}

/// Resolves credentials to principals. Cheap to clone.
#[derive(Clone)]
pub struct Authenticator {
    master: Secret,
    store: Store,
    signer: Signer,
}

impl Authenticator {
    /// Creates an authenticator for the given master token and store.
    pub fn new(master: Secret, store: Store) -> Self {
        let signer = Signer::new(master.expose());
        Self {
            master,
            store,
            signer,
        }
    }

    /// Signs and verifies OAuth tokens and UI sessions.
    pub fn signer(&self) -> &Signer {
        &self.signer
    }

    /// The backing store.
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// The built-in admin, used where there is no HTTP authentication (stdio mode).
    pub fn admin(&self) -> Principal {
        Principal {
            id: self.store.admin_id(),
            name: crate::store::ADMIN_NAME.to_owned(),
            is_admin: true,
            can_email: true,
        }
    }

    /// Resolves a master token or user key (as typed into a sign-in form or sent as bearer).
    pub async fn by_key(&self, key: &str) -> Option<Principal> {
        let key = key.trim();
        if self.master.matches(key) {
            return Some(self.admin());
        }
        match self.store.user_by_key(key).await {
            Ok(user) => user.map(Principal::from),
            Err(err) => {
                error!(%err, "user lookup failed");
                None
            }
        }
    }

    /// Resolves a user id from a signed token, if the user still exists and is not revoked.
    pub async fn by_id(&self, id: UserId) -> Option<Principal> {
        match self.store.active_user(id).await {
            Ok(user) => user.map(Principal::from),
            Err(err) => {
                error!(%err, "user lookup failed");
                None
            }
        }
    }

    /// Resolves an `Authorization: Bearer` value: a key or an OAuth access token.
    pub async fn by_bearer(&self, bearer: &str) -> Option<Principal> {
        if let Some(principal) = self.by_key(bearer).await {
            return Some(principal);
        }
        match self.signer.verify(bearer) {
            Some(Claims::Access { uid, .. }) => self.by_id(uid).await,
            _ => None,
        }
    }
}

/// State for [`require_auth`].
pub struct McpAuth {
    /// Credential resolver.
    pub auth: Authenticator,
    /// OAuth protected-resource metadata URL, advertised on 401 when OAuth is enabled.
    pub resource_metadata: Option<String>,
}

/// `/mcp` middleware: rejects requests without a valid bearer credential and attaches the
/// caller's [`Principal`] to the request extensions.
///
/// With OAuth enabled the 401 advertises the resource metadata URL, which is how MCP clients
/// discover where to sign in.
pub async fn require_auth(
    State(state): State<Arc<McpAuth>>,
    mut request: Request,
    next: Next,
) -> Response {
    let bearer = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(|value| value.trim().to_owned());
    let principal = match bearer {
        Some(bearer) => state.auth.by_bearer(&bearer).await,
        None => None,
    };
    if let Some(principal) = principal {
        request.extensions_mut().insert(principal);
        return next.run(request).await;
    }
    if request.headers().contains_key(header::AUTHORIZATION) {
        warn!("rejected /mcp request with invalid or revoked credentials");
    }
    let challenge = match &state.resource_metadata {
        Some(url) => format!(r#"Bearer resource_metadata="{url}""#),
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
    use crate::token::expires_in;
    use std::time::Duration;

    const MASTER: &str = "0123456789abcdef0123456789abcdef";

    #[tokio::test]
    async fn resolves_all_credential_kinds_and_honours_revocation() {
        let master: Secret = MASTER.parse().unwrap();
        let auth = Authenticator::new(master.clone(), Store::in_memory(&master));
        let (alice, key) = auth.store().create_user("alice").await.unwrap();

        assert!(auth.by_bearer(MASTER).await.unwrap().is_admin);
        let by_key = auth.by_bearer(&key).await.unwrap();
        assert_eq!((by_key.id, by_key.is_admin), (alice.id, false));

        let access = auth.signer().sign(&Claims::Access {
            uid: alice.id,
            exp: expires_in(Duration::from_secs(60)),
        });
        assert_eq!(auth.by_bearer(&access).await.map(|p| p.id), Some(alice.id));
        assert!(auth.by_bearer("garbage").await.is_none());

        auth.store().revoke_user(alice.id).await.unwrap();
        assert!(auth.by_bearer(&key).await.is_none());
        assert!(
            auth.by_bearer(&access).await.is_none(),
            "revocation must cut off OAuth tokens"
        );
    }
}

//! Stateless, HMAC-signed tokens for every artifact of the OAuth flow.
//!
//! The server keeps no OAuth state: client registrations, pending authorization requests,
//! authorization codes, and access/refresh tokens are all [`Claims`] serialized to JSON,
//! base64url-encoded, and signed with HMAC-SHA256:
//!
//! ```text
//!   base64url(json(claims)) "." base64url(hmac_sha256(key, payload))
//! ```
//!
//! This survives restarts and works on a read-only filesystem. The signing key is derived
//! from the server's auth token ([`Signer::new`]), so rotating that token revokes every
//! client registration and session at once. Each claim kind is a distinct enum variant, so
//! a token of one kind can never be accepted where another is expected.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit as _, Mac as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Domain-separation label for deriving the signing key from the auth token.
const KEY_CONTEXT: &[u8] = b"web-mcp oauth signing key v1";

/// Everything the server signs. The `typ` tag keeps token kinds from being confused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "typ", rename_all = "snake_case")]
pub enum Claims {
    /// A dynamically registered client; the signed blob *is* the `client_id`.
    Client {
        /// Redirect URIs the client registered; `/authorize` only redirects to these.
        redirect_uris: Vec<String>,
        /// Human-readable name shown on the login page.
        name: Option<String>,
    },
    /// A validated `/authorize` request, carried through the login form.
    Request {
        /// The client asking for access.
        client_id: String,
        /// Where to send the code (already checked against the registration).
        redirect_uri: String,
        /// PKCE S256 challenge.
        code_challenge: String,
        /// Opaque client state echoed back on redirect.
        state: Option<String>,
        /// Expiry (Unix seconds).
        exp: u64,
    },
    /// A one-time authorization code.
    Code {
        /// Client the code was issued to.
        client_id: String,
        /// Redirect URI that must be repeated at the token endpoint.
        redirect_uri: String,
        /// PKCE S256 challenge the verifier must match.
        code_challenge: String,
        /// Expiry (Unix seconds).
        exp: u64,
    },
    /// A bearer token accepted by `/mcp`.
    Access {
        /// Expiry (Unix seconds).
        exp: u64,
    },
    /// A token exchangeable for a fresh access/refresh pair.
    Refresh {
        /// Client the token was issued to.
        client_id: String,
        /// Expiry (Unix seconds).
        exp: u64,
    },
}

impl Claims {
    /// Whether the claims carry an expiry that has passed. Client registrations never expire.
    pub fn is_expired(&self) -> bool {
        match self {
            Self::Client { .. } => false,
            Self::Request { exp, .. }
            | Self::Code { exp, .. }
            | Self::Access { exp }
            | Self::Refresh { exp, .. } => *exp <= now(),
        }
    }
}

/// Signs and verifies [`Claims`].
#[derive(Clone)]
pub struct Signer {
    key: [u8; 32],
}

impl Signer {
    /// Derives the signing key from the server's auth `secret`.
    pub fn new(secret: &str) -> Self {
        let mut mac =
            HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
        mac.update(KEY_CONTEXT);
        Self {
            key: mac.finalize().into_bytes().into(),
        }
    }

    /// Serializes and signs `claims`.
    pub fn sign(&self, claims: &Claims) -> String {
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("claims serialize"));
        let signature = URL_SAFE_NO_PAD.encode(self.mac(&payload).finalize().into_bytes());
        format!("{payload}.{signature}")
    }

    /// Returns the claims if `token` carries a valid signature and has not expired.
    pub fn verify(&self, token: &str) -> Option<Claims> {
        let (payload, signature) = token.split_once('.')?;
        let signature = URL_SAFE_NO_PAD.decode(signature).ok()?;
        self.mac(payload).verify_slice(&signature).ok()?;
        let claims: Claims = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
        (!claims.is_expired()).then_some(claims)
    }

    fn mac(&self, payload: &str) -> HmacSha256 {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("HMAC accepts any key length");
        mac.update(payload.as_bytes());
        mac
    }
}

/// Seconds since the Unix epoch.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The Unix time `ttl` from now.
pub fn expires_in(ttl: Duration) -> u64 {
    now() + ttl.as_secs()
}

/// Checks a PKCE `code_verifier` against an S256 `code_challenge` (RFC 7636 §4.6).
pub fn pkce_matches(verifier: &str, challenge: &str) -> bool {
    use subtle::ConstantTimeEq as _;
    let computed = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    computed.as_bytes().ct_eq(challenge.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> Signer {
        Signer::new("0123456789abcdef0123456789abcdef")
    }

    #[test]
    fn round_trips_and_rejects_tampering() {
        let signer = signer();
        let claims = Claims::Access {
            exp: expires_in(Duration::from_secs(60)),
        };
        let token = signer.sign(&claims);
        assert_eq!(signer.verify(&token), Some(claims));

        let (payload, sig) = token.split_once('.').unwrap();
        let forged = URL_SAFE_NO_PAD.encode(br#"{"typ":"access","exp":99999999999}"#);
        assert_eq!(signer.verify(&format!("{forged}.{sig}")), None);
        assert_eq!(signer.verify(payload), None);
        assert_eq!(
            Signer::new("a different secret, same length!!").verify(&token),
            None
        );
    }

    #[test]
    fn rejects_expired_tokens() {
        let token = signer().sign(&Claims::Access { exp: now() - 1 });
        assert_eq!(signer().verify(&token), None);
    }

    #[test]
    fn pkce_rfc7636_example() {
        // Appendix B of RFC 7636.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert!(pkce_matches(
            verifier,
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        ));
        assert!(!pkce_matches(
            verifier,
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cN"
        ));
        assert!(!pkce_matches(
            "wrong-verifier",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        ));
    }
}

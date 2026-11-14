//! Detection of anti-bot blocks: challenge pages, CAPTCHAs, WAF denials, and rate limits.
//!
//! Many sites answer automated traffic not with an error but with an interstitial page (often
//! `200`, `202`, `403`, or `503`) that says "checking your browser" or shows a CAPTCHA. Handing
//! that page to the model as if it were content is misleading, so [`WebClient`] runs every
//! response through [`detect`] first and turns a match into
//! [`WebError::Blocked`](crate::web::WebError::Blocked), which is logged at `WARN`.
//!
//! Detection is heuristic and deliberately conservative:
//!
//! * **Strong** signatures (vendor challenge pages, block messages) count on any status — but on
//!   a 2xx response only if the body is small, since real pages can embed CAPTCHA widgets while
//!   challenge interstitials are tiny.
//! * **Weak** signatures (generic CAPTCHA scripts, vendor cookies, `Server` headers) count only
//!   on 4xx/5xx responses.
//! * With no signature, `403` is reported as a generic denial and `429` as rate limiting.
//!
//! [`WebClient`]: crate::web::WebClient

use std::{collections::HashMap, fmt};

/// Only this many leading bytes of the body are scanned; block pages are small and their
/// markers appear early.
const SCAN_BYTES: usize = 128 * 1024;

/// A 2xx response larger than this is assumed to be real content even if it contains a strong
/// marker (e.g. an article page that embeds a Turnstile or reCAPTCHA widget).
const MAX_CHALLENGE_PAGE_BYTES: usize = 64 * 1024;

/// A detected block: who blocked the request and how.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Block {
    /// Human-readable description, e.g. `"Cloudflare challenge"`.
    pub reason: &'static str,
    /// HTTP status of the blocking response.
    pub status: u16,
}

/// Reason given to a bare `403` with no recognisable anti-bot vendor.
const GENERIC_DENIAL: &str = "access denied";

impl Block {
    /// Whether this is a bare `403` with no recognised vendor signature. Such denials are
    /// sometimes triggered by the browser impersonation itself, so they are worth one retry
    /// with a plain client; vendor challenges are not.
    pub fn is_generic_denial(&self) -> bool {
        self.reason == GENERIC_DENIAL
    }
}

impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (HTTP {})", self.reason, self.status)
    }
}

/// Lower-case substrings that identify a block page.
struct Signature {
    reason: &'static str,
    markers: &'static [&'static str],
    strong: bool,
}

const BODY_SIGNATURES: &[Signature] = &[
    Signature {
        reason: "Cloudflare challenge",
        markers: &[
            "<title>just a moment...</title>",
            "cf-chl-",
            "cf_chl_opt",
            "/cdn-cgi/challenge-platform/h/",
        ],
        strong: true,
    },
    Signature {
        reason: "Cloudflare firewall block",
        markers: &[
            "attention required! | cloudflare",
            "cf-error-details",
            "error code: 1020",
        ],
        strong: true,
    },
    Signature {
        reason: "DataDome CAPTCHA",
        markers: &["captcha-delivery.com", "geo.captcha-delivery"],
        strong: true,
    },
    Signature {
        reason: "PerimeterX / HUMAN challenge",
        markers: &[
            "px-captcha",
            "_pxcaptcha",
            "press &amp; hold",
            "press & hold to confirm",
        ],
        strong: true,
    },
    Signature {
        reason: "Imperva / Incapsula block",
        markers: &["incapsula incident id", "_incapsula_resource"],
        strong: true,
    },
    Signature {
        reason: "Akamai block",
        markers: &["errors.edgesuite.net", "reference&#32;&#35;"],
        strong: true,
    },
    Signature {
        reason: "AWS WAF challenge",
        markers: &["awswaf.com", "aws-waf-token"],
        strong: true,
    },
    Signature {
        reason: "Sucuri firewall block",
        markers: &["sucuri website firewall", "cloudproxy.sucuri.net"],
        strong: true,
    },
    Signature {
        reason: "Craigslist IP block",
        markers: &["has been automatically blocked", "blocks@craigslist.org"],
        strong: true,
    },
    Signature {
        reason: "Google unusual-traffic block",
        markers: &["our systems have detected unusual traffic"],
        strong: true,
    },
    Signature {
        reason: "CAPTCHA",
        markers: &[
            "g-recaptcha",
            "recaptcha/api.js",
            "hcaptcha.com",
            "challenges.cloudflare.com/turnstile",
        ],
        strong: false,
    },
    Signature {
        reason: "PerimeterX / HUMAN block",
        markers: &["perimeterx", "_pxhd"],
        strong: false,
    },
    Signature {
        reason: "DataDome block",
        markers: &["datadome"],
        strong: false,
    },
];

/// Classifies a response as blocked, or `None` if it looks like real content.
///
/// `headers` may use any key case. Only the first [`SCAN_BYTES`] of `body` are examined.
pub fn detect(status: u16, headers: &HashMap<String, String>, body: &[u8]) -> Option<Block> {
    let is_error = status >= 400;
    let header = |name: &str| {
        headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.to_ascii_lowercase())
    };
    let block = |reason| Some(Block { reason, status });

    // Explicit vendor headers are the most reliable signal.
    if header("cf-mitigated").is_some_and(|v| v.contains("challenge")) {
        return block("Cloudflare challenge");
    }
    if header("x-amzn-waf-action").is_some_and(|v| v.contains("captcha") || v.contains("challenge"))
    {
        return block("AWS WAF challenge");
    }
    if is_error
        && headers
            .keys()
            .any(|k| k.to_ascii_lowercase().starts_with("x-kpsdk"))
    {
        return block("Kasada challenge");
    }

    let head = String::from_utf8_lossy(&body[..body.len().min(SCAN_BYTES)]).to_ascii_lowercase();
    let small = body.len() <= MAX_CHALLENGE_PAGE_BYTES;
    let signature = BODY_SIGNATURES
        .iter()
        .filter(|sig| {
            if sig.strong {
                is_error || small
            } else {
                is_error
            }
        })
        .find(|sig| sig.markers.iter().any(|marker| head.contains(marker)));
    if let Some(sig) = signature {
        return block(sig.reason);
    }

    let server = header("server").unwrap_or_default();
    match status {
        403 if server.contains("cloudflare") => block("Cloudflare firewall block"),
        403 if server.contains("akamai") => block("Akamai block"),
        403 => block(GENERIC_DENIAL),
        429 => block("rate limited"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_headers() -> HashMap<String, String> {
        HashMap::new()
    }

    fn reason(status: u16, body: &str) -> Option<&'static str> {
        detect(status, &no_headers(), body.as_bytes()).map(|b| b.reason)
    }

    #[test]
    fn detects_vendor_challenge_pages() {
        let cases = [
            (
                403,
                "<html><head><title>Just a moment...</title></head><script>window._cf_chl_opt={}</script>",
                "Cloudflare challenge",
            ),
            (
                403,
                "<title>Attention Required! | Cloudflare</title><div class=\"cf-error-details\">",
                "Cloudflare firewall block",
            ),
            (
                403,
                "<script src=\"https://ct.captcha-delivery.com/c.js\"></script>",
                "DataDome CAPTCHA",
            ),
            (
                403,
                "<div id=\"px-captcha\"></div><p>Press &amp; Hold to confirm you are a human</p>",
                "PerimeterX / HUMAN challenge",
            ),
            (
                403,
                "Request unsuccessful. Incapsula incident ID: 123-456",
                "Imperva / Incapsula block",
            ),
            (
                403,
                "<H1>Access Denied</H1>Reference&#32;&#35;18&#46;abc https://errors.edgesuite.net/18.abc",
                "Akamai block",
            ),
            (
                202,
                "<script src=\"https://abc.token.awswaf.com/challenge.js\"></script>",
                "AWS WAF challenge",
            ),
            (
                200,
                "This IP has been automatically blocked. If you have questions, please email: blocks@craigslist.org",
                "Craigslist IP block",
            ),
            (
                429,
                "Our systems have detected unusual traffic from your computer network.",
                "Google unusual-traffic block",
            ),
        ];
        for (status, body, expected) in cases {
            assert_eq!(reason(status, body), Some(expected), "{body}");
        }
    }

    #[test]
    fn detects_by_header_and_status() {
        let headers = HashMap::from([("CF-Mitigated".to_owned(), "challenge".to_owned())]);
        assert_eq!(
            detect(403, &headers, b"").map(|b| b.reason),
            Some("Cloudflare challenge")
        );
        let server = HashMap::from([("server".to_owned(), "cloudflare".to_owned())]);
        assert_eq!(
            detect(403, &server, b"nope").map(|b| b.reason),
            Some("Cloudflare firewall block")
        );
        assert_eq!(reason(403, "Forbidden"), Some("access denied"));
        assert_eq!(reason(429, "Too Many Requests"), Some("rate limited"));
    }

    #[test]
    fn ignores_normal_pages() {
        assert_eq!(
            reason(
                200,
                "<html><title>Bikes for sale</title><main>Fuji hybrid $175</main>"
            ),
            None
        );
        assert_eq!(reason(404, "<h1>Not Found</h1>"), None);
        assert_eq!(reason(503, "<h1>Service Unavailable</h1>"), None);
        // A contact form with reCAPTCHA on a normal page is not a block (weak marker, 2xx).
        assert_eq!(
            reason(200, "<form><div class=\"g-recaptcha\"></div></form>"),
            None
        );
    }

    #[test]
    fn large_pages_with_widgets_are_not_challenges() {
        let article = format!(
            "<title>Just a moment...</title>{}",
            "<p>real content</p>".repeat(5_000)
        );
        assert!(article.len() > MAX_CHALLENGE_PAGE_BYTES);
        assert_eq!(reason(200, &article), None);
        assert_eq!(reason(403, &article), Some("Cloudflare challenge"));
    }
}

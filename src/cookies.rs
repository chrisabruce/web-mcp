//! Per-site cookie jars: scoping, merging, and importing cookies exported from a browser.
//!
//! A [`CookieJar`] belongs to one user and one site domain (e.g. `craigslist.org`). It is sent
//! with requests to that domain and its subdomains, updated from every response's
//! `Set-Cookie`, and persisted encrypted by [`crate::store`]. Cookie attributes (path,
//! expiry, per-cookie domain) are intentionally not modelled: the fetcher only exposes
//! cookie names and values, and treating the whole site as one scope is what a logged-in
//! session needs in practice.
//!
//! [`parse_import`] accepts the three formats users can get out of a browser:
//!
//! * a `Cookie` request header (`name=value; other=value`) copied from developer tools,
//! * a JSON array from extensions such as Cookie-Editor or EditThisCookie,
//! * a Netscape `cookies.txt` file.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Cookies for one site, keyed by name.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CookieJar {
    cookies: BTreeMap<String, String>,
}

impl CookieJar {
    /// Builds a jar from name/value pairs; later duplicates win.
    pub fn from_pairs(pairs: impl IntoIterator<Item = (String, String)>) -> Self {
        Self {
            cookies: pairs.into_iter().collect(),
        }
    }

    /// Whether the jar holds no cookies.
    pub fn is_empty(&self) -> bool {
        self.cookies.is_empty()
    }

    /// Number of cookies in the jar.
    pub fn len(&self) -> usize {
        self.cookies.len()
    }

    /// The cookies as a name→value map, in the shape the fetcher's `RequestConfig` expects.
    pub fn to_map(&self) -> std::collections::HashMap<String, String> {
        self.cookies.clone().into_iter().collect()
    }

    /// Merges cookies from a response. An empty value is how servers delete a cookie, so it
    /// removes the entry. Returns whether anything changed.
    pub fn merge(&mut self, set_cookies: &std::collections::HashMap<String, String>) -> bool {
        let mut changed = false;
        for (name, value) in set_cookies {
            changed |= if value.is_empty() {
                self.cookies.remove(name).is_some()
            } else {
                self.cookies.insert(name.clone(), value.clone()).as_ref() != Some(value)
            };
        }
        changed
    }
}

/// Whether a cookie scoped to `domain` should be sent to `host` (exact or subdomain match).
pub fn domain_matches(domain: &str, host: &str) -> bool {
    let (domain, host) = (domain.to_ascii_lowercase(), host.to_ascii_lowercase());
    host == domain || host.ends_with(&format!(".{domain}"))
}

/// Normalizes user input (`https://www.Example.com/login`, `example.com.`) to a bare domain.
///
/// A leading `www.` is dropped so the jar also covers the apex and other subdomains.
pub fn normalize_domain(input: &str) -> Option<String> {
    let input = input.trim();
    let host = match url::Url::parse(input) {
        Ok(url) if url.host_str().is_some() => url.host_str()?.to_owned(),
        _ => input
            .split(['/', '?', '#'])
            .next()?
            .split(':')
            .next()?
            .to_owned(),
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let host = host.strip_prefix("www.").unwrap_or(&host).to_owned();
    let valid = !host.is_empty()
        && host.contains('.')
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.');
    valid.then_some(host)
}

/// Why imported cookie text could not be used.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ImportError {
    /// The text looked like JSON but was not an array of `{name, value}` objects.
    #[error("invalid cookie JSON: {0}")]
    Json(String),
    /// Nothing usable was found.
    #[error(
        "no cookies found; paste a Cookie header (name=value; ...), a JSON export, or cookies.txt"
    )]
    Empty,
}

/// Parses cookies pasted from a browser, keeping only those that apply to `domain`
/// (formats that carry a per-cookie domain are filtered; the header format is trusted).
pub fn parse_import(text: &str, domain: &str) -> Result<CookieJar, ImportError> {
    let text = text.trim();
    let pairs: Vec<(String, String)> = if text.starts_with('[') || text.starts_with('{') {
        parse_json(text, domain)?
    } else if text.lines().any(|line| line.split('\t').count() >= 7) {
        parse_netscape(text, domain)
    } else {
        parse_header(text)
    };
    let jar = CookieJar::from_pairs(pairs);
    if jar.is_empty() {
        Err(ImportError::Empty)
    } else {
        Ok(jar)
    }
}

/// `name=value; name2=value2`, optionally prefixed with `Cookie:`.
fn parse_header(text: &str) -> Vec<(String, String)> {
    let text = text
        .strip_prefix("Cookie:")
        .or_else(|| text.strip_prefix("cookie:"))
        .unwrap_or(text);
    text.split(';')
        .filter_map(|pair| {
            let (name, value) = pair.split_once('=')?;
            let name = name.trim();
            (!name.is_empty()).then(|| (name.to_owned(), value.trim().to_owned()))
        })
        .collect()
}

/// A JSON array of cookie objects (Cookie-Editor / EditThisCookie / Playwright storage).
fn parse_json(text: &str, domain: &str) -> Result<Vec<(String, String)>, ImportError> {
    #[derive(Deserialize)]
    struct JsonCookie {
        name: String,
        value: String,
        #[serde(default)]
        domain: Option<String>,
    }
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Export {
        List(Vec<JsonCookie>),
        Storage { cookies: Vec<JsonCookie> },
    }
    let cookies = match serde_json::from_str(text).map_err(|e| ImportError::Json(e.to_string()))? {
        Export::List(list) | Export::Storage { cookies: list } => list,
    };
    Ok(cookies
        .into_iter()
        .filter(|c| applies(c.domain.as_deref(), domain))
        .map(|c| (c.name, c.value))
        .collect())
}

/// Netscape `cookies.txt`: `domain  flag  path  secure  expiry  name  value`, tab-separated.
fn parse_netscape(text: &str, domain: &str) -> Vec<(String, String)> {
    text.lines()
        .map(|line| line.strip_prefix("#HttpOnly_").unwrap_or(line))
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| {
            let fields: Vec<&str> = line.split('\t').collect();
            let [cookie_domain, _, _, _, _, name, value] =
                fields.as_slice().get(..7)?.try_into().ok()?;
            applies(Some(cookie_domain), domain).then(|| ((*name).to_owned(), (*value).to_owned()))
        })
        .collect()
}

/// Whether a cookie exported with `cookie_domain` belongs to the jar for `site`.
fn applies(cookie_domain: Option<&str>, site: &str) -> bool {
    cookie_domain.is_none_or(|d| {
        let d = d.trim_start_matches('.');
        domain_matches(site, d) || domain_matches(d, site)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_scoping() {
        assert!(domain_matches("craigslist.org", "craigslist.org"));
        assert!(domain_matches("craigslist.org", "accounts.craigslist.org"));
        assert!(!domain_matches("craigslist.org", "evilcraigslist.org"));
        assert!(!domain_matches("craigslist.org", "craigslist.org.evil.com"));
    }

    #[test]
    fn normalizes_domains() {
        assert_eq!(
            normalize_domain("https://www.Example.com/login?x=1").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            normalize_domain("accounts.craigslist.org").as_deref(),
            Some("accounts.craigslist.org")
        );
        assert_eq!(
            normalize_domain("example.com:8443/x").as_deref(),
            Some("example.com")
        );
        assert_eq!(normalize_domain("localhost"), None);
        assert_eq!(normalize_domain("bad domain.com"), None);
    }

    #[test]
    fn merge_tracks_changes_and_deletions() {
        let mut jar = CookieJar::from_pairs([("a".into(), "1".into())]);
        let set = |pairs: &[(&str, &str)]| {
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        };
        assert!(!jar.merge(&set(&[("a", "1")])));
        assert!(jar.merge(&set(&[("b", "2")])));
        assert!(jar.merge(&set(&[("a", "")])));
        assert_eq!(jar, CookieJar::from_pairs([("b".into(), "2".into())]));
    }

    #[test]
    fn imports_header_format() {
        let jar = parse_import("Cookie: session=abc; theme=dark ; =skip", "example.com").unwrap();
        assert_eq!(jar.len(), 2);
        assert_eq!(jar.to_map()["session"], "abc");
    }

    #[test]
    fn imports_json_and_filters_domains() {
        let json = r#"[
            {"name":"cl_session","value":"s1","domain":".craigslist.org"},
            {"name":"tracker","value":"t","domain":".ads.example"},
            {"name":"nodomain","value":"n"}
        ]"#;
        let jar = parse_import(json, "craigslist.org").unwrap();
        assert_eq!(jar.to_map().len(), 2);
        assert_eq!(jar.to_map()["cl_session"], "s1");
        let storage =
            r#"{"cookies":[{"name":"x","value":"1","domain":"craigslist.org"}],"origins":[]}"#;
        assert_eq!(parse_import(storage, "craigslist.org").unwrap().len(), 1);
    }

    #[test]
    fn imports_netscape_format() {
        let txt = "# Netscape HTTP Cookie File\n\
                   .craigslist.org\tTRUE\t/\tTRUE\t1999999999\tcl_session\tabc\n\
                   #HttpOnly_accounts.craigslist.org\tFALSE\t/\tTRUE\t0\tauth\txyz\n\
                   .other.com\tTRUE\t/\tFALSE\t0\tnope\t1\n";
        let jar = parse_import(txt, "craigslist.org").unwrap();
        assert_eq!(jar.len(), 2);
        assert_eq!(jar.to_map()["auth"], "xyz");
    }

    #[test]
    fn rejects_empty_import() {
        assert_eq!(parse_import("   ", "example.com"), Err(ImportError::Empty));
        assert!(matches!(
            parse_import("[{]", "example.com"),
            Err(ImportError::Json(_))
        ));
    }
}

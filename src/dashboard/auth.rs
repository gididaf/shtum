//! Dashboard authentication: random session token + Host-header validation.
//!
//! The dashboard binds 127.0.0.1 only, but loopback is not a sufficient
//! authorisation boundary on a shared machine: any local process owned by
//! the same user can also reach the port, and a malicious site can attempt
//! DNS rebinding to point its own hostname at 127.0.0.1 in the victim's
//! browser. We defend against both with:
//!
//! - A 24-byte random token generated at startup, included in the launch URL
//!   and required on every request. Token lives in the request *body* (form
//!   field) or the query string — never set as a cookie, so it can't be
//!   replayed via cross-origin form submissions.
//! - A strict `Host:` header check that accepts only `127.0.0.1:<port>` or
//!   `localhost:<port>`. This blocks DNS rebinding because the attacker's
//!   hostname won't match.

use std::fmt;
use std::fs::File;
use std::io::{self, Read};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

/// A loopback-only session capability. Created once per `shtum dashboard`
/// process and printed in the launch URL. Treat it like a bearer token:
/// anyone with the value can act as the user against the dashboard.
pub struct Token(String);

impl Token {
    /// Generate a fresh token by reading 24 bytes from `/dev/urandom` and
    /// base64-URL-encoding them (no padding). 24 bytes = 192 bits of entropy,
    /// well above brute-force concerns against a process that lives minutes
    /// to hours.
    pub fn generate() -> io::Result<Self> {
        let mut bytes = [0u8; 24];
        File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        Ok(Self(URL_SAFE_NO_PAD.encode(bytes)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Constant-time string comparison. The length check leaks the candidate
    /// length, but our tokens are always the same length so this is fine.
    pub fn verify(&self, candidate: &str) -> bool {
        ct_eq(self.0.as_bytes(), candidate.as_bytes())
    }
}

/// Never print the token, even in debug logs.
impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(<redacted>)")
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[derive(Debug, PartialEq, Eq)]
pub enum AuthResult {
    Ok,
    BadHost,
    BadToken,
}

/// Validate the `Host:` header against the bound port. Accepts exactly
/// `127.0.0.1:<port>` or `localhost:<port>`. Anything else is rejected,
/// including `*.localhost` resolution tricks and bare IP variants.
pub fn host_ok(host: &str, expected_port: u16) -> bool {
    let expected_127 = format!("127.0.0.1:{expected_port}");
    let expected_localhost = format!("localhost:{expected_port}");
    host == expected_127 || host == expected_localhost
}

/// Extract the `token` query parameter from a URL of the form `/path?token=...`.
/// Returns `None` if absent or if it appears more than once (a duplicate-key
/// smuggling attempt).
pub fn extract_token_from_url(url: &str) -> Option<String> {
    let query = url.split_once('?').map(|(_, q)| q)?;
    let mut found: Option<String> = None;
    for pair in query.split('&') {
        let (k, v) = match pair.split_once('=') {
            Some(kv) => kv,
            None => continue,
        };
        if k == "token" {
            if found.is_some() {
                // Two `token=` entries — refuse to guess which one the
                // server should trust.
                return None;
            }
            found = Some(percent_decode(v));
        }
    }
    found
}

/// Minimal percent-decoding for token values. Tokens are URL-safe base64
/// (no padding) so we won't see `%XX` in practice, but decode anyway in case
/// a client over-escapes.
fn percent_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}

/// Look up the `Host:` header on a tiny_http request (case-insensitive).
pub fn host_header<'a>(req: &'a tiny_http::Request) -> Option<&'a str> {
    for h in req.headers() {
        if h.field.as_str().as_str().eq_ignore_ascii_case("host") {
            return Some(h.value.as_str());
        }
    }
    None
}

/// Full per-request auth check: Host header + token (from query string).
/// Token-in-form-body is checked separately by the handler that parses the
/// form, because we need the parsed body anyway and don't want to read it
/// twice.
pub fn check_get(req: &tiny_http::Request, token: &Token, port: u16) -> AuthResult {
    let host = match host_header(req) {
        Some(h) => h,
        None => return AuthResult::BadHost,
    };
    if !host_ok(host, port) {
        return AuthResult::BadHost;
    }
    let candidate = match extract_token_from_url(req.url()) {
        Some(t) => t,
        None => return AuthResult::BadToken,
    };
    if token.verify(&candidate) {
        AuthResult::Ok
    } else {
        AuthResult::BadToken
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_generate_is_random() {
        let a = Token::generate().expect("urandom read failed");
        let b = Token::generate().expect("urandom read failed");
        assert_ne!(a.as_str(), b.as_str());
        // URL_SAFE_NO_PAD of 24 bytes = 32 chars.
        assert_eq!(a.as_str().len(), 32);
    }

    #[test]
    fn token_verify_is_constant_time_eq() {
        let t = Token("abc123".to_string());
        assert!(t.verify("abc123"));
        assert!(!t.verify("abc124"));
        assert!(!t.verify("abc12")); // length mismatch
        assert!(!t.verify(""));
    }

    #[test]
    fn token_debug_does_not_leak() {
        let t = Token("supersecret".to_string());
        let debug = format!("{t:?}");
        assert!(!debug.contains("supersecret"));
        assert!(debug.contains("redacted"));
    }

    #[test]
    fn host_ok_accepts_loopback_and_localhost() {
        assert!(host_ok("127.0.0.1:8080", 8080));
        assert!(host_ok("localhost:8080", 8080));
    }

    #[test]
    fn host_ok_rejects_everything_else() {
        assert!(!host_ok("evil.com:8080", 8080));
        assert!(!host_ok("foo.localhost:8080", 8080));
        assert!(!host_ok("127.0.0.1:8081", 8080)); // wrong port
        assert!(!host_ok("127.0.0.1", 8080)); // missing port
        assert!(!host_ok("", 8080));
        // ::1 (IPv6 loopback) is intentionally rejected; tiny_http binds on
        // 127.0.0.1 only so we should never see it, but be explicit.
        assert!(!host_ok("[::1]:8080", 8080));
    }

    #[test]
    fn extract_token_from_url_basic() {
        assert_eq!(
            extract_token_from_url("/?token=abc").as_deref(),
            Some("abc"),
        );
        assert_eq!(
            extract_token_from_url("/foo/bar?token=xyz&extra=1").as_deref(),
            Some("xyz"),
        );
        assert_eq!(
            extract_token_from_url("/?extra=1&token=xyz").as_deref(),
            Some("xyz"),
        );
    }

    #[test]
    fn extract_token_from_url_absent() {
        assert!(extract_token_from_url("/").is_none());
        assert!(extract_token_from_url("/?").is_none());
        assert!(extract_token_from_url("/?notoken=abc").is_none());
    }

    #[test]
    fn extract_token_from_url_rejects_duplicates() {
        // Two `token=` entries — refuse to guess.
        assert!(extract_token_from_url("/?token=abc&token=def").is_none());
    }

    #[test]
    fn extract_token_handles_percent_encoded() {
        // `abc%2Fdef` decodes to `abc/def`. Real tokens are URL-safe so this
        // is just defensive.
        assert_eq!(
            extract_token_from_url("/?token=abc%2Fdef").as_deref(),
            Some("abc/def"),
        );
    }
}

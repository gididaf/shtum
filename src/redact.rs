// Copyright 2026 Gidi Dafner
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use base64::Engine;
use percent_encoding::{NON_ALPHANUMERIC, percent_encode};
use regex::bytes::Regex;

const REDACTED: &[u8] = b"[REDACTED]";

/// Upper bound on how many bytes the sliding window will hold to support
/// regex-based (Layer B) matching. A regex match longer than this will not
/// be redacted — accept the gap rather than buffer the entire stream.
const REGEX_WINDOW_CAP: usize = 4096;

/// Built-in default regex patterns that the user can opt out of with
/// `--no-default-redact`. ASCII-only; matched against raw subprocess bytes.
const DEFAULT_PATTERNS: &[&str] = &[
    // JWT (header.payload.signature, base64url alphabet)
    r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    // AWS access key ID
    r"AKIA[0-9A-Z]{16}",
    // Bearer token header (greedy on token charset)
    r"Bearer\s+[A-Za-z0-9_\-.=]+",
    // GitHub personal access tokens (classic + fine-grained variants)
    r"gh[pousr]_[A-Za-z0-9]{36}",
];

/// Compile user-supplied `--redact` patterns and (optionally) the built-in
/// default set into a single combined alternation regex. Returns `None` if
/// no patterns are enabled.
///
/// Each user pattern is also validated individually first so error messages
/// can identify which one failed to compile.
pub fn build_layer_b(user_patterns: &[String], include_defaults: bool) -> Result<Option<Regex>> {
    let mut parts: Vec<String> = Vec::new();
    if include_defaults {
        for p in DEFAULT_PATTERNS {
            parts.push(format!("(?:{p})"));
        }
    }
    for p in user_patterns {
        Regex::new(p).with_context(|| format!("invalid --redact pattern `{p}`"))?;
        parts.push(format!("(?:{p})"));
    }
    if parts.is_empty() {
        return Ok(None);
    }
    let combined = parts.join("|");
    let re = Regex::new(&combined).context("compiling combined redact regex")?;
    Ok(Some(re))
}

/// Streaming byte filter that scrubs known secret values out of subprocess
/// output.
///
/// **Layer A** (always active when `secrets` is non-empty): three variants
/// per secret — literal bytes, conservative URL-encoded form, and standard
/// base64 — matched at the exact head position, longest-first.
///
/// **Layer B** (active when `regex_b` is `Some`): a combined alternation
/// regex of user-supplied `--redact` patterns and (optionally) the
/// built-in default set, applied as leftmost-match within a bounded window.
///
/// The filter holds back the trailing `max_len - 1` bytes of each chunk so
/// matches split across read boundaries still match; `flush()` drains the
/// tail at EOF.
pub struct Filter {
    variants: Vec<Vec<u8>>, // Layer A, sorted longest-first
    regex_b: Option<Regex>, // Layer B
    max_len: usize,
    buffer: Vec<u8>,
    head: usize,
    /// Cached next Layer B match `(start, end)` in absolute buffer
    /// coordinates. Cleared on `push` (buffer changed) and after the cached
    /// match is consumed. Recomputed lazily when `head` advances past it.
    b_cache: Option<(usize, usize)>,
}

impl Filter {
    pub fn new(secrets: &[Vec<u8>], regex_b: Option<Regex>) -> Self {
        let mut variants: Vec<Vec<u8>> = Vec::new();
        for s in secrets {
            if s.is_empty() {
                continue;
            }
            variants.push(s.clone());
            variants.push(url_encoded(s));
            variants.push(base64_encoded(s));
        }
        variants.sort();
        variants.dedup();
        variants.sort_by(|a, b| b.len().cmp(&a.len()));
        let max_a = variants.first().map(|v| v.len()).unwrap_or(0);
        let max_b = if regex_b.is_some() { REGEX_WINDOW_CAP } else { 0 };
        let max_len = max_a.max(max_b);
        Self {
            variants,
            regex_b,
            max_len,
            buffer: Vec::new(),
            head: 0,
            b_cache: None,
        }
    }

    pub fn is_noop(&self) -> bool {
        self.variants.is_empty() && self.regex_b.is_none()
    }

    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        if self.is_noop() {
            return chunk.to_vec();
        }
        self.buffer.extend_from_slice(chunk);
        // New bytes may have extended a partial match or revealed an earlier
        // one; invalidate the cache.
        self.b_cache = None;
        let mut out = Vec::with_capacity(chunk.len());
        while self.head + self.max_len <= self.buffer.len() {
            self.step(&mut out, /* eof = */ false);
        }
        self.compact();
        out
    }

    pub fn flush(&mut self) -> Vec<u8> {
        if self.is_noop() {
            let out = self.buffer[self.head..].to_vec();
            self.buffer.clear();
            self.head = 0;
            return out;
        }
        // At EOF, the regex window expands to whatever's left.
        self.b_cache = None;
        let mut out = Vec::with_capacity(self.buffer.len().saturating_sub(self.head));
        while self.head < self.buffer.len() {
            self.step(&mut out, /* eof = */ true);
        }
        self.buffer.clear();
        self.head = 0;
        out
    }

    /// One decision step: redact, or emit one byte. Layer A is checked
    /// first at the exact head position. Layer B's next match is cached so
    /// the regex isn't re-run on every step; when head reaches the cached
    /// match start, redact and clear the cache. Otherwise emit one byte —
    /// this guarantees Layer A gets a chance to match at every position
    /// between two Layer B matches.
    fn step(&mut self, out: &mut Vec<u8>, eof: bool) {
        if let Some(len) = self.match_a_at(self.head) {
            out.extend_from_slice(REDACTED);
            self.head += len;
            // A Layer A redaction may have stepped past the cached B match's
            // start without consuming it; force recompute next time.
            if let Some((b_start, _)) = self.b_cache {
                if self.head > b_start {
                    self.b_cache = None;
                }
            }
            return;
        }
        // Ensure Layer B cache is current.
        let needs_refresh = match self.b_cache {
            None => true,
            Some((b_start, _)) => b_start < self.head,
        };
        if needs_refresh {
            self.b_cache = self.find_b(self.head, eof);
        }
        if let Some((b_start, b_end)) = self.b_cache {
            if b_start == self.head {
                out.extend_from_slice(REDACTED);
                self.head = b_end;
                self.b_cache = None;
                return;
            }
        }
        out.push(self.buffer[self.head]);
        self.head += 1;
    }

    fn match_a_at(&self, pos: usize) -> Option<usize> {
        for v in &self.variants {
            let end = pos + v.len();
            if end <= self.buffer.len() && &self.buffer[pos..end] == v.as_slice() {
                return Some(v.len());
            }
        }
        None
    }

    fn find_b(&self, pos: usize, eof: bool) -> Option<(usize, usize)> {
        let r = self.regex_b.as_ref()?;
        let window_end = if eof {
            self.buffer.len()
        } else {
            (pos + self.max_len).min(self.buffer.len())
        };
        if pos >= window_end {
            return None;
        }
        let m = r.find(&self.buffer[pos..window_end])?;
        Some((pos + m.start(), pos + m.end()))
    }

    fn compact(&mut self) {
        if self.head >= 4096 {
            let drained = self.head;
            self.buffer.drain(..drained);
            self.head = 0;
            // Cache holds absolute positions; shift them.
            if let Some((s, e)) = self.b_cache {
                self.b_cache = if s >= drained {
                    Some((s - drained, e - drained))
                } else {
                    None
                };
            }
        }
    }
}

fn url_encoded(bytes: &[u8]) -> Vec<u8> {
    percent_encode(bytes, NON_ALPHANUMERIC)
        .collect::<String>()
        .into_bytes()
}

fn base64_encoded(bytes: &[u8]) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .encode(bytes)
        .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(secrets: &[&[u8]], regex_b: Option<Regex>, chunks: &[&[u8]]) -> Vec<u8> {
        let owned: Vec<Vec<u8>> = secrets.iter().map(|s| s.to_vec()).collect();
        let mut f = Filter::new(&owned, regex_b);
        let mut out = Vec::new();
        for c in chunks {
            out.extend(f.push(c));
        }
        out.extend(f.flush());
        out
    }

    #[test]
    fn literal_redacted() {
        let out = run(&[b"supersecret-xyz"], None, &[b"response: supersecret-xyz returned\n"]);
        assert_eq!(out, b"response: [REDACTED] returned\n");
    }

    #[test]
    fn split_across_chunks() {
        let out = run(&[b"supersecret-xyz"], None, &[b"super", b"secret-xyz\n"]);
        assert_eq!(out, b"[REDACTED]\n");
    }

    #[test]
    fn url_encoded_match() {
        let out = run(&[b"a/b+c"], None, &[b"encoded: a%2Fb%2Bc\n"]);
        assert_eq!(out, b"encoded: [REDACTED]\n");
    }

    #[test]
    fn base64_match() {
        let out = run(&[b"supersecret-xyz"], None, &[b"c3VwZXJzZWNyZXQteHl6\n"]);
        assert_eq!(out, b"[REDACTED]\n");
    }

    #[test]
    fn no_secrets_no_regex_passes_through() {
        let out = run(&[], None, &[b"hello world\n"]);
        assert_eq!(out, b"hello world\n");
    }

    #[test]
    fn back_to_back_matches() {
        let out = run(&[b"abc"], None, &[b"abcabc\n"]);
        assert_eq!(out, b"[REDACTED][REDACTED]\n");
    }

    #[test]
    fn partial_no_match_at_eof() {
        let out = run(&[b"supersecret"], None, &[b"prefix sup"]);
        assert_eq!(out, b"prefix sup");
    }

    #[test]
    fn longer_variant_preferred() {
        let out = run(&[b"abc", b"abcdef"], None, &[b"abcdef\n"]);
        assert_eq!(out, b"[REDACTED]\n");
    }

    fn defaults_only() -> Option<Regex> {
        build_layer_b(&[], true).unwrap()
    }

    #[test]
    fn default_jwt_redacted() {
        let out = run(
            &[],
            defaults_only(),
            &[b"token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c next\n"],
        );
        assert_eq!(out, b"token: [REDACTED] next\n");
    }

    #[test]
    fn default_akia_redacted() {
        let out = run(&[], defaults_only(), &[b"key=AKIAIOSFODNN7EXAMPLE rest\n"]);
        assert_eq!(out, b"key=[REDACTED] rest\n");
    }

    #[test]
    fn default_bearer_redacted() {
        let out = run(&[], defaults_only(), &[b"Authorization: Bearer abcDEF123.-_=xyz\n"]);
        assert_eq!(out, b"Authorization: [REDACTED]\n");
    }

    #[test]
    fn default_github_pat_redacted() {
        let out = run(&[], defaults_only(), &[b"token=ghp_abcdefghijklmnopqrstuvwxyz0123456789 done\n"]);
        assert_eq!(out, b"token=[REDACTED] done\n");
    }

    #[test]
    fn user_regex_redacted() {
        // Pattern intentionally excludes the leading `"` so the redaction
        // begins at `zone_id`, leaving the opening `{"` intact.
        let regex_b = build_layer_b(&[r#"zone_id":\s*"[a-f0-9]+""#.to_string()], false).unwrap();
        let out = run(&[], regex_b, &[b"{\"zone_id\": \"abcdef0123\"}\n"]);
        assert_eq!(out, b"{\"[REDACTED]}\n");
    }

    #[test]
    fn layer_a_and_b_combined() {
        // Literal secret AND a JWT-shape in the same line; both redacted.
        let out = run(
            &[b"supersecret-xyz"],
            defaults_only(),
            &[b"resp: supersecret-xyz tok=eyJhbGciOiJIUzI1NiJ9.eyJzIn0.abc-_X\n"],
        );
        assert_eq!(out, b"resp: [REDACTED] tok=[REDACTED]\n");
    }

    #[test]
    fn layer_a_matches_before_a_layer_b_match_in_same_buffer() {
        // Regression: when Layer B finds a match later in the buffer, Layer
        // A occurrences BEFORE that B-match position must still be redacted.
        // Mirrors the live three-keychain-entries QA scenario.
        let out = run(
            &[b"hello-world-123", b"supersecret-xyz", b"a/b+c"],
            defaults_only(),
            &[b"resp: hello-world-123 tok=eyJa.eyJb.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV hello-world-123\n"],
        );
        assert_eq!(
            std::str::from_utf8(&out).unwrap(),
            "resp: [REDACTED] tok=[REDACTED] [REDACTED]\n"
        );
    }

    #[test]
    fn invalid_user_pattern_errors() {
        let err = build_layer_b(&["[unterminated".to_string()], false).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("invalid --redact pattern"), "got: {msg}");
    }

    #[test]
    fn defaults_disabled_passes_jwt() {
        // No defaults, no user patterns, no secrets → pure passthrough.
        let out = run(&[], None, &[b"eyJa.eyJb.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\n"]);
        assert_eq!(out, b"eyJa.eyJb.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\n");
    }
}

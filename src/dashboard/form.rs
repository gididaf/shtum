// Copyright 2026 Gidi Dafner
// SPDX-License-Identifier: MIT

//! Strict parser for `application/x-www-form-urlencoded` request bodies.
//!
//! The dashboard's mutation routes accept exactly one set of form fields
//! per request; if a client sends two `token=...` entries, we refuse to
//! guess which one to trust instead of letting the last-one-wins behaviour
//! of a permissive parser smuggle past the token check.

use std::collections::HashMap;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum FormError {
    #[error("duplicate form field: `{0}`")]
    DuplicateKey(String),
    #[error("form body is not valid UTF-8")]
    InvalidUtf8,
    #[error("malformed percent-encoding in form body")]
    Malformed,
}

/// Parse a form body, returning a map of decoded keys to decoded values.
/// Rejects duplicate keys with [`FormError::DuplicateKey`].
///
/// Empty body is valid and parses to an empty map. Empty segments between
/// `&`s are ignored. `key` (no `=`) decodes to an empty value.
///
/// Per the urlencoded spec, `+` decodes to space in both keys and values.
/// `%2B` decodes to a literal `+`, so the substitution must happen
/// *before* percent-decoding (which is what we do).
pub fn parse_strict(body: &[u8]) -> Result<HashMap<String, String>, FormError> {
    let s = std::str::from_utf8(body).map_err(|_| FormError::InvalidUtf8)?;
    let mut out: HashMap<String, String> = HashMap::new();
    for pair in s.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (raw_key, raw_val) = match pair.split_once('=') {
            Some(kv) => kv,
            None => (pair, ""),
        };
        let key = decode(raw_key)?;
        let value = decode(raw_val)?;
        if out.contains_key(&key) {
            return Err(FormError::DuplicateKey(key));
        }
        out.insert(key, value);
    }
    Ok(out)
}

fn decode(s: &str) -> Result<String, FormError> {
    // Urlencoded uses `+` for space. Substitute before percent-decoding so
    // that `%2B` (which decodes to a literal `+`) is *not* turned into a
    // space.
    let plus_to_space: String = s
        .chars()
        .map(|c| if c == '+' { ' ' } else { c })
        .collect();
    percent_encoding::percent_decode_str(&plus_to_space)
        .decode_utf8()
        .map(|cow| cow.into_owned())
        .map_err(|_| FormError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_pairs() {
        let m = parse_strict(b"name=FOO&value=bar").unwrap();
        assert_eq!(m.get("name").map(String::as_str), Some("FOO"));
        assert_eq!(m.get("value").map(String::as_str), Some("bar"));
    }

    #[test]
    fn plus_decodes_to_space() {
        let m = parse_strict(b"q=hello+world").unwrap();
        assert_eq!(m.get("q").map(String::as_str), Some("hello world"));
    }

    #[test]
    fn percent_encoded_plus_stays_plus() {
        // `%2B` is the escape for a literal `+`; it must NOT collapse to
        // space. This is the subtle correctness invariant the doc comment
        // calls out.
        let m = parse_strict(b"q=a%2Bb").unwrap();
        assert_eq!(m.get("q").map(String::as_str), Some("a+b"));
    }

    #[test]
    fn percent_decoding_handles_special_chars() {
        let m = parse_strict(b"v=%2Fpath%3Fto%3Dstuff").unwrap();
        assert_eq!(m.get("v").map(String::as_str), Some("/path?to=stuff"));
    }

    #[test]
    fn key_without_value_decodes_to_empty_string() {
        let m = parse_strict(b"flag").unwrap();
        assert_eq!(m.get("flag").map(String::as_str), Some(""));
    }

    #[test]
    fn empty_body_parses_to_empty_map() {
        let m = parse_strict(b"").unwrap();
        assert!(m.is_empty());
    }

    #[test]
    fn empty_segments_ignored() {
        let m = parse_strict(b"&a=1&&b=2&").unwrap();
        assert_eq!(m.get("a").map(String::as_str), Some("1"));
        assert_eq!(m.get("b").map(String::as_str), Some("2"));
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn duplicate_keys_rejected() {
        // Defence against a client smuggling a second `token=` past the
        // server's verification.
        let err = parse_strict(b"token=good&token=evil").expect_err("must reject");
        match err {
            FormError::DuplicateKey(k) => assert_eq!(k, "token"),
            other => panic!("expected DuplicateKey, got {other:?}"),
        }
    }

    #[test]
    fn invalid_utf8_rejected() {
        let err = parse_strict(&[0xFF, 0xFE]).expect_err("must reject");
        assert!(matches!(err, FormError::InvalidUtf8));
    }

    #[test]
    fn malformed_percent_rejected() {
        // `%Z!` is not a valid percent-escape — percent-decode treats it
        // as bytes, then UTF-8 decode fails.
        let err = parse_strict(b"q=%FF%FE").expect_err("must reject");
        assert!(matches!(err, FormError::Malformed));
    }
}

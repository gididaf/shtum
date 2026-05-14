use base64::Engine;
use percent_encoding::{NON_ALPHANUMERIC, percent_encode};

const REDACTED: &[u8] = b"[REDACTED]";

/// Streaming byte filter that scrubs known secret values out of subprocess
/// output. Three variants are generated per secret: the literal bytes,
/// a conservative URL-encoded form (every non-alphanumeric byte percent-
/// encoded), and a standard base64 encoding of the literal. Matches are
/// replaced with `[REDACTED]`.
///
/// The filter holds back the trailing `max_variant_len - 1` bytes of each
/// chunk so a secret split across read boundaries still matches; `flush()`
/// drains that tail at EOF.
pub struct Filter {
    variants: Vec<Vec<u8>>, // sorted longest-first for greedy matching
    max_len: usize,
    buffer: Vec<u8>,
    head: usize,
}

impl Filter {
    pub fn new(secrets: &[Vec<u8>]) -> Self {
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
        let max_len = variants.first().map(|v| v.len()).unwrap_or(0);
        Self {
            variants,
            max_len,
            buffer: Vec::new(),
            head: 0,
        }
    }

    pub fn is_noop(&self) -> bool {
        self.variants.is_empty()
    }

    /// Feed a chunk of bytes; returns the redacted bytes safe to emit now.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        if self.is_noop() {
            return chunk.to_vec();
        }
        self.buffer.extend_from_slice(chunk);
        let mut out = Vec::with_capacity(chunk.len());
        // Position `p` is decidable once buffer extends through p + max_len - 1.
        while self.head + self.max_len <= self.buffer.len() {
            if let Some(len) = self.match_at(self.head) {
                out.extend_from_slice(REDACTED);
                self.head += len;
            } else {
                out.push(self.buffer[self.head]);
                self.head += 1;
            }
        }
        self.compact();
        out
    }

    /// Drain the remaining buffered tail at EOF.
    pub fn flush(&mut self) -> Vec<u8> {
        if self.is_noop() {
            let out = self.buffer[self.head..].to_vec();
            self.buffer.clear();
            self.head = 0;
            return out;
        }
        let mut out = Vec::with_capacity(self.buffer.len() - self.head);
        while self.head < self.buffer.len() {
            if let Some(len) = self.match_at(self.head) {
                out.extend_from_slice(REDACTED);
                self.head += len;
            } else {
                out.push(self.buffer[self.head]);
                self.head += 1;
            }
        }
        self.buffer.clear();
        self.head = 0;
        out
    }

    fn match_at(&self, pos: usize) -> Option<usize> {
        for v in &self.variants {
            let end = pos + v.len();
            if end <= self.buffer.len() && &self.buffer[pos..end] == v.as_slice() {
                return Some(v.len());
            }
        }
        None
    }

    fn compact(&mut self) {
        if self.head >= 4096 {
            self.buffer.drain(..self.head);
            self.head = 0;
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

    fn run(secrets: &[&[u8]], chunks: &[&[u8]]) -> Vec<u8> {
        let owned: Vec<Vec<u8>> = secrets.iter().map(|s| s.to_vec()).collect();
        let mut f = Filter::new(&owned);
        let mut out = Vec::new();
        for c in chunks {
            out.extend(f.push(c));
        }
        out.extend(f.flush());
        out
    }

    #[test]
    fn literal_redacted() {
        let out = run(&[b"supersecret-xyz"], &[b"response: supersecret-xyz returned\n"]);
        assert_eq!(out, b"response: [REDACTED] returned\n");
    }

    #[test]
    fn split_across_chunks() {
        let out = run(&[b"supersecret-xyz"], &[b"super", b"secret-xyz\n"]);
        assert_eq!(out, b"[REDACTED]\n");
    }

    #[test]
    fn url_encoded_match() {
        let out = run(&[b"a/b+c"], &[b"encoded: a%2Fb%2Bc\n"]);
        assert_eq!(out, b"encoded: [REDACTED]\n");
    }

    #[test]
    fn base64_match() {
        let out = run(&[b"supersecret-xyz"], &[b"c3VwZXJzZWNyZXQteHl6\n"]);
        assert_eq!(out, b"[REDACTED]\n");
    }

    #[test]
    fn no_secrets_passes_through() {
        let out = run(&[], &[b"hello world\n"]);
        assert_eq!(out, b"hello world\n");
    }

    #[test]
    fn back_to_back_matches() {
        let out = run(&[b"abc"], &[b"abcabc\n"]);
        assert_eq!(out, b"[REDACTED][REDACTED]\n");
    }

    #[test]
    fn partial_no_match_at_eof() {
        // Buffer tail "sup" is shorter than the secret; should pass through unchanged on flush.
        let out = run(&[b"supersecret"], &[b"prefix sup"]);
        assert_eq!(out, b"prefix sup");
    }

    #[test]
    fn longer_variant_preferred() {
        // Two secrets where one is a prefix of the other: longer should win.
        let out = run(&[b"abc", b"abcdef"], &[b"abcdef\n"]);
        assert_eq!(out, b"[REDACTED]\n");
    }
}

use anyhow::{Context, Result, anyhow, bail};
use regex::Regex;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::OnceLock;

use crate::store::{SecretStore, StoreError};

/// Where to look up a placeholder's value.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PlaceholderSource {
    /// `{NAME}` — default store (Keychain), with env-var fallback.
    Default(String),
    /// `{kc:NAME}` — Keychain only; no fallback.
    Keychain(String),
    /// `{env:NAME}` — environment variable; no fallback.
    Env(String),
    /// `{file:PATH}` — file content (one trailing newline trimmed); no fallback.
    File(PathBuf),
}

impl PlaceholderSource {
    pub fn display(&self) -> String {
        match self {
            Self::Default(n) => n.clone(),
            Self::Keychain(n) => format!("kc:{n}"),
            Self::Env(n) => format!("env:{n}"),
            Self::File(p) => format!("file:{}", p.display()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PlaceholderRef {
    /// Original placeholder text including braces, e.g. `{CF_TOKEN}`.
    pub raw: String,
    pub source: PlaceholderSource,
}

#[derive(Debug)]
pub enum Segment {
    Literal(String),
    Placeholder(PlaceholderRef),
}

fn placeholder_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\{([^{}]*)\}").unwrap())
}

fn classify(inner: &str) -> Option<PlaceholderSource> {
    if let Some(rest) = inner.strip_prefix("kc:") {
        return is_valid_name(rest).then(|| PlaceholderSource::Keychain(rest.to_string()));
    }
    if let Some(rest) = inner.strip_prefix("env:") {
        return is_valid_name(rest).then(|| PlaceholderSource::Env(rest.to_string()));
    }
    if let Some(rest) = inner.strip_prefix("file:") {
        return (!rest.is_empty()).then(|| PlaceholderSource::File(PathBuf::from(rest)));
    }
    is_valid_name(inner).then(|| PlaceholderSource::Default(inner.to_string()))
}

fn is_valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

/// Parse a single argv string into a sequence of literal and placeholder segments.
/// Non-placeholder `{...}` content (e.g. JSON literals) is preserved as literal text.
pub fn parse_arg(s: &str) -> Vec<Segment> {
    let re = placeholder_regex();
    let mut out = Vec::new();
    let mut cursor = 0;
    for m in re.captures_iter(s) {
        let whole = m.get(0).unwrap();
        let inner = m.get(1).unwrap().as_str();
        let Some(source) = classify(inner) else {
            continue;
        };
        if whole.start() > cursor {
            out.push(Segment::Literal(s[cursor..whole.start()].to_string()));
        }
        out.push(Segment::Placeholder(PlaceholderRef {
            raw: whole.as_str().to_string(),
            source,
        }));
        cursor = whole.end();
    }
    if cursor < s.len() {
        out.push(Segment::Literal(s[cursor..].to_string()));
    }
    if out.is_empty() {
        out.push(Segment::Literal(String::new()));
    }
    out
}

/// Resolved execution plan: the argv to exec, with placeholder values
/// substituted in place. Values are bytes (not String) so binary-safe secrets
/// can flow through unchanged.
pub struct Plan {
    pub argv: Vec<Vec<u8>>,
}

pub fn build_plan(argv: &[String], store: &dyn SecretStore) -> Result<Plan> {
    if argv.is_empty() {
        bail!("no command specified after `--`");
    }
    let parsed: Vec<Vec<Segment>> = argv.iter().map(|a| parse_arg(a)).collect();

    let mut values: BTreeMap<PlaceholderSource, Vec<u8>> = BTreeMap::new();
    for arg in &parsed {
        for seg in arg {
            if let Segment::Placeholder(p) = seg {
                if !values.contains_key(&p.source) {
                    let value = resolve(&p.source, store).with_context(|| {
                        format!("resolving placeholder `{}`", p.source.display())
                    })?;
                    values.insert(p.source.clone(), value);
                }
            }
        }
    }

    let mut out_argv: Vec<Vec<u8>> = Vec::with_capacity(parsed.len());
    for arg in &parsed {
        let mut bytes = Vec::new();
        for seg in arg {
            match seg {
                Segment::Literal(s) => bytes.extend_from_slice(s.as_bytes()),
                Segment::Placeholder(p) => bytes.extend_from_slice(&values[&p.source]),
            }
        }
        out_argv.push(bytes);
    }

    Ok(Plan { argv: out_argv })
}

/// For dry-run display: rebuild each argv string with placeholders replaced
/// by `[REDACTED:<raw>]` markers, never touching real secret values.
pub fn format_masked(argv: &[String]) -> Vec<String> {
    argv.iter()
        .map(|a| {
            let segs = parse_arg(a);
            let mut out = String::new();
            for seg in segs {
                match seg {
                    Segment::Literal(s) => out.push_str(&s),
                    Segment::Placeholder(p) => {
                        out.push_str("[REDACTED:");
                        out.push_str(&p.raw);
                        out.push(']');
                    }
                }
            }
            out
        })
        .collect()
}

pub fn resolve(source: &PlaceholderSource, store: &dyn SecretStore) -> Result<Vec<u8>> {
    match source {
        PlaceholderSource::Default(name) => match store.get(name) {
            Ok(v) => Ok(v),
            Err(StoreError::NotFound(_)) => std::env::var(name)
                .map(String::into_bytes)
                .map_err(|_| anyhow!("`{name}` not in default store and not set as env var")),
            Err(e) => Err(e.into()),
        },
        PlaceholderSource::Keychain(name) => store.get(name).map_err(Into::into),
        PlaceholderSource::Env(name) => std::env::var(name)
            .map(String::into_bytes)
            .map_err(|_| anyhow!("env var `{name}` not set")),
        PlaceholderSource::File(path) => {
            let bytes =
                std::fs::read(path).with_context(|| format!("reading `{}`", path.display()))?;
            Ok(strip_trailing_newline(&bytes).to_vec())
        }
    }
}

fn strip_trailing_newline(b: &[u8]) -> &[u8] {
    let mut end = b.len();
    if end > 0 && b[end - 1] == b'\n' {
        end -= 1;
        if end > 0 && b[end - 1] == b'\r' {
            end -= 1;
        }
    }
    &b[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn placeholders(segs: &[Segment]) -> Vec<&PlaceholderRef> {
        segs.iter()
            .filter_map(|s| {
                if let Segment::Placeholder(p) = s {
                    Some(p)
                } else {
                    None
                }
            })
            .collect()
    }

    #[test]
    fn bare_name_parses() {
        let segs = parse_arg("token={CF_TOKEN} ok");
        let ps = placeholders(&segs);
        assert_eq!(ps.len(), 1);
        assert!(matches!(ps[0].source, PlaceholderSource::Default(ref n) if n == "CF_TOKEN"));
    }

    #[test]
    fn prefixes_parse() {
        let segs = parse_arg("{kc:FOO} {env:BAR} {file:/tmp/x}");
        let ps = placeholders(&segs);
        assert_eq!(ps.len(), 3);
        assert!(matches!(ps[0].source, PlaceholderSource::Keychain(_)));
        assert!(matches!(ps[1].source, PlaceholderSource::Env(_)));
        assert!(matches!(ps[2].source, PlaceholderSource::File(_)));
    }

    #[test]
    fn json_braces_ignored() {
        let segs = parse_arg(r#"{"foo": "bar"}"#);
        assert!(placeholders(&segs).is_empty());
    }

    #[test]
    fn unknown_prefix_ignored() {
        let segs = parse_arg("{nope:thing}");
        assert!(placeholders(&segs).is_empty());
    }

    #[test]
    fn format_masked_replaces_placeholders() {
        let masked = format_masked(&[
            "echo".to_string(),
            "token={CF_TOKEN}".to_string(),
            "{env:HOME}".to_string(),
        ]);
        assert_eq!(masked[0], "echo");
        assert_eq!(masked[1], "token=[REDACTED:{CF_TOKEN}]");
        assert_eq!(masked[2], "[REDACTED:{env:HOME}]");
    }
}

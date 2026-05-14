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
    /// Human-readable form used in error messages and dry-run output.
    pub fn display(&self) -> String {
        match self {
            Self::Default(n) => n.clone(),
            Self::Keychain(n) => format!("kc:{n}"),
            Self::Env(n) => format!("env:{n}"),
            Self::File(p) => format!("file:{}", p.display()),
        }
    }

    fn var_basename(&self) -> String {
        match self {
            Self::Default(n) | Self::Keychain(n) => sanitize(n),
            Self::Env(n) => format!("ENV_{}", sanitize(n)),
            Self::File(_) => "FILE".to_string(),
        }
    }
}

fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
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
        if is_valid_name(rest) {
            return Some(PlaceholderSource::Keychain(rest.to_string()));
        }
        return None;
    }
    if let Some(rest) = inner.strip_prefix("env:") {
        if is_valid_name(rest) {
            return Some(PlaceholderSource::Env(rest.to_string()));
        }
        return None;
    }
    if let Some(rest) = inner.strip_prefix("file:") {
        if !rest.is_empty() {
            return Some(PlaceholderSource::File(PathBuf::from(rest)));
        }
        return None;
    }
    if is_valid_name(inner) {
        return Some(PlaceholderSource::Default(inner.to_string()));
    }
    None
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

/// Fully-baked execution plan: the `sh -c` command line, the env vars to set,
/// and a mapping from var name to a representative placeholder ref (for dry-run).
pub struct Plan {
    pub shell_cmd: String,
    pub env: Vec<(String, Vec<u8>)>,
    pub var_refs: Vec<(String, PlaceholderRef)>,
}

pub fn build_plan(argv: &[String], store: &dyn SecretStore) -> Result<Plan> {
    if argv.is_empty() {
        bail!("no command specified after `--`");
    }
    let parsed: Vec<Vec<Segment>> = argv.iter().map(|a| parse_arg(a)).collect();

    let mut sources_in_order: Vec<PlaceholderSource> = Vec::new();
    let mut representative: BTreeMap<PlaceholderSource, PlaceholderRef> = BTreeMap::new();
    for arg in &parsed {
        for seg in arg {
            if let Segment::Placeholder(p) = seg {
                if !representative.contains_key(&p.source) {
                    sources_in_order.push(p.source.clone());
                    representative.insert(p.source.clone(), p.clone());
                }
            }
        }
    }

    let mut var_for: BTreeMap<PlaceholderSource, String> = BTreeMap::new();
    let mut used: Vec<String> = Vec::new();
    for source in &sources_in_order {
        let base = source.var_basename();
        let mut candidate = format!("__SHTUM_{base}");
        let mut suffix = 1;
        while used.contains(&candidate) {
            suffix += 1;
            candidate = format!("__SHTUM_{base}_{suffix}");
        }
        used.push(candidate.clone());
        var_for.insert(source.clone(), candidate);
    }

    let mut tokens = Vec::with_capacity(parsed.len());
    for segs in &parsed {
        tokens.push(quote_token(segs, &var_for));
    }
    let shell_cmd = tokens.join(" ");

    let mut env: Vec<(String, Vec<u8>)> = Vec::new();
    let mut var_refs: Vec<(String, PlaceholderRef)> = Vec::new();
    for source in &sources_in_order {
        let var = var_for[source].clone();
        let value = resolve(source, store)
            .with_context(|| format!("resolving placeholder `{}`", source.display()))?;
        env.push((var.clone(), value));
        var_refs.push((var, representative[source].clone()));
    }

    Ok(Plan {
        shell_cmd,
        env,
        var_refs,
    })
}

fn quote_token(segments: &[Segment], var_for: &BTreeMap<PlaceholderSource, String>) -> String {
    let mut out = String::new();
    for seg in segments {
        match seg {
            Segment::Literal(s) => {
                if !s.is_empty() {
                    out.push_str(&shell_escape_literal(s));
                }
            }
            Segment::Placeholder(p) => {
                let var = &var_for[&p.source];
                out.push('"');
                out.push('$');
                out.push('{');
                out.push_str(var);
                out.push('}');
                out.push('"');
            }
        }
    }
    if out.is_empty() {
        out.push_str("''");
    }
    out
}

fn shell_escape_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
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
    fn shell_escape_single_quote() {
        assert_eq!(shell_escape_literal("hello"), "'hello'");
        assert_eq!(shell_escape_literal("it's"), "'it'\\''s'");
    }

    #[test]
    fn quote_token_mixed_segments() {
        let mut var_for = BTreeMap::new();
        var_for.insert(
            PlaceholderSource::Default("T".into()),
            "__SHTUM_T".to_string(),
        );
        let segs = parse_arg("pre {T} post");
        let out = quote_token(&segs, &var_for);
        assert_eq!(out, r#"'pre '"${__SHTUM_T}"' post'"#);
    }
}

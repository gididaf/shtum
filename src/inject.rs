// Copyright 2026 Gidi Dafner
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result, anyhow, bail};
use regex::Regex;
use std::collections::BTreeMap;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::OnceLock;

use crate::store::{SecretStore, StoreError};
use crate::temp::TempTouch;
use crate::tempfile::TempFileGuard;

/// How the resolved value reaches the subprocess.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Default: literal byte substitution into the argv string.
    Argv,
    /// `{argv:NAME}` — explicit argv substitution; prints a stderr warning.
    ArgvExplicit,
    /// `{env-inject:NAME}` — directive: set `NAME=<value>` in subprocess env,
    /// strip the placeholder argv slot. Must be a standalone argv element.
    EnvInject,
    /// `{stdin:NAME}` — directive: pipe `<value>` to subprocess stdin, strip
    /// the placeholder argv slot. Must be a standalone argv element. At most
    /// one per command.
    Stdin,
    /// `{tempfile:NAME}` — inline: write value to a `0600` temp file and
    /// substitute the file path. Multiple refs to the same NAME share one
    /// file. RAII cleanup on normal exit.
    TempFile,
}

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
    fn name(&self) -> Option<&str> {
        match self {
            Self::Default(n) | Self::Keychain(n) | Self::Env(n) => Some(n),
            Self::File(_) => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PlaceholderRef {
    /// Original placeholder text including braces, e.g. `{CF_TOKEN}`.
    pub raw: String,
    pub source: PlaceholderSource,
    pub mode: Mode,
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

/// Returns (mode, source) for the contents of `{...}`, or None if the text
/// doesn't look like a valid placeholder (e.g. JSON braces).
fn classify(inner: &str) -> Option<(Mode, PlaceholderSource)> {
    // Source prefixes
    if let Some(rest) = inner.strip_prefix("kc:") {
        return is_valid_name(rest).then(|| (Mode::Argv, PlaceholderSource::Keychain(rest.to_string())));
    }
    if let Some(rest) = inner.strip_prefix("env:") {
        return is_valid_name(rest).then(|| (Mode::Argv, PlaceholderSource::Env(rest.to_string())));
    }
    if let Some(rest) = inner.strip_prefix("file:") {
        return (!rest.is_empty()).then(|| (Mode::Argv, PlaceholderSource::File(PathBuf::from(rest))));
    }
    // Mode prefixes (source is always Default for these)
    if let Some(rest) = inner.strip_prefix("argv:") {
        return is_valid_name(rest)
            .then(|| (Mode::ArgvExplicit, PlaceholderSource::Default(rest.to_string())));
    }
    if let Some(rest) = inner.strip_prefix("env-inject:") {
        return is_valid_name(rest)
            .then(|| (Mode::EnvInject, PlaceholderSource::Default(rest.to_string())));
    }
    if let Some(rest) = inner.strip_prefix("stdin:") {
        return is_valid_name(rest)
            .then(|| (Mode::Stdin, PlaceholderSource::Default(rest.to_string())));
    }
    if let Some(rest) = inner.strip_prefix("tempfile:") {
        return is_valid_name(rest)
            .then(|| (Mode::TempFile, PlaceholderSource::Default(rest.to_string())));
    }
    // Bare name = default store, default mode
    is_valid_name(inner).then(|| (Mode::Argv, PlaceholderSource::Default(inner.to_string())))
}

fn is_valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

/// Return true if `s` contains at least one valid shtum placeholder. Used
/// by the Claude Code hook to decide whether a Bash command needs to be
/// wrapped through `shtum run`. JSON literals like `{"foo": "bar"}` do not
/// count.
pub fn contains_placeholder(s: &str) -> bool {
    parse_arg(s)
        .iter()
        .any(|seg| matches!(seg, Segment::Placeholder(_)))
}

/// Parse a single argv string into a sequence of literal and placeholder
/// segments. Non-placeholder `{...}` content (e.g. JSON literals) is
/// preserved as literal text.
pub fn parse_arg(s: &str) -> Vec<Segment> {
    let re = placeholder_regex();
    let mut out = Vec::new();
    let mut cursor = 0;
    for m in re.captures_iter(s) {
        let whole = m.get(0).unwrap();
        let inner = m.get(1).unwrap().as_str();
        let Some((mode, source)) = classify(inner) else {
            continue;
        };
        if whole.start() > cursor {
            out.push(Segment::Literal(s[cursor..whole.start()].to_string()));
        }
        out.push(Segment::Placeholder(PlaceholderRef {
            raw: whole.as_str().to_string(),
            source,
            mode,
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

/// Fully resolved execution plan.
pub struct Plan {
    /// argv to exec, after substitution and after directive slots stripped.
    pub argv: Vec<Vec<u8>>,
    /// Raw resolved secret values (deduped), for the output redaction filter.
    pub secrets: Vec<Vec<u8>>,
    /// Env vars to set on the subprocess (from `{env-inject:NAME}`).
    pub env: Vec<(String, Vec<u8>)>,
    /// Bytes to pipe to subprocess stdin (from `{stdin:NAME}`). None = inherit
    /// parent stdin.
    pub stdin: Option<Vec<u8>>,
    /// Names that used `{argv:NAME}` mode; printed as a one-line stderr
    /// warning before exec.
    pub argv_warnings: Vec<String>,
    /// RAII guards for tempfiles created during plan build. Must outlive the
    /// subprocess; the exec layer holds the Plan across `wait()`.
    pub tempfiles: Vec<TempFileGuard>,
    /// Keychain names that `build_plan` already fetched (from
    /// `{NAME}`-style references). `enrich_with_store_secrets` skips these
    /// so the user doesn't get prompted twice for the same item.
    pub already_fetched_keychain_names: Vec<String>,
}

/// Build the execution plan for `shtum run`.
///
/// `temp_touch` is the idle-timer hook: when `Some`, names that resolved
/// against the Keychain (bare `{NAME}` or `{kc:NAME}`) are passed to
/// `TempTouch::touch_for_run` so the temp-key registry can bump their
/// `last_used_at`. `None` (used for dry-run) skips the bump — dry-run
/// is explicitly side-effect-free.
///
/// The bump happens AFTER successful resolution and BEFORE exec, so a
/// debugging loop where the wrapped command itself fails still counts
/// as "the user used this key" (the failure is in their command, not
/// in shtum's resolution).
pub fn build_plan(
    argv: &[String],
    store: &dyn SecretStore,
    temp_touch: Option<&dyn TempTouch>,
) -> Result<Plan> {
    if argv.is_empty() {
        bail!("no command specified after `--`");
    }
    let parsed: Vec<Vec<Segment>> = argv.iter().map(|a| parse_arg(a)).collect();

    // Validate directive placement before doing any IO.
    let mut stdin_count = 0;
    for (i, segs) in parsed.iter().enumerate() {
        for seg in segs {
            if let Segment::Placeholder(p) = seg {
                match p.mode {
                    Mode::EnvInject | Mode::Stdin => {
                        if segs.len() != 1 {
                            bail!(
                                "`{}` must be a standalone argv element, not embedded in `{}`",
                                p.raw,
                                argv[i]
                            );
                        }
                        if p.mode == Mode::Stdin {
                            stdin_count += 1;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    if stdin_count > 1 {
        bail!(
            "at most one `{{stdin:...}}` placeholder per command (found {stdin_count})"
        );
    }

    // Resolve unique sources once.
    let mut values: BTreeMap<PlaceholderSource, Vec<u8>> = BTreeMap::new();
    for segs in &parsed {
        for seg in segs {
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

    // Tempfile cache: one file per NAME, shared across multiple refs.
    let mut tempfile_paths: BTreeMap<String, PathBuf> = BTreeMap::new();
    let mut tempfiles: Vec<TempFileGuard> = Vec::new();

    let mut out_argv: Vec<Vec<u8>> = Vec::new();
    let mut env: Vec<(String, Vec<u8>)> = Vec::new();
    let mut stdin: Option<Vec<u8>> = None;
    let mut argv_warnings: Vec<String> = Vec::new();

    for segs in &parsed {
        // Directive arg? (whole arg = single env-inject or stdin placeholder)
        if segs.len() == 1 {
            if let Segment::Placeholder(p) = &segs[0] {
                match p.mode {
                    Mode::EnvInject => {
                        let name = p
                            .source
                            .name()
                            .expect("env-inject source has a name")
                            .to_string();
                        env.push((name, values[&p.source].clone()));
                        continue;
                    }
                    Mode::Stdin => {
                        stdin = Some(values[&p.source].clone());
                        continue;
                    }
                    _ => {}
                }
            }
        }

        // Otherwise: substitute into argv bytes.
        let mut bytes = Vec::new();
        for seg in segs {
            match seg {
                Segment::Literal(s) => bytes.extend_from_slice(s.as_bytes()),
                Segment::Placeholder(p) => match p.mode {
                    Mode::Argv => {
                        bytes.extend_from_slice(&values[&p.source]);
                    }
                    Mode::ArgvExplicit => {
                        if let Some(name) = p.source.name() {
                            if !argv_warnings.iter().any(|n| n == name) {
                                argv_warnings.push(name.to_string());
                            }
                        }
                        bytes.extend_from_slice(&values[&p.source]);
                    }
                    Mode::TempFile => {
                        let name = p
                            .source
                            .name()
                            .expect("tempfile source has a name")
                            .to_string();
                        let path = if let Some(p) = tempfile_paths.get(&name) {
                            p.clone()
                        } else {
                            let guard = TempFileGuard::create_with_value(
                                &name,
                                &values[&p.source],
                            )?;
                            let path = guard.path().to_path_buf();
                            tempfile_paths.insert(name, path.clone());
                            tempfiles.push(guard);
                            path
                        };
                        bytes.extend_from_slice(path.as_os_str().as_bytes());
                    }
                    Mode::EnvInject | Mode::Stdin => unreachable!(
                        "directive placeholder reached substitution path (should have been caught by validation)"
                    ),
                },
            }
        }
        out_argv.push(bytes);
    }

    if out_argv.is_empty() {
        bail!("no command remaining after stripping directive placeholders");
    }

    let mut already_fetched_keychain_names: Vec<String> = values
        .keys()
        .filter_map(|src| match src {
            PlaceholderSource::Default(n) | PlaceholderSource::Keychain(n) => Some(n.clone()),
            _ => None,
        })
        .collect();
    already_fetched_keychain_names.sort();
    already_fetched_keychain_names.dedup();

    // Bump idle timers on any of these names that are tracked as temp
    // keys in the registry. The registry silently ignores names it
    // doesn't track, so it's safe to pass non-temp Keychain names too.
    // {env:...} and {file:...} sources are intentionally NOT touched —
    // they don't correspond to Keychain entries, so they can't be temp.
    if let Some(touch) = temp_touch {
        if !already_fetched_keychain_names.is_empty() {
            let refs: Vec<&str> = already_fetched_keychain_names
                .iter()
                .map(|s| s.as_str())
                .collect();
            touch.touch_for_run(&refs);
        }
    }

    let mut secrets: Vec<Vec<u8>> = values.into_values().filter(|v| !v.is_empty()).collect();
    secrets.sort();
    secrets.dedup();

    Ok(Plan {
        argv: out_argv,
        secrets,
        env,
        stdin,
        argv_warnings,
        tempfiles,
        already_fetched_keychain_names,
    })
}

/// When at least one placeholder resolved, also fold every other stored
/// secret into the redaction set, so a forgotten `{NAME}` doesn't let a
/// stored value slip through. Skips names that `build_plan` already fetched
/// so the user isn't prompted twice by the Keychain ACL for the same item.
/// Failures to load individual entries print a warning but do not abort the
/// run.
pub fn enrich_with_store_secrets(plan: &mut Plan, store: &dyn SecretStore) -> Result<()> {
    let already: std::collections::BTreeSet<&str> = plan
        .already_fetched_keychain_names
        .iter()
        .map(|s| s.as_str())
        .collect();
    let names = store
        .list()
        .context("failed to enumerate stored secrets for redaction")?;
    for name in names {
        if already.contains(name.as_str()) {
            continue;
        }
        match store.get(&name) {
            Ok(v) if !v.is_empty() => plan.secrets.push(v),
            Ok(_) => {}
            Err(e) => eprintln!("shtum: could not load `{name}` for redaction: {e}"),
        }
    }
    plan.secrets.sort();
    plan.secrets.dedup();
    Ok(())
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
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    struct InjectMockStore {
        items: RefCell<BTreeMap<String, Vec<u8>>>,
    }
    impl InjectMockStore {
        fn seed(items: &[(&str, &[u8])]) -> Self {
            let map: BTreeMap<String, Vec<u8>> = items
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_vec()))
                .collect();
            Self {
                items: RefCell::new(map),
            }
        }
    }
    impl SecretStore for InjectMockStore {
        fn get(&self, name: &str) -> Result<Vec<u8>, StoreError> {
            self.items
                .borrow()
                .get(name)
                .cloned()
                .ok_or_else(|| StoreError::NotFound(name.to_string()))
        }
        fn set(&self, name: &str, value: &[u8]) -> Result<(), StoreError> {
            self.items
                .borrow_mut()
                .insert(name.to_string(), value.to_vec());
            Ok(())
        }
        fn delete(&self, name: &str) -> Result<(), StoreError> {
            self.items
                .borrow_mut()
                .remove(name)
                .map(|_| ())
                .ok_or_else(|| StoreError::NotFound(name.to_string()))
        }
        fn list(&self) -> Result<Vec<String>, StoreError> {
            Ok(self.items.borrow().keys().cloned().collect())
        }
    }

    /// Capturing TempTouch for asserting which names get bumped per call.
    struct MockTouch {
        calls: RefCell<Vec<Vec<String>>>,
    }
    impl MockTouch {
        fn new() -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
            }
        }
        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.borrow().clone()
        }
        fn total_names(&self) -> Vec<String> {
            self.calls.borrow().iter().flatten().cloned().collect()
        }
    }
    impl TempTouch for MockTouch {
        fn touch_for_run(&self, names: &[&str]) {
            self.calls
                .borrow_mut()
                .push(names.iter().map(|s| s.to_string()).collect());
        }
    }

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
        assert_eq!(ps[0].mode, Mode::Argv);
    }

    #[test]
    fn source_prefixes_parse() {
        let segs = parse_arg("{kc:FOO} {env:BAR} {file:/tmp/x}");
        let ps = placeholders(&segs);
        assert_eq!(ps.len(), 3);
        assert!(matches!(ps[0].source, PlaceholderSource::Keychain(_)));
        assert!(matches!(ps[1].source, PlaceholderSource::Env(_)));
        assert!(matches!(ps[2].source, PlaceholderSource::File(_)));
        assert!(ps.iter().all(|p| p.mode == Mode::Argv));
    }

    #[test]
    fn mode_prefixes_parse() {
        let segs = parse_arg("{argv:A} {env-inject:B} {stdin:C} {tempfile:D}");
        let ps = placeholders(&segs);
        assert_eq!(ps.len(), 4);
        assert_eq!(ps[0].mode, Mode::ArgvExplicit);
        assert_eq!(ps[1].mode, Mode::EnvInject);
        assert_eq!(ps[2].mode, Mode::Stdin);
        assert_eq!(ps[3].mode, Mode::TempFile);
        for p in &ps {
            assert!(matches!(p.source, PlaceholderSource::Default(_)));
        }
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
    fn touch_bumps_default_and_keychain_names_once_each() {
        let store = InjectMockStore::seed(&[
            ("FOO", b"foo-val"),
            ("BAR", b"bar-val"),
        ]);
        let touch = MockTouch::new();
        // Two refs to FOO (deduped), one to BAR via {kc:}, plus a literal.
        let argv = vec![
            "echo".to_string(),
            "first={FOO}".to_string(),
            "second={FOO}".to_string(),
            "third={kc:BAR}".to_string(),
        ];
        let _ = build_plan(&argv, &store, Some(&touch)).expect("plan should build");
        assert_eq!(touch.calls().len(), 1, "exactly one touch_for_run call");
        let mut names = touch.total_names();
        names.sort();
        assert_eq!(names, vec!["BAR".to_string(), "FOO".to_string()]);
    }

    #[test]
    fn touch_skips_env_and_file_sources() {
        let store = InjectMockStore::seed(&[]);
        let touch = MockTouch::new();
        // Set an env var so the {env:...} placeholder resolves.
        // SAFETY: this test process sets/unsets its own env vars.
        unsafe {
            std::env::set_var("INJECT_TEST_ENV_VAR", "hi");
        }
        // Create a file for {file:...}.
        let dir = std::env::temp_dir().join(format!(
            "shtum-inject-touch-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let fp = dir.join("v.txt");
        std::fs::write(&fp, b"file-val").unwrap();

        let argv = vec![
            "echo".to_string(),
            format!("env={{env:INJECT_TEST_ENV_VAR}}"),
            format!("file={{file:{}}}", fp.display()),
        ];
        let _ = build_plan(&argv, &store, Some(&touch)).expect("plan should build");
        // Neither env nor file sources should produce a touch call.
        assert!(
            touch.total_names().is_empty(),
            "env/file placeholders should not bump the idle timer; got: {:?}",
            touch.total_names()
        );
        unsafe {
            std::env::remove_var("INJECT_TEST_ENV_VAR");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn touch_skipped_when_no_keychain_names_resolve() {
        let store = InjectMockStore::seed(&[]);
        let touch = MockTouch::new();
        // No placeholders → nothing to touch.
        let argv = vec!["echo".to_string(), "hello".to_string()];
        let _ = build_plan(&argv, &store, Some(&touch)).expect("plan should build");
        assert!(touch.total_names().is_empty());
        assert!(touch.calls().is_empty(), "no Keychain names → no touch_for_run call");
    }

    #[test]
    fn touch_none_means_no_bump_dry_run_carve_out() {
        let store = InjectMockStore::seed(&[("FOO", b"v")]);
        // Passing None as the temp_touch — dry-run path's wiring.
        let _ = build_plan(
            &["echo".to_string(), "{FOO}".to_string()],
            &store,
            None,
        )
        .expect("plan should build");
        // No assertion needed on the touch (it's None); the contract is
        // that `build_plan` doesn't panic and doesn't reach into a
        // registry it wasn't given.
    }

    #[test]
    fn touch_called_even_when_value_falls_back_to_env() {
        // Default source `{FOO}` resolves via env when not in store. We
        // still pass the name to touch_for_run because it's cheap and the
        // registry's `touch_many` is a silent no-op for names it doesn't
        // track. The alternative (filter at inject) would couple inject
        // to registry state without a meaningful win.
        let store = InjectMockStore::seed(&[]);
        unsafe {
            std::env::set_var("INJECT_TEST_FALLBACK", "from-env");
        }
        let touch = MockTouch::new();
        let _ = build_plan(
            &["echo".to_string(), "{INJECT_TEST_FALLBACK}".to_string()],
            &store,
            Some(&touch),
        )
        .expect("plan should build");
        assert_eq!(
            touch.total_names(),
            vec!["INJECT_TEST_FALLBACK".to_string()],
            "default-source names go to touch_for_run regardless of where they actually resolved"
        );
        unsafe {
            std::env::remove_var("INJECT_TEST_FALLBACK");
        }
    }

    #[test]
    fn format_masked_replaces_placeholders() {
        let masked = format_masked(&[
            "echo".to_string(),
            "token={CF_TOKEN}".to_string(),
            "{env:HOME}".to_string(),
            "{env-inject:AWS}".to_string(),
        ]);
        assert_eq!(masked[0], "echo");
        assert_eq!(masked[1], "token=[REDACTED:{CF_TOKEN}]");
        assert_eq!(masked[2], "[REDACTED:{env:HOME}]");
        assert_eq!(masked[3], "[REDACTED:{env-inject:AWS}]");
    }
}

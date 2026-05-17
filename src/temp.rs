//! Temp-key registry — sidecar metadata for `TMP_*` keys created via
//! `shtum quick`. Tracks idle TTL (last_used_at + ttl_seconds); sweep
//! removes expired entries lazily at the start of `shtum run`, `shtum
//! store list`, and dashboard request handlers.
//!
//! The secret VALUE always lives in Keychain; this registry only holds
//! names and timestamps. Only registry-tracked names are sweep candidates
//! — a user who manually `shtum store add TMP_foo` is unaffected.
//!
//! Concurrency: register / touch_many / extend / sweep all serialize
//! through an exclusive `flock(2)` on a sibling `temp-keys.lock` file, so
//! two concurrent `shtum run` invocations cannot lose each other's
//! touches. Read-only snapshot() does not lock — slightly stale reads are
//! fine for rendering.
//!
//! Failure mode: corrupt JSON, unknown schema version, or unreadable file
//! all fail open (treat as empty registry, log to stderr). The next
//! successful write self-heals.

// register / touch_many / extend / snapshot / is_temp / TempEntry helpers
// are wired in by P9b (CLI), P9c (inject), and P9d (dashboard). They're
// already used by this module's tests in P9a. The blanket allow keeps
// `cargo check` quiet during the incremental rollout.
#![allow(dead_code)]

use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::store::{SecretStore, StoreError};
use crate::util::atomic_write_json;

/// Sidecar schema version. Bump on incompatible changes; readers fail open
/// on unknown versions so a downgrade after an upgrade can't lock anyone
/// out.
pub const SCHEMA_VERSION: u32 = 1;

/// Default idle TTL for `shtum quick` if `--ttl` is not passed: 4 hours.
pub const DEFAULT_TTL_SECONDS: u64 = 4 * 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TempEntry {
    pub name: String,
    pub created_at: u64,
    pub last_used_at: u64,
    pub ttl_seconds: u64,
}

impl TempEntry {
    pub fn expires_at(&self) -> u64 {
        self.last_used_at.saturating_add(self.ttl_seconds)
    }

    pub fn is_expired_at(&self, now: u64) -> bool {
        now >= self.expires_at()
    }
}

#[derive(Debug, Default)]
pub struct SweepReport {
    pub removed: Vec<String>,
    pub errored: Vec<(String, String)>,
}

pub struct TempRegistry {
    path: PathBuf,
}

impl TempRegistry {
    /// Open the registry at the default macOS location:
    /// `$HOME/Library/Application Support/shtum/temp-keys.json`. Does NOT
    /// create the file — load() tolerates a missing file as "empty".
    pub fn open_default() -> Result<Self> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .context("HOME not set; cannot locate Application Support dir")?;
        let dir = home
            .join("Library")
            .join("Application Support")
            .join("shtum");
        Ok(Self::at(dir.join("temp-keys.json")))
    }

    /// Open the registry at an explicit path. Used by tests.
    pub fn at(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read-only snapshot for rendering. Returns an empty list on any
    /// load failure (fail open).
    pub fn snapshot(&self) -> Vec<TempEntry> {
        self.load()
    }

    /// True iff `name` is currently tracked in the registry.
    pub fn is_temp(&self, name: &str) -> bool {
        self.load().iter().any(|e| e.name == name)
    }

    /// Insert or replace an entry for `name` with the given TTL and
    /// `last_used_at = now`. The Keychain entry must already exist —
    /// callers (currently only `shtum quick`) `store.add` first, then
    /// register here.
    pub fn register(&self, name: &str, ttl: Duration) -> Result<()> {
        let now = now_secs();
        let ttl_seconds = ttl.as_secs();
        self.with_write_lock(|reg| {
            let mut entries = reg.load();
            entries.retain(|e| e.name != name);
            entries.push(TempEntry {
                name: name.to_string(),
                created_at: now,
                last_used_at: now,
                ttl_seconds,
            });
            reg.save(&entries)
        })
    }

    /// Bump `last_used_at` to now for any names in `names` that are
    /// tracked in the registry. Names not in the registry are silently
    /// ignored (they're not temp keys). Returns the count of bumped
    /// entries. A zero-length input is a fast no-op.
    pub fn touch_many(&self, names: &[&str]) -> Result<usize> {
        if names.is_empty() {
            return Ok(0);
        }
        let now = now_secs();
        self.with_write_lock(|reg| {
            let mut entries = reg.load();
            let mut touched = 0usize;
            for e in entries.iter_mut() {
                if names.iter().any(|n| *n == e.name) {
                    e.last_used_at = now;
                    touched += 1;
                }
            }
            if touched > 0 {
                reg.save(&entries)?;
            }
            Ok(touched)
        })
    }

    /// Manual extension (dashboard "Extend" button). Returns true if the
    /// entry existed and was touched, false if `name` is not registered.
    pub fn extend(&self, name: &str) -> Result<bool> {
        Ok(self.touch_many(&[name])? > 0)
    }

    /// Remove expired entries from BOTH the registry and the underlying
    /// Keychain. Keychain `NotFound` is treated like `Ok` (the user
    /// removed it manually — still drop our orphan tracking row). Other
    /// backend errors keep the entry in the sidecar for next sweep.
    pub fn sweep<S: SecretStore + ?Sized>(&self, store: &S) -> SweepReport {
        let mut report = SweepReport::default();
        let now = now_secs();
        let _ = self.with_write_lock(|reg| {
            let entries = reg.load();
            let mut kept: Vec<TempEntry> = Vec::with_capacity(entries.len());
            let mut changed = false;
            for e in entries {
                if !e.is_expired_at(now) {
                    kept.push(e);
                    continue;
                }
                match store.delete(&e.name) {
                    Ok(()) | Err(StoreError::NotFound(_)) => {
                        report.removed.push(e.name.clone());
                        changed = true;
                    }
                    Err(other) => {
                        report.errored.push((e.name.clone(), other.to_string()));
                        kept.push(e);
                    }
                }
            }
            if changed {
                reg.save(&kept)?;
            }
            Ok(())
        });
        report
    }

    fn load(&self) -> Vec<TempEntry> {
        if !self.path.exists() {
            return Vec::new();
        }
        let raw = match fs::read_to_string(&self.path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "shtum: failed to read {} ({e}); treating temp-key registry as empty",
                    self.path.display()
                );
                return Vec::new();
            }
        };
        if raw.trim().is_empty() {
            return Vec::new();
        }
        let json: Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(e) => {
                eprintln!(
                    "shtum: temp-keys.json at {} is not valid JSON ({e}); treating as empty",
                    self.path.display()
                );
                return Vec::new();
            }
        };
        let version = json.get("version").and_then(|v| v.as_u64()).unwrap_or(0);
        if version != SCHEMA_VERSION as u64 {
            eprintln!(
                "shtum: temp-keys.json schema version {version} unsupported (expected {}); treating as empty",
                SCHEMA_VERSION
            );
            return Vec::new();
        }
        let Some(arr) = json.get("entries").and_then(|v| v.as_array()) else {
            return Vec::new();
        };
        arr.iter().filter_map(parse_entry).collect()
    }

    fn save(&self, entries: &[TempEntry]) -> Result<()> {
        let blob = json!({
            "version": SCHEMA_VERSION,
            "entries": entries
                .iter()
                .map(|e| json!({
                    "name": e.name,
                    "created_at": e.created_at,
                    "last_used_at": e.last_used_at,
                    "ttl_seconds": e.ttl_seconds,
                }))
                .collect::<Vec<_>>(),
        });
        atomic_write_json(&self.path, &blob)
    }

    fn with_write_lock<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Self) -> Result<T>,
    {
        let parent = self
            .path
            .parent()
            .context("temp registry path has no parent directory")?;
        fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
        // Stable sibling lockfile — never renamed, never deleted, so the
        // inode is stable across runs. flock'ing the data file itself
        // would race with the temp+rename pattern in atomic_write_json.
        let lock_path = parent.join("temp-keys.lock");
        let lock_file = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .truncate(false)
            .open(&lock_path)
            .with_context(|| format!("opening lockfile {}", lock_path.display()))?;
        lock_file
            .lock()
            .with_context(|| format!("acquiring exclusive lock on {}", lock_path.display()))?;
        let result = f(self);
        // Dropping releases the lock.
        drop(lock_file);
        result
    }
}

/// Narrow contract that `inject::build_plan` consumes to bump idle timers
/// on temp keys after their values have been resolved for a `shtum run`.
/// Lives behind a trait so tests can supply a capturing mock without
/// having to set up a real sidecar file. Errors are intentionally
/// swallowed in production: a touch failure should never break the
/// caller's command — at worst the key expires a few minutes earlier
/// than it would have.
pub trait TempTouch {
    fn touch_for_run(&self, names: &[&str]);
}

impl TempTouch for TempRegistry {
    fn touch_for_run(&self, names: &[&str]) {
        if let Err(e) = self.touch_many(names) {
            eprintln!(
                "shtum: failed to bump temp-key idle timer for {names:?}: {e}"
            );
        }
    }
}

/// Parse a `--ttl` value like `30m`, `2h`, `1d` into a `Duration`. Used as
/// a clap `value_parser`, so the return type uses `String` errors. Min 60s,
/// max 7d. Empty string and missing unit are rejected; everything else
/// maps to seconds via the unit suffix.
pub fn parse_ttl(s: &str) -> Result<Duration, String> {
    const SYNTAX_HINT: &str =
        "expected <N>{s,m,h,d}, e.g. 30m, 2h, 1d";
    let s = s.trim();
    if s.is_empty() {
        return Err(format!("--ttl is empty; {SYNTAX_HINT}"));
    }
    // Split off the trailing unit char.
    let unit = s
        .chars()
        .last()
        .ok_or_else(|| format!("--ttl is empty; {SYNTAX_HINT}"))?;
    let num_str = &s[..s.len() - unit.len_utf8()];
    if num_str.is_empty() {
        return Err(format!("invalid --ttl '{s}': missing number; {SYNTAX_HINT}"));
    }
    let n: u64 = num_str
        .parse()
        .map_err(|_| format!("invalid --ttl '{s}': '{num_str}' is not a positive integer; {SYNTAX_HINT}"))?;
    let mult: u64 = match unit {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => 86400,
        _ => return Err(format!("invalid --ttl '{s}': unknown unit '{unit}'; {SYNTAX_HINT}")),
    };
    let secs = n
        .checked_mul(mult)
        .ok_or_else(|| format!("--ttl '{s}' overflows; pick a smaller value"))?;
    const MIN: u64 = 60;
    const MAX: u64 = 7 * 86400;
    if secs < MIN {
        return Err(format!("--ttl too short: minimum is 60s ({secs}s requested)"));
    }
    if secs > MAX {
        return Err(format!("--ttl too long: maximum is 7d ({secs}s requested)"));
    }
    Ok(Duration::from_secs(secs))
}

/// Render a `Duration` as a compact unit string (`30m`, `4h`, `2d`) for the
/// stderr success note and dashboard countdown labels. Falls back to whole
/// seconds when no larger unit divides evenly.
pub fn format_duration_compact(d: Duration) -> String {
    let secs = d.as_secs();
    if secs == 0 {
        return "0s".to_string();
    }
    if secs % 86400 == 0 {
        return format!("{}d", secs / 86400);
    }
    if secs % 3600 == 0 {
        return format!("{}h", secs / 3600);
    }
    if secs % 60 == 0 {
        return format!("{}m", secs / 60);
    }
    format!("{}s", secs)
}

/// Generate a fresh `TMP_<6 chars>` name. Reads 6 bytes from `/dev/urandom`
/// and maps each to the 62-char alphabet `[A-Za-z0-9]` via modulo. The
/// modulo introduces a tiny bias, which is fine: the name is non-secret
/// and collisions are handled by the caller via `store.add(force=false)`
/// retry — uniqueness against the existing keyspace, not entropy, is the
/// goal.
pub fn generate_temp_name() -> Result<String> {
    const ALPHABET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut bytes = [0u8; 6];
    File::open("/dev/urandom")
        .context("opening /dev/urandom for temp-key name generator")?
        .read_exact(&mut bytes)
        .context("reading /dev/urandom for temp-key name generator")?;
    let suffix: String = bytes
        .iter()
        .map(|b| ALPHABET[(*b as usize) % ALPHABET.len()] as char)
        .collect();
    Ok(format!("TMP_{suffix}"))
}

fn parse_entry(v: &Value) -> Option<TempEntry> {
    let name = v.get("name")?.as_str()?.to_string();
    let created_at = v.get("created_at")?.as_u64()?;
    let last_used_at = v.get("last_used_at")?.as_u64()?;
    let ttl_seconds = v.get("ttl_seconds")?.as_u64()?;
    Some(TempEntry {
        name,
        created_at,
        last_used_at,
        ttl_seconds,
    })
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    fn tmpdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "shtum-temp-test-{}-{tag}-{}",
            std::process::id(),
            now_secs()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn reg_at(dir: &Path) -> TempRegistry {
        TempRegistry::at(dir.join("temp-keys.json"))
    }

    struct MockStore {
        items: RefCell<BTreeMap<String, Vec<u8>>>,
    }
    impl MockStore {
        fn new() -> Self {
            Self {
                items: RefCell::new(BTreeMap::new()),
            }
        }
        fn seed(items: &[(&str, &[u8])]) -> Self {
            let s = Self::new();
            for (k, v) in items {
                s.items.borrow_mut().insert(k.to_string(), v.to_vec());
            }
            s
        }
    }
    impl SecretStore for MockStore {
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

    #[test]
    fn snapshot_on_missing_file_is_empty() {
        let dir = tmpdir("missing");
        let reg = reg_at(&dir);
        assert!(reg.snapshot().is_empty());
        assert!(!reg.is_temp("anything"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn register_then_snapshot_roundtrips() {
        let dir = tmpdir("register");
        let reg = reg_at(&dir);
        reg.register("TMP_aaa111", Duration::from_secs(60)).unwrap();
        let entries = reg.snapshot();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "TMP_aaa111");
        assert_eq!(entries[0].ttl_seconds, 60);
        assert_eq!(entries[0].created_at, entries[0].last_used_at);
        assert!(reg.is_temp("TMP_aaa111"));
        assert!(!reg.is_temp("TMP_other"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn register_replaces_existing_entry_with_same_name() {
        let dir = tmpdir("replace");
        let reg = reg_at(&dir);
        reg.register("TMP_x", Duration::from_secs(60)).unwrap();
        let first = reg.snapshot()[0].clone();
        std::thread::sleep(Duration::from_millis(1100));
        reg.register("TMP_x", Duration::from_secs(120)).unwrap();
        let entries = reg.snapshot();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ttl_seconds, 120);
        assert!(entries[0].created_at >= first.created_at);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn touch_many_bumps_only_known_entries() {
        let dir = tmpdir("touch");
        let reg = reg_at(&dir);
        reg.register("TMP_a", Duration::from_secs(60)).unwrap();
        reg.register("TMP_b", Duration::from_secs(60)).unwrap();
        let before_a = reg.snapshot().into_iter().find(|e| e.name == "TMP_a").unwrap().last_used_at;
        std::thread::sleep(Duration::from_millis(1100));
        let n = reg.touch_many(&["TMP_a", "NOT_A_TEMP"]).unwrap();
        assert_eq!(n, 1);
        let after_a = reg.snapshot().into_iter().find(|e| e.name == "TMP_a").unwrap().last_used_at;
        let after_b = reg.snapshot().into_iter().find(|e| e.name == "TMP_b").unwrap().last_used_at;
        assert!(after_a > before_a, "TMP_a should have been bumped");
        // TMP_b was not in the touch set; its timestamp matches creation.
        assert!(after_b < after_a, "TMP_b should not have been bumped");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn touch_many_empty_input_is_no_op() {
        let dir = tmpdir("touch-empty");
        let reg = reg_at(&dir);
        reg.register("TMP_a", Duration::from_secs(60)).unwrap();
        assert_eq!(reg.touch_many(&[]).unwrap(), 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn extend_returns_false_for_unknown() {
        let dir = tmpdir("extend");
        let reg = reg_at(&dir);
        assert!(!reg.extend("NOT_THERE").unwrap());
        reg.register("TMP_a", Duration::from_secs(60)).unwrap();
        assert!(reg.extend("TMP_a").unwrap());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sweep_removes_expired_from_store_and_sidecar() {
        let dir = tmpdir("sweep");
        let store = MockStore::seed(&[
            ("TMP_expired", b"old"),
            ("TMP_fresh", b"new"),
            ("KEEP_ME", b"permanent"),
        ]);
        let reg = reg_at(&dir);
        // Hand-craft entries: one already-expired, one fresh.
        let now = now_secs();
        let blob = json!({
            "version": SCHEMA_VERSION,
            "entries": [
                { "name": "TMP_expired",
                  "created_at": now - 10_000,
                  "last_used_at": now - 10_000,
                  "ttl_seconds": 60 },
                { "name": "TMP_fresh",
                  "created_at": now,
                  "last_used_at": now,
                  "ttl_seconds": 3600 },
            ]
        });
        atomic_write_json(&reg.path, &blob).unwrap();

        let report = reg.sweep(&store);
        assert_eq!(report.removed, vec!["TMP_expired".to_string()]);
        assert!(report.errored.is_empty());

        // Keychain side: expired entry gone; fresh + permanent untouched.
        assert!(store.get("TMP_expired").is_err());
        assert_eq!(store.get("TMP_fresh").unwrap(), b"new");
        assert_eq!(store.get("KEEP_ME").unwrap(), b"permanent");

        // Sidecar side: expired entry pruned.
        let entries = reg.snapshot();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "TMP_fresh");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sweep_treats_keychain_notfound_as_success() {
        let dir = tmpdir("sweep-notfound");
        // Store has no TMP_x — user removed it manually behind our back.
        let store = MockStore::new();
        let reg = reg_at(&dir);
        let now = now_secs();
        let blob = json!({
            "version": SCHEMA_VERSION,
            "entries": [
                { "name": "TMP_x",
                  "created_at": now - 10_000,
                  "last_used_at": now - 10_000,
                  "ttl_seconds": 60 },
            ]
        });
        atomic_write_json(&reg.path, &blob).unwrap();
        let report = reg.sweep(&store);
        assert_eq!(report.removed, vec!["TMP_x".to_string()]);
        assert!(reg.snapshot().is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sweep_keeps_non_expired_untouched() {
        let dir = tmpdir("sweep-keep");
        let store = MockStore::seed(&[("TMP_a", b"v")]);
        let reg = reg_at(&dir);
        reg.register("TMP_a", Duration::from_secs(3600)).unwrap();
        let report = reg.sweep(&store);
        assert!(report.removed.is_empty());
        assert_eq!(reg.snapshot().len(), 1);
        assert_eq!(store.get("TMP_a").unwrap(), b"v");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_json_fails_open() {
        let dir = tmpdir("corrupt");
        let reg = reg_at(&dir);
        fs::write(&reg.path, "this is not json {{{").unwrap();
        assert!(reg.snapshot().is_empty());
        // And subsequent register self-heals.
        reg.register("TMP_after", Duration::from_secs(60)).unwrap();
        assert_eq!(reg.snapshot().len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_schema_version_fails_open() {
        let dir = tmpdir("schema");
        let reg = reg_at(&dir);
        let blob = json!({ "version": 99, "entries": [] });
        atomic_write_json(&reg.path, &blob).unwrap();
        assert!(reg.snapshot().is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_entries_field_is_treated_as_empty() {
        let dir = tmpdir("no-entries");
        let reg = reg_at(&dir);
        let blob = json!({ "version": SCHEMA_VERSION });
        atomic_write_json(&reg.path, &blob).unwrap();
        assert!(reg.snapshot().is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_ttl_accepts_canonical_units() {
        assert_eq!(parse_ttl("60s").unwrap(), Duration::from_secs(60));
        assert_eq!(parse_ttl("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_ttl("4h").unwrap(), Duration::from_secs(14_400));
        assert_eq!(parse_ttl("1d").unwrap(), Duration::from_secs(86_400));
        assert_eq!(parse_ttl("7d").unwrap(), Duration::from_secs(7 * 86_400));
    }

    #[test]
    fn parse_ttl_rejects_below_minimum() {
        let err = parse_ttl("30s").unwrap_err();
        assert!(err.contains("minimum"), "got: {err}");
        let err = parse_ttl("0m").unwrap_err();
        assert!(err.contains("minimum"), "got: {err}");
    }

    #[test]
    fn parse_ttl_rejects_above_maximum() {
        let err = parse_ttl("8d").unwrap_err();
        assert!(err.contains("maximum"), "got: {err}");
        let err = parse_ttl("999h").unwrap_err();
        assert!(err.contains("maximum"), "got: {err}");
    }

    #[test]
    fn parse_ttl_rejects_bad_syntax() {
        assert!(parse_ttl("").is_err());
        assert!(parse_ttl("5x").is_err());
        assert!(parse_ttl("abc").is_err());
        assert!(parse_ttl("m").is_err());
        assert!(parse_ttl("-5m").is_err());
        // Whitespace trimmed, then bad form.
        assert!(parse_ttl("  5x  ").is_err());
    }

    #[test]
    fn parse_ttl_trims_whitespace() {
        assert_eq!(parse_ttl("  5m  ").unwrap(), Duration::from_secs(300));
    }

    #[test]
    fn format_duration_compact_renders_largest_evenly_divisible_unit() {
        assert_eq!(format_duration_compact(Duration::from_secs(0)), "0s");
        assert_eq!(format_duration_compact(Duration::from_secs(30)), "30s");
        assert_eq!(format_duration_compact(Duration::from_secs(60)), "1m");
        assert_eq!(format_duration_compact(Duration::from_secs(90)), "90s");
        assert_eq!(format_duration_compact(Duration::from_secs(300)), "5m");
        assert_eq!(format_duration_compact(Duration::from_secs(3600)), "1h");
        assert_eq!(format_duration_compact(Duration::from_secs(3660)), "61m");
        assert_eq!(format_duration_compact(Duration::from_secs(86_400)), "1d");
        assert_eq!(format_duration_compact(Duration::from_secs(4 * 3600)), "4h");
    }

    #[test]
    fn generate_temp_name_shape() {
        let name = generate_temp_name().unwrap();
        assert!(name.starts_with("TMP_"), "got: {name}");
        assert_eq!(name.len(), 10, "expected TMP_ + 6 chars; got: {name}");
        let suffix = &name[4..];
        assert!(
            suffix.chars().all(|c| c.is_ascii_alphanumeric()),
            "suffix should be [A-Za-z0-9]+; got: {suffix}"
        );
    }

    #[test]
    fn generate_temp_name_changes_each_call() {
        // Astronomically unlikely to collide with 62^6 ~= 5.7e10 possibilities.
        let a = generate_temp_name().unwrap();
        let b = generate_temp_name().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn entry_with_missing_fields_is_skipped() {
        let dir = tmpdir("malformed-entry");
        let reg = reg_at(&dir);
        let blob = json!({
            "version": SCHEMA_VERSION,
            "entries": [
                { "name": "TMP_ok",
                  "created_at": 100u64,
                  "last_used_at": 100u64,
                  "ttl_seconds": 60u64 },
                { "name": "TMP_bad" },
            ]
        });
        atomic_write_json(&reg.path, &blob).unwrap();
        let entries = reg.snapshot();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "TMP_ok");
        let _ = fs::remove_dir_all(&dir);
    }
}

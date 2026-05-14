use anyhow::{Context, Result, bail};
use regex::Regex;
use serde_json::{Value, json};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::inject;
use crate::store::{SecretStore, default_store};
use crate::util::shtum_exe_path;

#[derive(Clone, Copy, Debug)]
pub enum Scope {
    Global,
    Project,
}

impl Scope {
    fn settings_path(&self) -> Result<PathBuf> {
        match self {
            Scope::Global => {
                let home = std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .context("HOME not set; cannot locate ~/.claude/settings.json")?;
                Ok(home.join(".claude").join("settings.json"))
            }
            Scope::Project => Ok(PathBuf::from(".claude").join("settings.json")),
        }
    }
}

/// Print the hook entry that `install` would add, without touching disk.
pub fn show() -> Result<()> {
    let entry = build_hook_entry()?;
    let blob = json!({
        "hooks": {
            "PreToolUse": [entry]
        }
    });
    println!("{}", serde_json::to_string_pretty(&blob)?);
    Ok(())
}

/// Merge the shtum hook entry into the target settings.json. Preserves any
/// unrelated hooks. Refuses if a shtum entry is already present unless
/// `force` is true.
pub fn install(scope: Scope, force: bool) -> Result<()> {
    let path = scope.settings_path()?;
    let mut settings = read_settings(&path)?;
    let new_entry = build_hook_entry()?;

    let hooks = settings
        .as_object_mut()
        .context("settings.json root is not a JSON object")?
        .entry("hooks")
        .or_insert_with(|| json!({}));
    let hooks_obj = hooks
        .as_object_mut()
        .context("settings.json `hooks` is not a JSON object")?;
    let pre_tool_use = hooks_obj
        .entry("PreToolUse")
        .or_insert_with(|| Value::Array(Vec::new()));
    let arr = pre_tool_use
        .as_array_mut()
        .context("settings.json `hooks.PreToolUse` is not an array")?;

    let existing = arr.iter().position(is_shtum_entry);
    if let Some(idx) = existing {
        if !force {
            bail!(
                "an existing shtum hook entry was found in {}. \
                 Run `shtum hook uninstall` first, or pass --force.",
                path.display()
            );
        }
        arr[idx] = new_entry;
    } else {
        arr.push(new_entry);
    }

    atomic_write_json(&path, &settings)?;
    eprintln!("installed shtum hook into {}", path.display());
    Ok(())
}

/// Remove the shtum hook entry. Leaves all other hooks intact.
pub fn uninstall(scope: Scope) -> Result<()> {
    let path = scope.settings_path()?;
    if !path.exists() {
        eprintln!("no settings file at {} — nothing to do", path.display());
        return Ok(());
    }
    let mut settings = read_settings(&path)?;

    let Some(hooks_obj) = settings
        .get_mut("hooks")
        .and_then(|v| v.as_object_mut())
    else {
        eprintln!("no `hooks` section in {} — nothing to do", path.display());
        return Ok(());
    };
    let Some(arr) = hooks_obj
        .get_mut("PreToolUse")
        .and_then(|v| v.as_array_mut())
    else {
        eprintln!(
            "no `hooks.PreToolUse` in {} — nothing to do",
            path.display()
        );
        return Ok(());
    };

    let before = arr.len();
    arr.retain(|e| !is_shtum_entry(e));
    let removed = before - arr.len();
    if removed == 0 {
        eprintln!("no shtum hook entry found in {}", path.display());
        return Ok(());
    }
    // Tidy up empty containers.
    if arr.is_empty() {
        hooks_obj.remove("PreToolUse");
    }
    if hooks_obj.is_empty() {
        settings
            .as_object_mut()
            .expect("root is object")
            .remove("hooks");
    }

    atomic_write_json(&path, &settings)?;
    eprintln!("removed shtum hook entry from {}", path.display());
    Ok(())
}

/// The PreToolUse interceptor. Reads the tool-call envelope from stdin,
/// emits a JSON decision on stdout (or nothing for pass-through). Never
/// blocks the caller on errors — defense in depth shouldn't break the
/// host. Returns the process exit code to use.
pub fn handle() -> Result<i32> {
    let mut raw = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut raw) {
        eprintln!("shtum hook: failed to read stdin: {e}");
        return Ok(0);
    }
    let envelope: Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("shtum hook: stdin was not valid JSON ({e}); passing through");
            return Ok(0);
        }
    };
    let tool_name = envelope
        .get("tool_name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if tool_name != "Bash" {
        return Ok(0);
    }
    let command = envelope
        .get("tool_input")
        .and_then(|v| v.get("command"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Loop guard — we wrote this string in a prior iteration.
    if looks_like_shtum_run(command) {
        return Ok(0);
    }

    // Placeholder branch — auto-wrap.
    if inject::contains_placeholder(command) {
        let exe = shtum_exe_path()?;
        let rewritten = format!("{exe} run -- {command}");
        let out = json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "updatedInput": {
                    "command": rewritten,
                }
            }
        });
        println!("{}", out);
        return Ok(0);
    }

    // Safety-net branch — looks authenticated but no placeholder.
    if let Some(matched) = match_safety_net(command) {
        let reason = build_deny_message(matched);
        let out = json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        });
        println!("{}", out);
        return Ok(0);
    }

    // Default: pass through.
    Ok(0)
}

fn looks_like_shtum_run(cmd: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Matches `shtum run` invoked either bare or with any path prefix (e.g.
    // `/usr/local/bin/shtum`, `./shtum`). The path prefix is anything
    // non-whitespace ending in `/`.
    let re = RE.get_or_init(|| Regex::new(r"^\s*(?:\S+/)?shtum\s+run\b").unwrap());
    re.is_match(cmd)
}

#[derive(Clone, Copy)]
struct SafetyNetMatch {
    /// Short label for the matched pattern, used in the deny header.
    label: &'static str,
    /// Tool-specific hint for the agent on how to rewrite the command.
    hint: &'static str,
}

/// Compiled-in safety-net patterns. Each pattern carries a label + a
/// tool-specific rewrite hint so the deny message tells the agent exactly
/// which placeholder to use.
fn match_safety_net(cmd: &str) -> Option<SafetyNetMatch> {
    static PATTERNS: OnceLock<Vec<(SafetyNetMatch, Regex)>> = OnceLock::new();
    let pats = PATTERNS.get_or_init(|| {
        let raw: &[(SafetyNetMatch, &str)] = &[
            (
                SafetyNetMatch {
                    label: "aws cli",
                    hint: "the aws CLI reads AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY from env. Append `{env-inject:AWS_ACCESS_KEY_ID} {env-inject:AWS_SECRET_ACCESS_KEY}` to your command (substitute the stored names you actually have).",
                },
                r"^\s*aws\b",
            ),
            (
                SafetyNetMatch {
                    label: "gh cli",
                    hint: "the gh CLI reads GH_TOKEN from env. Append `{env-inject:GH_TOKEN}` to your command.",
                },
                r"^\s*gh\b",
            ),
            (
                SafetyNetMatch {
                    label: "wrangler",
                    hint: "wrangler reads CLOUDFLARE_API_TOKEN from env. Append `{env-inject:CLOUDFLARE_API_TOKEN}` to your command.",
                },
                r"^\s*wrangler\b",
            ),
            (
                SafetyNetMatch {
                    label: "doppler",
                    hint: "doppler reads DOPPLER_TOKEN from env. Append `{env-inject:DOPPLER_TOKEN}` to your command.",
                },
                r"^\s*doppler\b",
            ),
            (
                SafetyNetMatch {
                    label: "kubectl",
                    hint: "kubectl reads KUBECONFIG from env (pointing at a kubeconfig file). If you have the kubeconfig stored, use `KUBECONFIG={tempfile:KUBECONFIG} kubectl ...` so the file is created at runtime and cleaned up.",
                },
                r"^\s*kubectl\b",
            ),
            (
                SafetyNetMatch {
                    label: "terraform",
                    hint: "terraform reads provider credentials from env (e.g. AWS_ACCESS_KEY_ID, TF_VAR_*). Append the relevant `{env-inject:NAME}` directives.",
                },
                r"^\s*terraform\b",
            ),
            (
                SafetyNetMatch {
                    label: "psql",
                    hint: "psql reads PGPASSWORD from env. Append `{env-inject:PGPASSWORD}` to your command.",
                },
                r"^\s*psql\b",
            ),
            (
                SafetyNetMatch {
                    label: "mysql",
                    hint: "mysql reads MYSQL_PWD from env. Append `{env-inject:MYSQL_PWD}` to your command.",
                },
                r"^\s*mysql\b",
            ),
            (
                SafetyNetMatch {
                    label: "Cloudflare API",
                    hint: "use `curl -H 'Authorization: Bearer {CF_API_TOKEN}' ...` (substitute your stored token name).",
                },
                r"\b(curl|wget)\b.*\bapi\.cloudflare\.com\b",
            ),
            (
                SafetyNetMatch {
                    label: "OpenAI API",
                    hint: "use `curl -H 'Authorization: Bearer {OPENAI_API_KEY}' ...` (substitute your stored token name).",
                },
                r"\b(curl|wget)\b.*\bapi\.openai\.com\b",
            ),
            (
                SafetyNetMatch {
                    label: "GitHub API",
                    hint: "use `curl -H 'Authorization: Bearer {GH_TOKEN}' ...` (substitute your stored token name).",
                },
                r"\b(curl|wget)\b.*\bapi\.github\.com\b",
            ),
            (
                SafetyNetMatch {
                    label: "AWS API",
                    hint: "AWS API calls usually need a signed request. Easier: install the aws CLI and use `aws ... {env-inject:AWS_ACCESS_KEY_ID} {env-inject:AWS_SECRET_ACCESS_KEY}`.",
                },
                r"\b(curl|wget)\b.*\.amazonaws\.com\b",
            ),
        ];
        raw.iter()
            .filter_map(|(m, p)| Regex::new(p).ok().map(|re| (*m, re)))
            .collect()
    });
    pats.iter()
        .find(|(_, re)| re.is_match(cmd))
        .map(|(m, _)| *m)
}

/// Build the human-readable deny message. Includes the matched-tool hint,
/// the absolute path to shtum so the agent can invoke it explicitly, and
/// (best-effort) the list of currently-stored secret names so the agent
/// can pick the right one without a separate `shtum store list` call.
fn build_deny_message(m: SafetyNetMatch) -> String {
    let mut msg = format!(
        "shtum blocked this command: it looks like a call to {} but no `{{NAME}}` placeholder is present.\n\nHint: {}",
        m.label, m.hint
    );

    // Try to enumerate available stored secrets so the agent can pick a
    // valid name without making a follow-up call. Names are not secrets;
    // values stay in Keychain. Failures here are non-fatal.
    let store = default_store();
    match store.list() {
        Ok(names) if !names.is_empty() => {
            msg.push_str("\n\nAvailable stored secrets:");
            for n in names.iter().take(20) {
                msg.push_str(&format!("\n  - {n}"));
            }
            if names.len() > 20 {
                msg.push_str(&format!("\n  ... and {} more", names.len() - 20));
            }
        }
        Ok(_) => {
            msg.push_str("\n\nNo secrets are stored yet. Add one with `shtum store add NAME`.");
        }
        Err(_) => {
            // Don't surface the error to the agent; just omit the list.
        }
    }

    if let Ok(exe) = shtum_exe_path() {
        msg.push_str(&format!(
            "\n\n(shtum binary: {exe})"
        ));
    }
    msg
}

fn build_hook_entry() -> Result<Value> {
    let exe_str = shtum_exe_path()?;
    Ok(json!({
        "matcher": "Bash",
        "hooks": [
            {
                "type": "command",
                "command": exe_str,
                "args": ["hook", "handle"],
            }
        ]
    }))
}

fn is_shtum_entry(entry: &Value) -> bool {
    if entry.get("matcher").and_then(|v| v.as_str()) != Some("Bash") {
        return false;
    }
    let Some(hooks) = entry.get("hooks").and_then(|v| v.as_array()) else {
        return false;
    };
    hooks.iter().any(|h| {
        let args = h
            .get("args")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        args == ["hook", "handle"]
    })
}

fn read_settings(path: &Path) -> Result<Value> {
    if !path.exists() {
        return Ok(json!({}));
    }
    let raw = fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    if raw.trim().is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_str(&raw)
        .with_context(|| format!("parsing {} as JSON", path.display()))
}

fn atomic_write_json(path: &Path, value: &Value) -> Result<()> {
    let parent = path
        .parent()
        .context("settings path has no parent directory")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("creating {}", parent.display()))?;
    let file_name = path
        .file_name()
        .context("settings path has no file name")?
        .to_string_lossy()
        .into_owned();
    let tmp = parent.join(format!(".{file_name}.shtum.tmp"));
    let json = serde_json::to_string_pretty(value)?;
    {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        f.write_all(json.as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loop_guard_matches_shtum_run_variants() {
        assert!(looks_like_shtum_run("shtum run -- echo hi"));
        assert!(looks_like_shtum_run("  shtum run -- echo hi"));
        assert!(looks_like_shtum_run("shtum  run  --  echo hi"));
        // Absolute path (what the hook now emits in rewrites).
        assert!(looks_like_shtum_run("/usr/local/bin/shtum run -- foo"));
        assert!(looks_like_shtum_run(
            "/Users/x/Documents/Code/utilities/shtum/target/release/shtum run -- foo"
        ));
        assert!(looks_like_shtum_run("./shtum run -- foo"));
    }

    #[test]
    fn loop_guard_does_not_match_random_commands() {
        assert!(!looks_like_shtum_run("echo hi"));
        assert!(!looks_like_shtum_run("ls"));
        assert!(!looks_like_shtum_run("# shtum run -- not the start"));
    }

    #[test]
    fn safety_net_catches_aws_cli() {
        assert_eq!(match_safety_net("aws s3 ls").map(|m| m.label), Some("aws cli"));
        assert_eq!(
            match_safety_net("  aws --profile p s3 ls").map(|m| m.label),
            Some("aws cli"),
        );
    }

    #[test]
    fn safety_net_catches_curl_to_known_host() {
        assert_eq!(
            match_safety_net("curl https://api.cloudflare.com/client/v4/zones").map(|m| m.label),
            Some("Cloudflare API"),
        );
        assert_eq!(
            match_safety_net("curl -X POST https://api.openai.com/v1/chat/completions").map(|m| m.label),
            Some("OpenAI API"),
        );
    }

    #[test]
    fn safety_net_ignores_innocuous_commands() {
        assert!(match_safety_net("ls").is_none());
        assert!(match_safety_net("cat foo.txt").is_none());
        assert!(match_safety_net("git status").is_none());
        assert!(match_safety_net("npm install").is_none());
    }

    #[test]
    fn aws_hint_mentions_env_inject() {
        let m = match_safety_net("aws s3 ls").unwrap();
        assert!(m.hint.contains("env-inject"), "aws hint should reference env-inject; got: {}", m.hint);
        assert!(m.hint.contains("AWS_ACCESS_KEY_ID"));
    }

    #[test]
    fn is_shtum_entry_matches_only_our_shape() {
        let ours = json!({
            "matcher": "Bash",
            "hooks": [{ "type": "command", "command": "/x/shtum", "args": ["hook", "handle"] }]
        });
        assert!(is_shtum_entry(&ours));

        let other = json!({
            "matcher": "Bash",
            "hooks": [{ "type": "command", "command": "/x/other-tool" }]
        });
        assert!(!is_shtum_entry(&other));

        let edit_tool = json!({
            "matcher": "Edit",
            "hooks": [{ "type": "command", "command": "/x/shtum", "args": ["hook", "handle"] }]
        });
        assert!(!is_shtum_entry(&edit_tool));
    }

    #[test]
    fn install_and_uninstall_round_trip() {
        let dir = std::env::temp_dir().join(format!("shtum-hook-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("settings.json");
        fs::write(&path, r#"{"otherKey": 42, "hooks": {"PreToolUse": [{"matcher": "Edit", "hooks": [{"type": "command", "command": "/x/already-here"}]}]}}"#).unwrap();

        let mut settings = read_settings(&path).unwrap();
        let entry = build_hook_entry().unwrap();
        {
            let arr = settings
                .pointer_mut("/hooks/PreToolUse")
                .unwrap()
                .as_array_mut()
                .unwrap();
            arr.push(entry);
        }
        atomic_write_json(&path, &settings).unwrap();

        let after_install = read_settings(&path).unwrap();
        assert_eq!(after_install["otherKey"], 42);
        let arr = after_install["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert!(arr.iter().any(is_shtum_entry));
        assert!(arr.iter().any(|e| e["matcher"] == "Edit"));

        let mut settings = after_install;
        let arr = settings
            .pointer_mut("/hooks/PreToolUse")
            .unwrap()
            .as_array_mut()
            .unwrap();
        arr.retain(|e| !is_shtum_entry(e));
        atomic_write_json(&path, &settings).unwrap();

        let after_uninstall = read_settings(&path).unwrap();
        let arr = after_uninstall["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["matcher"], "Edit");
        assert_eq!(after_uninstall["otherKey"], 42);

        let _ = fs::remove_dir_all(&dir);
    }
}

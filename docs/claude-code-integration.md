# Claude Code integration

This doc walks through installing the `shtum` hook into Claude Code, what the hook actually does, the recommended `CLAUDE.md` snippet to add to *your* projects (so Claude knows about the placeholder convention), and troubleshooting.

> **About this file vs. `CLAUDE.md` at the repo root:** the root-level `CLAUDE.md` is for AI agents working *on* the shtum codebase. The snippet in this doc (§ "Recommended CLAUDE.md snippet") is for AI agents working in *your other projects* that consume shtum-managed secrets.

## What the hook does

When installed, the hook intercepts every `PreToolUse` event for Claude Code's Bash tool. For each proposed Bash command:

1. **Loop guard:** if the command already starts with a `shtum run` invocation (bare or path-prefixed), pass through unchanged.
2. **Auto-wrap:** if the command contains a valid `{NAME}` placeholder matching shtum's grammar, rewrite the command to `<abs-path>/shtum run -- <original>` via the `permissionDecision: "allow"` + `updatedInput.command` hook response. The wrapped command then runs through shtum, which resolves placeholders and scrubs output.
3. **Safety-net deny:** if the command matches a compiled-in pattern for an authenticated tool (`aws`, `gh`, `wrangler`, `doppler`, `kubectl`, `terraform`, `psql`, `mysql`, or `curl`/`wget` to known authenticated hosts) AND has no placeholder, deny with `permissionDecision: "deny"` and a structured reason that includes:
   - A tool-specific hint pointing at the correct placeholder form
   - The inline list of currently stored secret names
   - The absolute path to the shtum binary
4. **Pass through** otherwise.

The hook is fully deterministic — no LLM calls, no semantic understanding. It's regex matching + string prepending. The "smart" part is the agent's response to the structured deny message.

For the design rationale (why selective-wrap rather than always-wrap), see `CLAUDE.md` and the P5 commit.

## Install

### Global (recommended for most users)

```bash
shtum hook install
```

Writes to `~/.claude/settings.json`. Affects every Claude Code session on this machine.

### Per-project

```bash
cd /path/to/your/project
shtum hook install --project
```

Writes to `./.claude/settings.json`. Only affects Claude Code sessions opened with this directory as cwd. Useful for testing or when only one project needs the firewall.

### Force-overwrite

```bash
shtum hook install --force
```

Replaces an existing shtum entry. Without `--force`, install refuses if it detects a prior install (preserving user state in case the existing entry was manually tuned).

### Preview without writing

```bash
shtum hook show
```

Prints the JSON that *would* be added. Useful for audit or for hand-merging into an existing settings file.

## Uninstall

```bash
shtum hook uninstall           # global
shtum hook uninstall --project # per-project
```

Removes only the shtum entry; preserves any other hook entries in the same settings file. Tidies up empty `PreToolUse` arrays and `hooks` objects after removal.

## What's added to settings.json

Install merges this into `hooks.PreToolUse`:

```json
{
  "matcher": "Bash",
  "hooks": [
    {
      "type": "command",
      "command": "/abs/path/to/shtum",
      "args": ["hook", "handle"]
    }
  ]
}
```

The `command` is the absolute path of the `shtum` binary that ran the install (`std::env::current_exe()`). If you rebuild shtum to a different location or `cargo install` it elsewhere, re-run `shtum hook install --force` to update the path.

Other hooks (yours or other tools') in the same `PreToolUse` array are preserved.

## Recommended CLAUDE.md snippet

Add this to the `CLAUDE.md` of any project where you want the agent to use shtum-managed secrets. It tells the agent the placeholder convention without requiring it to know shtum exists.

```markdown
## Secrets

Authenticated commands in this project use placeholder references instead of literal credentials. The placeholder is resolved at exec time by a local firewall; the literal value never enters your context.

**Convention:** write `{NAME}` wherever you would have written the credential value, where `NAME` is the stored secret name. The firewall expands the placeholder, runs the command, and scrubs the value out of any output before you see it.

**Modes when local-ps leakage matters** (the wrapped command's argv being readable via `ps aux`):

- For tools that read env vars natively (aws, psql, gh, wrangler, doppler): use the directive form `{env-inject:NAME}` as a standalone argument:
  ```
  aws s3 ls {env-inject:AWS_ACCESS_KEY_ID} {env-inject:AWS_SECRET_ACCESS_KEY}
  ```
- For tools that take a credential file path (gh auth login, sshpass, kubectl): use inline `{tempfile:NAME}`:
  ```
  sshpass -f {tempfile:SSH_PASS} ssh user@host
  ```
- For tools that read a credential from stdin: use the directive form `{stdin:NAME}` as a standalone argument:
  ```
  bash -c 'cat' {stdin:GPG_PASSPHRASE}
  ```

**Default (`{NAME}` with no prefix):** literal argv substitution. Good for `curl -H "Authorization: Bearer {API_TOKEN}"` style use. The value will be visible in `ps aux` on the local machine while the subprocess runs (documented limitation — protects your context, not the local process table).

**If a command is blocked** because it looks like an authenticated call without a placeholder, read the deny message: it names the right placeholder form for that tool and lists the secrets currently available. Pick the closest match and rewrite.
```

## Troubleshooting

### The hook installed but doesn't seem to fire

Check the settings file actually contains the entry:

```bash
cat ~/.claude/settings.json | python -m json.tool
```

Look for `hooks.PreToolUse[]` with `matcher: "Bash"` and a `command` ending in `shtum`. If absent, re-run install. If present, restart your Claude Code session — settings are loaded at session start.

### "command not found: shtum" inside Claude Code

The hook rewrites commands to use the absolute path of the shtum binary, so the rewritten form should always work. But if Claude tries to invoke `shtum` directly (e.g., `shtum store list` to discover available secrets), shtum needs to be on PATH for the Bash tool's shell.

Two fixes:

1. **Recommended:** install the shtum binary somewhere on PATH:
   ```bash
   cp target/release/shtum ~/.local/bin/
   ```
   Then re-run `shtum hook install --force` so the settings.json points at the new path.
2. The deny message already includes the absolute path and the list of stored secrets inline — Claude doesn't actually need to call `shtum store list` if it reads the deny message carefully. Tell Claude to read the deny output fully.

### macOS keeps prompting for Keychain access on every run

Every rebuild of the shtum binary changes its code signature, and macOS treats it as a new application for ACL purposes. The first run of any new build re-prompts for each Keychain item.

**During development:** click "Always Allow" each time. After clicking through, subsequent runs of *that exact build* are silent.

**For a stable install:** build once, copy to a stable location, and don't keep rebuilding in place. A `cargo install` flow with code-signing would make this a one-time prompt per item, ever.

### The hook denies a legitimate command

The safety-net pattern list is compiled in. If a false positive matters, two options:

1. Wrap the legitimate command in a placeholder anyway — e.g., add `{env-inject:DUMMY}` (referring to an empty no-op secret if needed). Any placeholder presence flips the hook from "deny" to "auto-wrap" for that command.
2. Open an issue or send a patch — the pattern list in `src/hook.rs:match_safety_net` is straightforward to tune. v2 plans support for an external config file.

### The hook's deny message mentions tools I don't have stored

The deny message lists *all* currently stored secrets, not just ones relevant to the matched tool. The agent should pick the closest match (or recognize that no relevant secret exists and tell you). This is intentional — listing only "matching" secrets would require shtum to know which secret goes with which tool, which it doesn't.

### Bash commands feel slow

The hook handler runs on every Bash tool call (~5–15 ms typical). For commands the hook passes through (the majority), there's no further overhead. For commands the hook wraps in `shtum run`, add ~10–20 ms for shtum startup and the output filter's sliding-window buffering. On interactive output that streams slowly, the buffer can introduce visible latency — use `--no-auto-redact` or `--no-default-redact` if you need real-time output and trust the wrapped command.

### Want to bypass the hook for a specific command

Type `!command` in Claude Code (the `!` prefix runs the command in your shell, not via the Bash tool — so no hook fires). Useful when you want to run something authentication-related in your own shell where credentials are already configured.

# CLAUDE.md — context for AI agents working on this repo

This file is loaded automatically by Claude Code (and equivalents) when a session opens with this repo as the working directory. It is the project-specific equivalent of a long-running memory file: every assistant working here should read it before making changes.

---

## What this project is

`shtum` is a local Rust CLI that lets an AI coding agent (Claude Code, etc.) invoke authenticated commands **without ever holding the credentials in its own context window**. Secrets live in the macOS Keychain; the agent uses placeholder references like `{CF_TOKEN}`; `shtum` resolves them at exec time, runs the command, and scrubs the literal values back out of stdout/stderr before they reach the caller.

The name means "stay silent" (British/Yiddish slang).

**Primary threat model:** preventing the credential VALUE from entering the agent's context (and therefore the LLM provider's servers). Local-machine `ps`-table leakage is a documented v1 limitation; the `{env-inject:NAME}`, `{stdin:NAME}`, and `{tempfile:NAME}` modes are opt-in escape hatches when local-ps protection matters.

For the full design rationale (problem motivation, comparison with vaults/dotenv/1Password CLI, why we own the scrubber), read `PLAN.md` at the repo root.

---

## Architecture in one screen

Single static Rust binary. Modules under `src/`:

| Module | Role |
|---|---|
| `cli.rs` | clap-derived CLI surface (`store`, `run`, `hook` subcommands) |
| `store/` | `SecretStore` trait + `KeychainStore` (macOS). Trait designed for Linux drop-in later |
| `inject.rs` | Placeholder parser (two orthogonal axes: *Source* and *Mode*), `Plan` struct, resolution + substitution |
| `tempfile.rs` | RAII guard for `{tempfile:NAME}` mode — creates mode-0600 files in `$TMPDIR`, unlinks on Drop |
| `exec.rs` | Subprocess spawn; pipes stdio through filters when redaction active; threads env-inject / stdin / tempfile through |
| `redact.rs` | Sliding-window streaming filter with two layers (A = literal/URL-encoded/base64 of stored values, B = regex defaults + user `--redact` patterns), combined alternation regex via DFA |
| `hook.rs` | Claude Code `PreToolUse` interceptor + `~/.claude/settings.json` JSON merge (`install` / `uninstall` / `show` / `handle`) |
| `main.rs` | Dispatch + glue |

---

## Locked v1 decisions — do not silently revise

If a request appears to contradict any of these, surface it before proceeding.

- **License:** Apache-2.0.
- **Platform:** macOS only. `SecretStore` trait is the abstraction point for Linux later.
- **Namespace claims** (GitHub org, crates.io, homebrew tap): **deferred** until the tool is proven working. Do not push to remote, publish, or claim names without explicit user instruction.
- **Placeholder grammar:** two orthogonal axes:
  - **Source** prefix (where the value comes from): bare `{NAME}` (default = Keychain + env fallback), `{kc:NAME}`, `{env:NAME}`, `{file:PATH}`.
  - **Mode** prefix (how the value reaches the subprocess; always paired with default source in v1): `{argv:NAME}` (explicit literal argv + ps-warning), `{env-inject:NAME}` (directive — must be standalone argv slot; sets env, strips slot), `{stdin:NAME}` (directive — standalone; piped to subprocess stdin; max one per command), `{tempfile:NAME}` (inline — replaced with path to 0600 temp file; multiple refs share one file; RAII cleanup).
- **Default injection** is **honest argv substitution** (direct exec, no shell wrapping). The earlier P2 design of "auto-promote env-inject + sh -c rewrite" was abandoned during QA when `sh -c` was found to expand env vars before exec, so the wrapped command's argv still leaked the value to `ps`. Direct argv substitution is honest about the leak; `{env-inject:NAME}` directive form is the opt-in fix.
- **Auto-redact scope** is **hybrid**:
  - No placeholders in the wrapped command → no redaction, stdio inherited, TTY preserved.
  - At least one placeholder resolved → ALL stored Keychain secrets are folded into the filter (defense in depth against a forgotten `{NAME}` reference). `--no-auto-redact` disables Layer A only; Layer B regex still runs.
- **Layer B regex defaults** (toggleable with `--no-default-redact`): JWT, AWS access key, Bearer header, GitHub PAT. `--redact <REGEX>` is repeatable and merged into one alternation regex compiled via the `regex` crate's DFA. Window cap = max(Layer-A max, 4096) bytes; matches longer than the cap are not redacted.
- **Hook integration policy** is **selective wrap** (Option Y from the design discussion):
  - Pass through if the command already starts with a `shtum run` invocation (loop guard).
  - Rewrite to `<abs-path>/shtum run -- <original>` if the command contains a valid `{NAME}` placeholder.
  - Deny (with a tool-specific hint + inline stored-secrets list + absolute shtum path) if it matches a compiled-in safety-net pattern (bare `aws/gh/wrangler/doppler/kubectl/terraform/psql/mysql` or `curl`/`wget` to known authenticated hosts) and has no placeholder.
  - Otherwise pass through.
  - Always-wrap (Option X) was considered and rejected: would break TTY for every Bash call (`vim`, `htop`, etc.) since stdio would always be piped through Layer B's regex filter.
- **Tempfile cleanup** is RAII on normal exit. Crash paths (SIGKILL, uncaught panic) leak the file; a startup sweep is deferred to v2.
- **Config file:** deferred to v2. v1 is flag-driven only.
- **Interactive/PTY:** deferred to v2 per PLAN.md §6.6.

---

## Workflow rules — the user has explicitly asked you to follow these

These come from the user, validated through multiple successful phases of this project. Honor them on every task.

1. **Verify assumptions before coding.** When asked to plan or implement anything, first identify all assumptions in your interpretation of the request. Use `AskUserQuestion` to verify them. Do not start writing code from a guessed reading of the task.
2. **No big-bang implementations.** Break work into incremental phases. Each phase must produce a tangible milestone the user can manually QA before you proceed. After each phase: stop, hand off a QA checklist, wait for confirmation.
3. **One commit per phase** with a meaningful body. The convention in this repo is `P<N>:` or `P<N><letter>:` prefix (e.g., `P4a:`). Commit messages explain the *why* (motivations, trade-offs, design decisions found during QA) — the diff already shows the *what*. The repo includes a `Co-Authored-By` trailer for the assisting model.
4. **Don't push, don't publish, don't claim namespaces** without explicit user instruction. Namespace claims are deferred per the locked v1 decisions.
5. **Update memory and CLAUDE.md when locked decisions change** so future sessions inherit the new reality.

---

## Build / test / dev loop

```bash
cargo build --release        # primary artifact at target/release/shtum
cargo test                   # 30+ unit tests covering inject, redact, hook
```

Every rebuild changes the binary signature, which causes macOS to re-prompt for Keychain access on the first run after each rebuild. For a codesigned installed binary it's one prompt per stored item, ever. During dev, the prompts are noise — click "Always Allow" each time.

No CI is configured for v1. Add it when preparing for public release.

---

## Things that look like they need fixing but are intentional

- **The placeholder grammar regex (`\{([^{}]*)\}`) is greedy and naive.** It catches JSON literals like `{"foo": "bar"}` then a `classify()` step rejects them. This is by design — the inject parser is built around "match candidates then validate" because nested brace handling in shell-quoted contexts is otherwise nightmarish.
- **`{env-inject:NAME}` is a directive, not an inline placeholder.** It must occupy a standalone argv slot. The mid-string error is intentional — see the locked decision above. An inline env-inject would require `sh -c` wrapping that re-creates the ps leak.
- **The hook handler doesn't touch the Keychain on the pass-through path.** It only calls `store.list()` (and never `store.get()`) when emitting a deny message, and `list` doesn't trigger value-access ACL prompts. The handler must stay fast and crash-free because it runs on every Bash tool call.
- **The auto-redact sliding window holds back up to ~4 KB of output** when Layer B regexes are enabled. For interactive tools that print slowly, this can introduce latency. Mitigation: `--no-auto-redact` for Layer A or `--no-default-redact` for Layer B; both can be combined.
- **Loop guard for the hook accepts path-prefixed `shtum run` invocations** (`(?:\S+/)?shtum\s+run\b`) because the rewrite emits an absolute path. If you change the rewrite format, update the loop guard regex in lockstep.

---

## When in doubt

- Read `PLAN.md` for the full design (335 lines).
- Read `docs/threat-model.md` for what shtum protects against vs. what it explicitly does not.
- Read `docs/claude-code-integration.md` for the hook contract and the recommended CLAUDE.md snippet **for projects that USE shtum** (different from this file, which is for working on shtum itself).
- Check `git log --oneline` — every phase has a descriptive commit and the body usually captures the design rationale.

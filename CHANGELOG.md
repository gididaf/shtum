# Changelog

All notable changes to `shtum` are recorded here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [SemVer](https://semver.org/) once a public release ships.

## [Unreleased]

### Added

- **`shtum quick [VALUE]`** — stash a one-off secret under an auto-generated `TMP_<6 chars>` name and hand the name back. Value input is whichever you prefer: positional `shtum quick "FDde#2DFdf@@r2r"`, `--from-stdin`, `--from-file PATH`, or interactive hidden prompt (default on a TTY). Auto-expires after 4 hours of no use; each `shtum run` that resolves the key resets the timer. Override with `--ttl 30m|2h|1d` (min 60s, max 7d). Sidecar registry lives at `~/Library/Application Support/shtum/temp-keys.json`; only registry-tracked names are sweep candidates. The Claude Code hook safety-net denies `shtum quick` from the agent — generating a temp key from inside Claude would put the name into the model's context.
- **Dashboard temp-key surface** — Keys tab now has a "Quick stash" card above Add (paste a value, get back an auto-name in the success flash); per-row TEMP badge with a client-side countdown driven by an absolute expiry epoch in `data-expires-at`; inline "Extend" button that bumps `last_used_at` to now. New routes: `POST /secrets/quick`, `POST /secrets/<name>/extend`. Both go through the same token-in-body CSRF gate as Add/Rotate/Delete. Sweep runs at the top of every dashboard request.
- **`shtum store list` annotates temp rows** — `TMP_a8f3k2 (temp, expires in 3h 12m)` for registry-tracked names; unannotated for everything else. Falls back to plain names if the registry can't be opened.
- **`shtum store rename <OLD> <NEW>`** — rename a stored secret in place; the value is preserved unchanged. Refuses by default if `<NEW>` is already a stored name; pass `--force` to overwrite the destination. Same-name renames are no-ops.
- **Dashboard rename action** — Rename lives inside the new per-row Edit panel (just a new-name field + button). Collisions are handled with a `confirm()` prompt: the page-level JS checks the typed name against the names embedded on `<body data-secret-names>`, and if it collides, asks the user before adding a hidden `force=on` field and submitting. Posts to `POST /secrets/<old>/rename` with the same token-in-body CSRF protection as the existing Add/Rotate/Delete forms.
- **`shtum store add --force`** — opt-in overwrite of an existing secret on `add`. The same `data-confirm-overwrite` JS hook covers the dashboard's Add form too: if the typed name is already stored, the page prompts before submitting.
- `SecretStore::add` (default trait impl: existence check → set; refuses on collision unless `force` is set), `SecretStore::rename` (existence check → get → set → delete; backends with native versions can override), and `StoreError::AlreadyExists`.

### Changed

- **`shtum store add` no longer silently overwrites.** Previously `add` and `rotate` were synonyms — both called `set()` directly, which on Keychain is upsert. `add` now refuses on collision with a clear error pointing at `rotate` (idempotent replace) or `--force` (opt-in clobber). `rotate` is unchanged: idempotent, succeeds whether the secret existed before or not.
- CLI: `Rotate(AddArgs)` split into `Rotate(RotateArgs)` so `--force` only appears on `add --help`, not `rotate --help`.
- **Dashboard UI redesign** — dark theme with a real button hierarchy (filled-primary / ghost-secondary / outline-danger), card-based sections, and a collapsible **Edit** panel per secret. The default secret-list row is now just `name + Reveal + Edit`; Rename / Rotate / Delete forms live inside the Edit panel (Rename first — identity before content). No new JS deps — same inline `<script>` block, with extra handlers for the toggle and the generic confirm-on-collision flow. CSP unchanged.

## [0.2.0] — 2026-05-14

### Added

- **`shtum dashboard`** — local web UI for Keychain CRUD and hook-install snippet copy-paste.
  - `--port <PORT>` flag, `PORT` env var; defaults to a random free port chosen by the OS (precedence: flag > env > random).
  - Binds 127.0.0.1 only. Per-launch 192-bit session token from `/dev/urandom`, base64-URL-encoded; printed in the launch URL on stderr. Token verification is constant-time. Strict `Host:` header check (`127.0.0.1:<port>` or `localhost:<port>` only) blocks DNS-rebinding.
  - GET `/` renders the secret list + Add form + per-row Rotate/Delete forms + ready-to-copy hook-install snippets (global and per-project). GET `/secrets/<name>/reveal?token=...` returns the value as `text/plain; charset=utf-8` (rendered inline via `textContent`, auto-hides after 30s). POST `/secrets/add` / `/secrets/<name>/rotate` / `/secrets/<name>/delete` validate the token from the form body, reject non-`application/x-www-form-urlencoded` requests with 415, cap body size at 64 KiB (413 otherwise), and 303-redirect to `/` with a flash query param on success or validation failure.
  - Locked-down CSP (`default-src 'none'` + explicit allows for `script-src`, `style-src`, `connect-src`, `form-action` — all `'self'` or `'unsafe-inline'`; `frame-ancestors 'none'`; `base-uri 'none'`). `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` on every response.
  - One-line stderr access log per request: `[shtum dashboard] METHOD path STATUS`. Token query values are redacted to `[REDACTED]`; request bodies and reveal response bodies are never logged.
  - Strict urlencoded form parser rejects duplicate keys (no `token=evil&token=good` smuggling).
  - The dashboard itself never modifies Claude settings. Hook snippets are static copy-paste text.
- **`docs/dashboard.md`** — full threat model + operational notes for the dashboard.

## [0.1.0] — 2026-05-14

First working version. macOS only. Not yet published to package registries; build from source.

### Added

- **`shtum store`** subcommands for managing secrets in the macOS Keychain:
  - `add <NAME>` with interactive hidden prompt, `--from-file`, or `--from-stdin`
  - `list` (names only; values never printed)
  - `rm <NAME>`
  - `rotate <NAME>` (delete + re-add)
- **`shtum run -- <command>`** wrapped subprocess execution:
  - Placeholder grammar with two orthogonal axes — **source** (`{NAME}`, `{kc:NAME}`, `{env:NAME}`, `{file:PATH}`) and **mode** (`{argv:NAME}`, `{env-inject:NAME}`, `{stdin:NAME}`, `{tempfile:NAME}`).
  - Direct exec (no shell wrapping) for the default argv-mode path.
  - `{env-inject:NAME}` directive: standalone argv slot, stripped before exec, value set as `NAME=<value>` in subprocess env. Closes the `ps`-table leak for tools that read env vars natively (aws, psql, gh, wrangler, etc.).
  - `{stdin:NAME}` directive: standalone argv slot, stripped, value piped to subprocess stdin. Max one per command.
  - `{tempfile:NAME}` inline: replaced with path to a `0600` file under `$TMPDIR` containing the value. Multiple references to the same NAME share one file. RAII-deleted on normal exit.
  - `{argv:NAME}` explicit form: identical to bare `{NAME}` but emits a one-line stderr warning naming the placeholders that will be visible in `ps` while the subprocess runs.
  - `--dry-run` resolves all placeholders (reachability check) and prints masked argv + env + stdin + tempfile entries; never reveals values.
  - Exit codes propagate from the wrapped command; signal kills mapped to `128+signum` per shell convention.
- **Auto-redact filter** on stdout and stderr:
  - **Layer A** — three variants per stored secret (literal bytes, conservative URL-encoded form, base64 of literal), matched at the exact head position with longest-variant-wins.
  - **Layer B** — combined alternation regex compiled via the `regex` crate's DFA. Built-in defaults: JWT, AWS access key, Bearer header, GitHub PAT. User-supplied patterns via repeatable `--redact <REGEX>`.
  - Sliding-window streaming with cached next-Layer-B-match, byte-by-byte step (Layer A is checked at every position even between Layer B matches).
  - `--no-auto-redact` disables Layer A only. `--no-default-redact` disables Layer B's built-in patterns.
  - Hybrid scope: no placeholders in the wrapped command → no redaction, stdio inherited (TTY preserved). At least one placeholder resolved → ALL stored Keychain secrets folded in.
- **Claude Code `PreToolUse` hook integration:**
  - `shtum hook install` / `uninstall` / `show` / `handle`.
  - Atomic JSON merge against `~/.claude/settings.json` (or `./.claude/settings.json` with `--project`); preserves unrelated entries.
  - Selective-wrap policy: rewrite if `{...}` placeholder present, deny with structured hint if a safety-net pattern matches and no placeholder, pass through otherwise.
  - Safety-net pattern list (bare `aws/gh/wrangler/doppler/kubectl/terraform/psql/mysql`; `curl`/`wget` to known authenticated hosts) with per-tool rewrite hints in the deny message.
  - Deny message includes the inline list of stored secret names so the agent can pick the right placeholder without a follow-up CLI call.
- **Documentation:**
  - `README.md` — install + quickstart + three core flows
  - `CLAUDE.md` — repo-level context for AI agents working on shtum itself
  - `docs/threat-model.md` — full threat-model breakdown
  - `docs/claude-code-integration.md` — hook walkthrough + recommended CLAUDE.md snippet for consumer projects
  - `docs/cookbook.md` — copy-paste recipes for Cloudflare/GitHub/AWS/psql/MySQL/SSH/Workers/Doppler/OpenAI

### Notes

- **Platform:** macOS only. `SecretStore` trait designed for Linux drop-in later.
- **License:** Apache-2.0.
- **Namespace claims** (GitHub org, crates.io, homebrew tap): deferred. Not pushed anywhere.
- **Tempfile cleanup** leaks on `SIGKILL` / uncaught panic. Startup sweep deferred to v2.
- **Interactive/PTY** support deferred to v2.
- **Config file** deferred to v2 (flag-driven only in v1).

[Unreleased]: #unreleased
[0.2.0]: #020--2026-05-14
[0.1.0]: #010--2026-05-14

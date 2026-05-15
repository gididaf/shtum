# Dashboard

`shtum dashboard` runs a local web UI for managing the Keychain entries and grabbing the right hook-install command. It exists because once you have more than three or four stored secrets, recalling the right `shtum store …` flags is slower than clicking. The dashboard is process-scoped — it lives as long as the `shtum dashboard` process and disappears when you Ctrl+C — so there is no long-running service to keep an eye on.

This page covers how to use it, what the auth model is, and what the dashboard does and does not protect.

## Running it

```bash
shtum dashboard               # random free port, OS picks one
shtum dashboard --port 8080   # explicit port
PORT=8080 shtum dashboard     # equivalent via env; --port wins if both are set
```

When it starts, the binary prints one line to stderr:

```
shtum dashboard listening on http://127.0.0.1:39871/?token=O87Zh0G-yW42wuxzGr_2Vb3pxVEo6eBC
press Ctrl+C to stop.
```

Click the URL (or paste it into a browser). The token in the query string is the entire access control — keep that URL to yourself.

Every request the dashboard handles prints one line to stderr in the same terminal:

```
[shtum dashboard] GET / 200
[shtum dashboard] POST /secrets/add 303
[shtum dashboard] GET /secrets/CF_TOKEN/reveal?token=[REDACTED] 200
```

The `token=` query value is replaced with `[REDACTED]` before logging. Request and response bodies are never logged, so reveal responses cannot leak into stderr.

## What you can do

Each row in the secrets list shows the name + a **Reveal** button + an **Edit** toggle. The destructive and write actions live inside the Edit panel, kept out of the way until you actually need them.

- **List** the names of stored secrets.
- **Add** a new secret with the form at the top of the page (Keychain names must match `[A-Za-z0-9_.-]+`). If you type a name that already exists, the dashboard prompts for confirmation before overwriting; declining cancels the add.
- **Reveal** a secret's value inline. The value renders in a green box for up to 30 seconds, then auto-hides; click Hide to clear it sooner.
- **Edit** opens an inline panel with three sections:
  - **Rotate value** — replace the stored value. Equivalent to `shtum store rotate`.
  - **Rename** — change the secret's name. Equivalent to `shtum store rename`. If the new name you typed is already in use, the dashboard prompts for confirmation before overwriting; declining cancels the request, accepting destroys the existing entry under that name.
  - **Danger zone → Delete** — remove the secret. A browser confirm dialog fires before the request leaves the page.
- **Copy** the global or per-project hook-install command to your clipboard. The dashboard never installs the hook itself — copy the command, paste it into a terminal, run it yourself.

## Threat model — what the dashboard protects against

The dashboard's job is to expose Keychain CRUD over HTTP without becoming an exfiltration path. The defences:

- **Bind 127.0.0.1 only.** The listening socket never appears on a real network interface. A device on your LAN cannot reach the dashboard.
- **24-byte (192-bit) random session token.** Generated from `/dev/urandom` at startup. Regenerated every run. Required on every request — query string for GETs, hidden form field for POSTs. A 192-bit token makes brute force computationally infeasible for any realistic dashboard lifetime.
- **Constant-time token comparison.** Prevents the (already implausible) timing-based brute force.
- **Strict `Host:` header check.** The dashboard refuses any request whose `Host` header isn't exactly `127.0.0.1:<port>` or `localhost:<port>`. This blocks DNS-rebinding attacks where a malicious site rebinds its own hostname to 127.0.0.1 in the victim's browser.
- **CSRF protection via token-in-form-body, not cookie.** A cross-origin form submission from an attacker's page cannot include the session token because the attacker can't read it (Same-Origin Policy blocks cross-origin reads of the dashboard's HTML).
- **Locked-down Content-Security-Policy** with `default-src 'none'`. The dashboard's own inline styles and scripts are explicitly allowed; everything else is blocked, including connections to anywhere except the dashboard itself (`connect-src 'self'`). A stored secret containing HTML cannot reach an attacker-controlled domain even if a future bug skipped escaping.
- **`text/plain` + `nosniff` on the reveal response.** Stored values are served as plain text and cannot be re-interpreted as HTML/JS by a misbehaving browser. The page JS additionally writes the value into the DOM with `textContent`, not `innerHTML`.
- **`X-Frame-Options: DENY`.** A malicious page cannot embed the dashboard in an iframe and clickjack the user into clicking Delete.
- **`Referrer-Policy: no-referrer`.** Browsers will not include the token-bearing URL as a Referer when following any link out of the dashboard.
- **`Cache-Control: no-store`.** Revealed values are never written to disk caches.

## What the dashboard does NOT protect against

These are out of scope by design; the dashboard's security boundary is the same as your macOS user account.

- **Other processes running as the same user.** Any binary you run can connect to `127.0.0.1:<port>` and *attempt* to access the dashboard. Without the session token, those attempts get 403 and never reach the Keychain — but the attempt itself is not stopped at the socket level. The 192-bit token is what protects you, not the loopback bind.
- **The browser's URL history.** The startup URL embeds the token in the query string. That URL ends up in your browser's history and may be visible in autocomplete. **Close the tab when you're done**, or use a private/incognito window when launching the dashboard. The token also rotates every time you launch a fresh `shtum dashboard`, so an old history entry is invalid the moment the process exits.
- **Browser extensions** with `http://127.0.0.1/*` host permissions can read the dashboard page like any other website. Same advice as for any local admin UI: don't run untrusted extensions while you have sensitive panels open.
- **Shoulder surfing / screen recording.** Reveal renders the value as visible text. It is not blurred. If you have a tendency to leave a tab open during screen shares, prefer the CLI `shtum store rotate` over the dashboard's reveal.
- **A compromised user account.** Keychain is unlocked while you're logged in. `shtum dashboard` does not add a per-secret password step; it's a convenience layer on top of the same `SecretStore` the CLI uses.

The dashboard never writes to disk: there is no log file, no session store, no on-disk cache. State lives entirely in process memory (token + tiny_http buffers). Stopping the process erases everything except the secrets themselves, which are in the Keychain.

## What about the hook commands shown in the dashboard?

They are copy-paste only. The dashboard renders two static command strings — `shtum hook install` (global) and `cd /path/to/your-project && shtum hook install --project` (per-project) — with a Copy button. Clicking Copy puts the command on your clipboard; the dashboard never executes it. To actually install the hook, paste the command into your terminal yourself, replacing `/path/to/your-project` with the project directory for the per-project version.

This is deliberate. Modifying Claude Code's settings.json is the kind of thing where a terminal log is helpful afterwards, and where you want explicit user intent at the moment the file changes — not a button click two clicks deep in a web page.

## When the dashboard is not the right tool

- **Headless / remote workflows.** The dashboard needs a browser on the same machine. If you're SSHed into a box and want to manage its secrets, use the CLI.
- **Sharing with other users on a multi-user Mac.** The token-in-URL model assumes a single user has the URL. Don't share the URL by email/Slack.
- **Long-running unattended sessions.** Close the dashboard when you're not actively using it. The token doesn't expire on its own; the process exiting is what invalidates it.

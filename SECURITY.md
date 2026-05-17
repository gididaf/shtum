# Security policy

## Reporting a vulnerability

If you believe you've found a security issue in `shtum`, please email
**`gididaf1@gmail.com`** with the subject line `shtum security` rather than
opening a public issue or pull request. I'll acknowledge receipt within 72 hours
and work with you on a coordinated disclosure timeline if appropriate.

For non-security bugs and feature requests, use the GitHub issue tracker
normally.

## What's in scope

`shtum` is a credential firewall between an AI coding agent and authenticated
services. The protections it intends to make are spelled out in
[`docs/threat-model.md`](./docs/threat-model.md), specifically the section
**"What `shtum` PROTECTS against"**. Reports concerning those properties are
in scope. Examples:

- A way to make a stored secret value enter the wrapped command's captured
  stdout/stderr without being scrubbed.
- A way to make `shtum` itself print, log, or otherwise emit a stored secret
  outside the subprocess argv/env/stdin path the user explicitly chose.
- A way to bypass the dashboard's session-token check or `Host`-header check.
- A flaw in the placeholder parser, redaction filter, or hook handler that
  causes a secret to leak in a context the threat model claims is protected.

## What's out of scope

The threat model also explicitly lists what `shtum` does **not** protect
against, in the section **"What `shtum` does NOT protect against"**. Please
read it before filing — those properties are intentional limitations, not
bugs, and we ask that you not report them as vulnerabilities. The big ones:

- Local-machine compromise. `shtum` is not a sandbox; same-user processes
  can read the Keychain via the OS ACL prompt.
- Response data that doesn't match a regex pattern. `shtum` scrubs credential
  *values* and a built-in set of credential *shapes*; it does not redact
  general API response data.
- The wrapped command itself misbehaving. `shtum run -- bash -c 'leak the
  filesystem'` cannot be stopped by `shtum`.

## Supported versions

`shtum` is pre-1.0. Only the latest `0.x` release is supported. Security
fixes will go into a new `0.x.y` release rather than backporting.

# shtum

> **Status:** work in progress. Not yet usable. See [`PLAN.md`](./PLAN.md) for the design.

`shtum` is a local CLI wrapper that lets an AI coding agent (Claude Code, etc.) run authenticated commands **without ever seeing the credentials in its context window**. Secrets live in the macOS Keychain; the agent uses placeholder references like `{CF_TOKEN}`; `shtum` resolves them just before exec, runs the command, and scrubs the secret values back out of stdout/stderr.

The name means "stay silent" (British/Yiddish slang) — which is what the tool makes your secrets do.

## License

Apache-2.0. See [`LICENSE`](./LICENSE).

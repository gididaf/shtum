use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::time::Duration;

use crate::temp::parse_ttl;

#[derive(Parser, Debug)]
#[command(
    name = "shtum",
    version,
    about = "Secret-injecting command wrapper for AI agents",
    long_about = "shtum stores secrets locally (macOS Keychain) and lets you invoke commands \
                  with placeholder references like `{NAME}`. The placeholder is resolved at exec \
                  time, the secret is injected into the subprocess via a safe mode, and the \
                  literal value is scrubbed back out of stdout/stderr before you see the output.",
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Manage stored secrets (macOS Keychain).
    Store {
        #[command(subcommand)]
        action: StoreAction,
    },
    /// Run a command, resolving `{NAME}` placeholders from the secret store.
    ///
    /// Inline placeholders are injected via the shell environment (not argv) so
    /// the literal secret value does not appear in `ps aux`. Use
    /// `shtum run -- <command...>`; everything after `--` is the wrapped command.
    Run(RunArgs),
    /// Manage the Claude Code PreToolUse hook integration.
    Hook {
        #[command(subcommand)]
        action: HookAction,
    },
    /// Serve a local web dashboard for managing stored secrets and viewing
    /// hook-install snippets. Binds to 127.0.0.1 only; access is gated by a
    /// random token printed at startup. Runs until Ctrl+C.
    Dashboard(DashboardArgs),
    /// Stash a one-off value under an auto-generated name (e.g. `TMP_a8f3k2`).
    ///
    /// The generated name is printed on stdout (one line, pipeable); a friendly
    /// note with the expiry policy goes to stderr. The value goes into the
    /// macOS Keychain like any other `shtum store add`, plus a sidecar
    /// registry entry that drives idle-TTL expiry. Auto-removes itself after
    /// 4 hours of no use (each `shtum run` that resolves the key resets the
    /// timer). Pass `--ttl <duration>` to override.
    Quick(QuickArgs),
}

#[derive(clap::Args, Debug)]
pub struct DashboardArgs {
    /// TCP port to bind on 127.0.0.1. Defaults to a random free port chosen
    /// by the OS. Also accepts the PORT environment variable; the flag wins
    /// when both are set.
    #[arg(long, value_name = "PORT")]
    pub port: Option<u16>,
}

#[derive(Subcommand, Debug)]
pub enum HookAction {
    /// Install the shtum hook into Claude Code's settings.json. Defaults to
    /// the user-global settings (~/.claude/settings.json); use --project for
    /// the per-project file (./.claude/settings.json).
    Install(HookInstallArgs),
    /// Remove the shtum hook entry from Claude Code's settings.json.
    Uninstall(HookScopeArgs),
    /// Print the JSON snippet that `install` would add, without touching disk.
    Show,
    /// Internal: invoked by Claude Code for every PreToolUse Bash event. Reads
    /// the tool-call envelope on stdin and decides whether to rewrite the
    /// command to go through `shtum run`, deny it (when it looks like an
    /// authenticated call missing a placeholder), or let it pass through.
    Handle,
}

#[derive(clap::Args, Debug)]
pub struct HookInstallArgs {
    /// Operate on the per-project settings (./.claude/settings.json) instead
    /// of the user-global (~/.claude/settings.json).
    #[arg(long)]
    pub project: bool,

    /// Replace any existing shtum hook entry. By default, install refuses if
    /// one is already present.
    #[arg(long)]
    pub force: bool,
}

#[derive(clap::Args, Debug)]
pub struct HookScopeArgs {
    /// Operate on the per-project settings (./.claude/settings.json) instead
    /// of the user-global (~/.claude/settings.json).
    #[arg(long)]
    pub project: bool,
}

#[derive(clap::Args, Debug)]
pub struct RunArgs {
    /// Don't actually execute. Print the rewritten invocation with secret
    /// values shown as `[REDACTED:<placeholder>]`. Still resolves all
    /// placeholders, so this doubles as a "are my secrets reachable?" check.
    #[arg(long)]
    pub dry_run: bool,

    /// Disable the automatic stdout/stderr scrubber that replaces literal,
    /// URL-encoded, and base64-encoded occurrences of injected secret values
    /// with `[REDACTED]`. Useful for debugging only.
    #[arg(long)]
    pub no_auto_redact: bool,

    /// Additional regex pattern to redact from subprocess output. Repeatable.
    /// Patterns are merged with the built-in default set (unless
    /// `--no-default-redact` is also passed). Matches are replaced with
    /// `[REDACTED]`. Pattern syntax: <https://docs.rs/regex/latest/regex/#syntax>.
    #[arg(long = "redact", value_name = "REGEX")]
    pub redact: Vec<String>,

    /// Disable the built-in default redaction regex set (JWTs, AWS access
    /// keys, Bearer tokens, GitHub PATs). Any `--redact` patterns are still
    /// applied.
    #[arg(long)]
    pub no_default_redact: bool,

    /// The command and its arguments, with placeholder references.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        required = true,
        num_args = 1..,
    )]
    pub cmd: Vec<String>,
}

#[derive(Subcommand, Debug)]
pub enum StoreAction {
    /// Add a new secret. Prompts for the value with hidden input by default.
    Add(AddArgs),
    /// List the names of stored secrets (values are never printed).
    List,
    /// Remove a stored secret.
    Rm {
        /// Name of the secret to remove.
        name: String,
    },
    /// Replace a stored secret's value (prompts for the new value).
    /// Idempotent: succeeds whether or not the secret already exists.
    Rotate(RotateArgs),
    /// Rename a stored secret. Refuses by default if `<NEW>` already exists;
    /// pass `--force` to overwrite the destination. The value is preserved
    /// unchanged.
    Rename(RenameArgs),
}

#[derive(clap::Args, Debug)]
pub struct RenameArgs {
    /// Current name.
    pub old: String,
    /// New name. Allowed characters: [A-Za-z0-9_.-].
    pub new: String,
    /// Overwrite the destination if it already exists. Without this, rename
    /// refuses when `<NEW>` is already a stored name.
    #[arg(long)]
    pub force: bool,
}

#[derive(clap::Args, Debug)]
pub struct AddArgs {
    /// Name of the secret. Allowed characters: [A-Za-z0-9_.-].
    pub name: String,

    /// Read the value from this file instead of prompting. A single trailing
    /// newline is stripped (so `echo secret > file` works as expected).
    #[arg(long, value_name = "PATH", conflicts_with = "from_stdin")]
    pub from_file: Option<PathBuf>,

    /// Read the value from stdin instead of prompting. A single trailing
    /// newline is stripped.
    #[arg(long, conflicts_with = "from_file")]
    pub from_stdin: bool,

    /// Replace the existing value if `<NAME>` is already stored. Without
    /// this, `add` refuses on collision; use `shtum store rotate` for an
    /// idempotent replace.
    #[arg(long)]
    pub force: bool,
}

#[derive(clap::Args, Debug)]
pub struct RotateArgs {
    /// Name of the secret. Allowed characters: [A-Za-z0-9_.-].
    pub name: String,

    /// Read the value from this file instead of prompting. A single trailing
    /// newline is stripped (so `echo secret > file` works as expected).
    #[arg(long, value_name = "PATH", conflicts_with = "from_stdin")]
    pub from_file: Option<PathBuf>,

    /// Read the value from stdin instead of prompting. A single trailing
    /// newline is stripped.
    #[arg(long, conflicts_with = "from_file")]
    pub from_stdin: bool,
}

#[derive(clap::Args, Debug)]
pub struct QuickArgs {
    /// Read the value from this file instead of prompting. A single trailing
    /// newline is stripped.
    #[arg(long, value_name = "PATH", conflicts_with = "from_stdin")]
    pub from_file: Option<PathBuf>,

    /// Read the value from stdin instead of prompting. A single trailing
    /// newline is stripped.
    #[arg(long, conflicts_with = "from_file")]
    pub from_stdin: bool,

    /// Idle TTL — time of no use (no `shtum run` resolving this key, no
    /// dashboard `Extend` press) before auto-expiry. Format: `<N>{s,m,h,d}`,
    /// e.g. `30m`, `2h`, `1d`. Min `60s`, max `7d`. Default: `4h`.
    #[arg(long, value_name = "DURATION", value_parser = parse_ttl)]
    pub ttl: Option<Duration>,
}

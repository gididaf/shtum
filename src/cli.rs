use clap::{Parser, Subcommand};
use std::path::PathBuf;

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
    Rotate(AddArgs),
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
}

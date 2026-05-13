mod cli;
mod store;

use anyhow::{Context, Result};
use clap::Parser;
use std::io::{IsTerminal, Read};
use std::path::Path;

use crate::cli::{AddArgs, Cli, Command, StoreAction};
use crate::store::{SecretStore, StoreError, default_store, validate_name};

fn main() -> Result<()> {
    let args = Cli::parse();
    match args.command {
        Command::Store { action } => run_store(action),
    }
}

fn run_store(action: StoreAction) -> Result<()> {
    let store = default_store();
    match action {
        StoreAction::Add(args) => add_secret(&store, args, false),
        StoreAction::Rotate(args) => add_secret(&store, args, true),
        StoreAction::List => list_secrets(&store),
        StoreAction::Rm { name } => {
            validate_name(&name)?;
            store.delete(&name).context("failed to remove secret")?;
            eprintln!("removed `{name}`");
            Ok(())
        }
    }
}

fn list_secrets(store: &impl SecretStore) -> Result<()> {
    let names = store.list().context("failed to list secrets")?;
    for n in names {
        println!("{n}");
    }
    Ok(())
}

fn add_secret(store: &impl SecretStore, args: AddArgs, rotating: bool) -> Result<()> {
    validate_name(&args.name)?;
    let value = read_value(&args)?;
    if value.is_empty() {
        anyhow::bail!("refusing to store an empty value");
    }
    if rotating {
        match store.delete(&args.name) {
            Ok(()) | Err(StoreError::NotFound(_)) => {}
            Err(e) => return Err(e.into()),
        }
    }
    store
        .set(&args.name, &value)
        .context("failed to store secret")?;
    eprintln!(
        "{} `{}`",
        if rotating { "rotated" } else { "stored" },
        args.name
    );
    Ok(())
}

fn read_value(args: &AddArgs) -> Result<Vec<u8>> {
    if let Some(path) = &args.from_file {
        return read_from_file(path);
    }
    if args.from_stdin {
        return read_from_stdin();
    }
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        let prompt = format!("Enter value for `{}`: ", args.name);
        let value = rpassword::prompt_password(prompt).context("failed to read password")?;
        Ok(value.into_bytes())
    } else {
        read_from_stdin()
    }
}

fn read_from_file(path: &Path) -> Result<Vec<u8>> {
    let bytes =
        std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    Ok(strip_trailing_newline(&bytes).to_vec())
}

fn read_from_stdin() -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    std::io::stdin()
        .read_to_end(&mut buf)
        .context("failed to read stdin")?;
    Ok(strip_trailing_newline(&buf).to_vec())
}

fn strip_trailing_newline(b: &[u8]) -> &[u8] {
    let mut end = b.len();
    if end > 0 && b[end - 1] == b'\n' {
        end -= 1;
        if end > 0 && b[end - 1] == b'\r' {
            end -= 1;
        }
    }
    &b[..end]
}

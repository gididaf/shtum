mod cli;
mod exec;
mod inject;
mod redact;
mod store;
mod tempfile;

use anyhow::{Context, Result};
use clap::Parser;
use std::io::{IsTerminal, Read};
use std::path::Path;

use crate::cli::{AddArgs, Cli, Command, RunArgs, StoreAction};
use crate::store::{SecretStore, StoreError, default_store, validate_name};

fn main() {
    match real_main() {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::exit(1);
        }
    }
}

fn real_main() -> Result<i32> {
    let args = Cli::parse();
    match args.command {
        Command::Store { action } => {
            run_store(action)?;
            Ok(0)
        }
        Command::Run(args) => run_command(args),
    }
}

fn run_command(args: RunArgs) -> Result<i32> {
    let store = default_store();
    if args.dry_run {
        // Resolve everything (so dry-run doubles as a reachability check),
        // then display the masked argv without ever using the real values.
        let plan = inject::build_plan(&args.cmd, &store)?;
        print_dry_run(&args.cmd, &plan);
        // RAII tempfiles drop here — they existed for milliseconds.
        drop(plan);
        Ok(0)
    } else {
        let mut plan = inject::build_plan(&args.cmd, &store)?;
        let layer_a = !args.no_auto_redact;
        if layer_a && !plan.secrets.is_empty() {
            inject::enrich_with_store_secrets(&mut plan, &store)?;
        }
        let layer_b = redact::build_layer_b(&args.redact, !args.no_default_redact)?;
        if !plan.argv_warnings.is_empty() {
            eprintln!(
                "[shtum] warning: {{argv:...}} substituted into argv — value(s) for {} \
                 will be visible in `ps` output while the subprocess runs",
                plan.argv_warnings.join(", ")
            );
        }
        exec::run_plan(plan, layer_a, layer_b)
    }
}

fn print_dry_run(original_argv: &[String], plan: &inject::Plan) {
    let masked = inject::format_masked(original_argv);
    eprintln!("[shtum] dry-run: would exec (values masked):");
    for (i, arg) in masked.iter().enumerate() {
        let prefix = if i == 0 { "  " } else { "    " };
        eprintln!("{prefix}{arg}");
    }
    if !plan.env.is_empty() {
        eprintln!("  env:");
        for (k, _) in &plan.env {
            eprintln!("    {k}=[REDACTED]");
        }
    }
    if plan.stdin.is_some() {
        eprintln!("  stdin: [REDACTED] (piped to subprocess)");
    }
    if !plan.tempfiles.is_empty() {
        eprintln!("  tempfiles ({}): created mode 0600 in $TMPDIR", plan.tempfiles.len());
    }
    if !plan.argv_warnings.is_empty() {
        eprintln!(
            "  warning: {{argv:...}} substituted for {} — visible in `ps`",
            plan.argv_warnings.join(", ")
        );
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

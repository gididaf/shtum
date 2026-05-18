// Copyright 2026 Gidi Dafner
// SPDX-License-Identifier: MIT

mod cli;
mod dashboard;
mod exec;
mod hook;
mod inject;
mod redact;
mod store;
mod temp;
mod tempfile;
mod util;

use anyhow::{Context, Result};
use clap::Parser;
use std::io::{IsTerminal, Read};
use std::path::Path;

use crate::cli::{
    AddArgs, Cli, Command, DashboardArgs, HookAction, QuickArgs, RenameArgs, RotateArgs, RunArgs,
    StoreAction,
};
use crate::hook::Scope;
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
        Command::Hook { action } => run_hook(action),
        Command::Dashboard(args) => run_dashboard(args),
        Command::Quick(args) => {
            run_quick(args)?;
            Ok(0)
        }
    }
}

fn run_dashboard(args: DashboardArgs) -> Result<i32> {
    dashboard::run(dashboard::DashboardOpts { port: args.port })
}

fn run_hook(action: HookAction) -> Result<i32> {
    match action {
        HookAction::Install(args) => {
            let scope = if args.project { Scope::Project } else { Scope::Global };
            hook::install(scope, args.force)?;
            Ok(0)
        }
        HookAction::Uninstall(args) => {
            let scope = if args.project { Scope::Project } else { Scope::Global };
            hook::uninstall(scope)?;
            Ok(0)
        }
        HookAction::Show => {
            hook::show()?;
            Ok(0)
        }
        HookAction::Handle => hook::handle(),
    }
}

fn run_command(args: RunArgs) -> Result<i32> {
    let store = default_store();
    sweep_temp_keys(&store);
    if args.dry_run {
        // Resolve everything (so dry-run doubles as a reachability check),
        // then display the masked argv without ever using the real values.
        // No temp-key timer bump — dry-run is explicitly side-effect-free.
        let plan = inject::build_plan(&args.cmd, &store, None)?;
        print_dry_run(&args.cmd, &plan);
        // RAII tempfiles drop here — they existed for milliseconds.
        drop(plan);
        Ok(0)
    } else {
        // Open the registry lazily — if HOME is unset or the dir is
        // unwritable we still want `shtum run` to work for users who
        // never touched `shtum quick`. A None temp-touch means "no bump"
        // which is harmless (registry is empty anyway in that case).
        let registry = temp::TempRegistry::open_default().ok();
        let touch: Option<&dyn temp::TempTouch> = registry
            .as_ref()
            .map(|r| r as &dyn temp::TempTouch);
        let mut plan = inject::build_plan(&args.cmd, &store, touch)?;
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
        StoreAction::Add(args) => add_secret(&store, args),
        StoreAction::Rotate(args) => rotate_secret(&store, args),
        StoreAction::List => list_secrets(&store),
        StoreAction::Rm { name } => {
            validate_name(&name)?;
            store.delete(&name).context("failed to remove secret")?;
            eprintln!("removed `{name}`");
            Ok(())
        }
        StoreAction::Rename(args) => rename_secret(&store, args),
    }
}

fn rename_secret(store: &impl SecretStore, args: RenameArgs) -> Result<()> {
    validate_name(&args.old)?;
    validate_name(&args.new)?;
    if args.old == args.new {
        eprintln!("`{}` unchanged (old and new names are identical)", args.old);
        return Ok(());
    }
    store
        .rename(&args.old, &args.new, args.force)
        .context("failed to rename secret")?;
    eprintln!("renamed `{}` -> `{}`", args.old, args.new);
    Ok(())
}

fn list_secrets(store: &impl SecretStore) -> Result<()> {
    sweep_temp_keys(store);
    let names = store.list().context("failed to list secrets")?;
    // Best-effort registry snapshot for annotation. If the registry can't
    // be opened (HOME unset, unreadable file) we just skip the annotation
    // and print plain names — listing must not fail on registry trouble.
    let temp_map: std::collections::HashMap<String, u64> = temp::TempRegistry::open_default()
        .ok()
        .map(|r| {
            r.snapshot()
                .into_iter()
                .map(|e| {
                    let exp = e.expires_at();
                    (e.name, exp)
                })
                .collect()
        })
        .unwrap_or_default();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    for n in names {
        match temp_map.get(&n) {
            Some(&exp) if exp > now => {
                let remaining = std::time::Duration::from_secs(exp - now);
                println!(
                    "{n} (temp, expires in {})",
                    temp::format_remaining(remaining),
                );
            }
            Some(_) => {
                // Expired but not yet swept (sweep is lazy and this same
                // call already ran one — likely an open-fail or a
                // backend error keeping the entry alive). Mark plainly.
                println!("{n} (temp, expired)");
            }
            None => println!("{n}"),
        }
    }
    Ok(())
}

fn run_quick(args: QuickArgs) -> Result<()> {
    let store = default_store();
    sweep_temp_keys(&store);
    let value = if let Some(v) = args.value {
        v.into_bytes()
    } else {
        read_value("new temp key", args.from_file.as_deref(), args.from_stdin)?
    };
    if value.is_empty() {
        anyhow::bail!("refusing to store an empty value");
    }
    let registry = temp::TempRegistry::open_default()
        .context("opening temp-key registry")?;
    let ttl = args.ttl.unwrap_or_else(|| {
        std::time::Duration::from_secs(temp::DEFAULT_TTL_SECONDS)
    });

    // Generate-and-add with collision retry. Store.add (force=false) is
    // the atomic uniqueness check — if we lose a race against another
    // process that happens to pick the same TMP_xxxxxx, the loser
    // generates a fresh name. 10 attempts is overkill against a 62^6
    // (~5.7e10) keyspace; we'd need to hold ~250k entries before even
    // the first attempt has a 1% collision rate.
    let mut last_err: Option<StoreError> = None;
    let mut chosen: Option<String> = None;
    for _ in 0..10 {
        let candidate = temp::generate_temp_name()
            .context("generating temp-key name")?;
        match store.add(&candidate, &value, false) {
            Ok(()) => {
                chosen = Some(candidate);
                break;
            }
            Err(StoreError::AlreadyExists(_)) => continue,
            Err(e) => {
                last_err = Some(e);
                break;
            }
        }
    }
    let name = match chosen {
        Some(n) => n,
        None => {
            if let Some(e) = last_err {
                return Err(anyhow::Error::from(e).context("failed to store temp value"));
            }
            anyhow::bail!(
                "could not find an unused TMP_* name after 10 attempts; \
                 this is extremely unlikely — does ~/Library/Application Support/shtum \
                 contain an enormous registry?"
            );
        }
    };

    registry
        .register(&name, ttl)
        .with_context(|| format!("registering {name} in temp-key registry"))?;

    // stdout: just the name, easy to pipe / capture.
    println!("{name}");
    // stderr: human-friendly hint.
    eprintln!(
        "created temp key `{name}`, expires after {} idle. use as `{{{name}}}` in `shtum run`.",
        temp::format_duration_compact(ttl)
    );
    Ok(())
}

/// Thin alias retained so existing call sites keep reading naturally.
/// The real implementation lives in `temp::sweep_default` because the
/// dashboard module needs the same behaviour and depending on
/// `main`-only helpers from `dashboard::` would be wrong-way coupling.
fn sweep_temp_keys<S: SecretStore + ?Sized>(store: &S) {
    temp::sweep_default(store);
}

fn add_secret(store: &impl SecretStore, args: AddArgs) -> Result<()> {
    validate_name(&args.name)?;
    let value = read_value(&args.name, args.from_file.as_deref(), args.from_stdin)?;
    if value.is_empty() {
        anyhow::bail!("refusing to store an empty value");
    }
    match store.add(&args.name, &value, args.force) {
        Ok(()) => {
            eprintln!("stored `{}`", args.name);
            Ok(())
        }
        Err(StoreError::AlreadyExists(n)) => anyhow::bail!(
            "`{n}` already exists. Use `shtum store rotate {n}` to replace its value, or pass `--force` to overwrite.",
        ),
        Err(e) => Err(e).context("failed to store secret"),
    }
}

fn rotate_secret(store: &impl SecretStore, args: RotateArgs) -> Result<()> {
    validate_name(&args.name)?;
    let value = read_value(&args.name, args.from_file.as_deref(), args.from_stdin)?;
    if value.is_empty() {
        anyhow::bail!("refusing to store an empty value");
    }
    match store.delete(&args.name) {
        Ok(()) | Err(StoreError::NotFound(_)) => {}
        Err(e) => return Err(e.into()),
    }
    store
        .set(&args.name, &value)
        .context("failed to store secret")?;
    eprintln!("rotated `{}`", args.name);
    Ok(())
}

fn read_value(name: &str, from_file: Option<&Path>, from_stdin: bool) -> Result<Vec<u8>> {
    if let Some(path) = from_file {
        return read_from_file(path);
    }
    if from_stdin {
        return read_from_stdin();
    }
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        let prompt = format!("Enter value for `{name}`: ");
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

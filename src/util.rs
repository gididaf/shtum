// Copyright 2026 Gidi Dafner
// SPDX-License-Identifier: Apache-2.0

//! Cross-module helpers that have no better home.

use anyhow::{Context, Result};
use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::Path;

/// Absolute path to the currently-running `shtum` binary, as UTF-8. Used by
/// the hook installer (to write the absolute path into Claude's settings)
/// and the dashboard (to show ready-to-copy install snippets that work
/// regardless of `$PATH`).
pub fn shtum_exe_path() -> Result<String> {
    let exe = std::env::current_exe().context("locating current shtum binary path")?;
    Ok(exe
        .to_str()
        .context("shtum binary path is not valid UTF-8")?
        .to_string())
}

/// Write a JSON value to `path` atomically: serialize to a sibling temp file
/// (`.<name>.shtum.tmp`), `fsync`, then `rename` over the target. Creates
/// parent directories on demand. Callers that need read-modify-write
/// serialization across processes must hold an external lock around the
/// load → modify → atomic_write_json sequence themselves; this function is
/// only atomic with respect to a single writer.
pub fn atomic_write_json(path: &Path, value: &Value) -> Result<()> {
    let parent = path
        .parent()
        .context("path has no parent directory")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("creating {}", parent.display()))?;
    let file_name = path
        .file_name()
        .context("path has no file name")?
        .to_string_lossy()
        .into_owned();
    let tmp = parent.join(format!(".{file_name}.shtum.tmp"));
    let json = serde_json::to_string_pretty(value)?;
    {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        f.write_all(json.as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

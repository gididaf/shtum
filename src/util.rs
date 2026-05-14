//! Cross-module helpers that have no better home.

use anyhow::{Context, Result};

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

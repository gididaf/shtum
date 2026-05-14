use anyhow::{Context, Result};
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::process::ExitStatusExt;
use std::process::Command;

use crate::inject::Plan;

/// Spawn the planned subprocess directly (no shell), wait for it, and return
/// the exit code (mapping signal kills to 128+signum, per shell convention).
pub fn run_plan(plan: Plan) -> Result<i32> {
    let mut iter = plan.argv.into_iter();
    let program = iter.next().context("empty argv after placeholder expansion")?;
    let program_os = OsString::from_vec(program);
    let mut cmd = Command::new(&program_os);
    for arg in iter {
        cmd.arg(OsString::from_vec(arg));
    }
    let status = cmd
        .status()
        .with_context(|| format!("failed to spawn `{}`", program_os.to_string_lossy()))?;
    if let Some(code) = status.code() {
        Ok(code)
    } else if let Some(sig) = status.signal() {
        Ok(128 + sig)
    } else {
        Ok(1)
    }
}

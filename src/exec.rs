use anyhow::{Context, Result};
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::process::ExitStatusExt;
use std::process::Command;

use crate::inject::Plan;

/// Spawn the planned subprocess via `sh -c` with the injected env vars,
/// wait for it, and return the exit code (mapping signal kills to 128+signum).
pub fn run_plan(plan: Plan) -> Result<i32> {
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg(&plan.shell_cmd);
    for (name, value) in plan.env {
        cmd.env(name, OsString::from_vec(value));
    }
    let status = cmd
        .status()
        .context("failed to spawn `sh -c` subprocess")?;
    if let Some(code) = status.code() {
        Ok(code)
    } else if let Some(sig) = status.signal() {
        Ok(128 + sig)
    } else {
        Ok(1)
    }
}

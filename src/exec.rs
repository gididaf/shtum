use anyhow::{Context, Result};
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};
use std::thread;

use crate::inject::Plan;
use crate::redact::Filter;

/// Spawn the planned subprocess directly (no shell), wait for it, and return
/// the exit code (mapping signal kills to 128+signum, per shell convention).
///
/// When `redact` is true and the plan resolved any secrets, stdout and stderr
/// are piped through a sliding-window filter that scrubs literal /
/// URL-encoded / base64-of-literal occurrences of each secret value out of
/// the streams before they reach the caller's terminal. Otherwise stdio is
/// inherited directly (preserves TTY behavior).
pub fn run_plan(plan: Plan, redact: bool) -> Result<i32> {
    let Plan { argv, secrets } = plan;
    let mut iter = argv.into_iter();
    let program = iter.next().context("empty argv after placeholder expansion")?;
    let program_os = OsString::from_vec(program);
    let mut cmd = Command::new(&program_os);
    for arg in iter {
        cmd.arg(OsString::from_vec(arg));
    }

    if !redact || secrets.is_empty() {
        let status = cmd
            .status()
            .with_context(|| format!("failed to spawn `{}`", program_os.to_string_lossy()))?;
        return Ok(exit_code(status));
    }

    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .with_context(|| format!("failed to spawn `{}`", program_os.to_string_lossy()))?;

    let child_stdout = child.stdout.take().expect("stdout piped");
    let child_stderr = child.stderr.take().expect("stderr piped");

    let secrets_out = secrets.clone();
    let out_handle = thread::spawn(move || -> io::Result<()> {
        pipe_filtered(child_stdout, io::stdout(), &secrets_out)
    });
    let secrets_err = secrets;
    let err_handle = thread::spawn(move || -> io::Result<()> {
        pipe_filtered(child_stderr, io::stderr(), &secrets_err)
    });

    let status = child.wait().context("failed to wait on child")?;
    out_handle
        .join()
        .map_err(|_| anyhow::anyhow!("stdout filter thread panicked"))?
        .context("stdout filter failed")?;
    err_handle
        .join()
        .map_err(|_| anyhow::anyhow!("stderr filter thread panicked"))?
        .context("stderr filter failed")?;

    Ok(exit_code(status))
}

fn exit_code(status: std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        code
    } else if let Some(sig) = status.signal() {
        128 + sig
    } else {
        1
    }
}

fn pipe_filtered<R: Read, W: Write>(mut r: R, mut w: W, secrets: &[Vec<u8>]) -> io::Result<()> {
    let mut filter = Filter::new(secrets);
    let mut buf = [0u8; 8192];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let out = filter.push(&buf[..n]);
        if !out.is_empty() {
            w.write_all(&out)?;
            w.flush()?;
        }
    }
    let tail = filter.flush();
    if !tail.is_empty() {
        w.write_all(&tail)?;
        w.flush()?;
    }
    Ok(())
}

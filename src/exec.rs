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
/// When `redact` is true and the plan resolved any secrets, stdout and
/// stderr are piped through a sliding-window filter that scrubs literal /
/// URL-encoded / base64-of-literal occurrences of each secret value out of
/// the streams before they reach the caller's terminal. Otherwise stdio is
/// inherited directly (preserves TTY behavior).
///
/// `plan.env` is applied to the subprocess env. `plan.stdin`, if present,
/// is piped to the subprocess's stdin and then closed (signaling EOF).
/// `plan.tempfiles` is held alive until after `wait()` returns so the RAII
/// guards' Drop runs only after the subprocess has finished reading them.
pub fn run_plan(plan: Plan, redact: bool) -> Result<i32> {
    let Plan {
        argv,
        secrets,
        env,
        stdin,
        argv_warnings: _,
        tempfiles,
    } = plan;
    let mut iter = argv.into_iter();
    let program = iter.next().context("empty argv after placeholder expansion")?;
    let program_os = OsString::from_vec(program);
    let mut cmd = Command::new(&program_os);
    for arg in iter {
        cmd.arg(OsString::from_vec(arg));
    }
    for (k, v) in &env {
        cmd.env(k, OsString::from_vec(v.clone()));
    }

    let pipe_output = redact && !secrets.is_empty();
    let pipe_input = stdin.is_some();

    if pipe_input {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::inherit());
    }
    if pipe_output {
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    } else {
        cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    }

    let mut child = cmd
        .spawn()
        .with_context(|| format!("failed to spawn `{}`", program_os.to_string_lossy()))?;

    let stdin_handle = if let Some(bytes) = stdin {
        let mut child_stdin = child.stdin.take().expect("stdin piped");
        Some(thread::spawn(move || -> io::Result<()> {
            child_stdin.write_all(&bytes)?;
            // Drop closes the pipe -> EOF for the subprocess.
            Ok(())
        }))
    } else {
        None
    };

    let (out_handle, err_handle) = if pipe_output {
        let child_stdout = child.stdout.take().expect("stdout piped");
        let child_stderr = child.stderr.take().expect("stderr piped");
        let secrets_out = secrets.clone();
        let secrets_err = secrets;
        let oh = thread::spawn(move || -> io::Result<()> {
            pipe_filtered(child_stdout, io::stdout(), &secrets_out)
        });
        let eh = thread::spawn(move || -> io::Result<()> {
            pipe_filtered(child_stderr, io::stderr(), &secrets_err)
        });
        (Some(oh), Some(eh))
    } else {
        (None, None)
    };

    let status = child.wait().context("failed to wait on child")?;

    if let Some(h) = stdin_handle {
        let _ = h
            .join()
            .map_err(|_| anyhow::anyhow!("stdin writer thread panicked"))?;
    }
    if let Some(h) = out_handle {
        h.join()
            .map_err(|_| anyhow::anyhow!("stdout filter thread panicked"))?
            .context("stdout filter failed")?;
    }
    if let Some(h) = err_handle {
        h.join()
            .map_err(|_| anyhow::anyhow!("stderr filter thread panicked"))?
            .context("stderr filter failed")?;
    }

    // Explicitly drop tempfile guards AFTER the subprocess exits — Drop
    // unlinks the files. Holding them on the stack until here ensures the
    // child could read them throughout its lifetime.
    drop(tempfiles);

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

// Copyright 2026 Gidi Dafner
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// Owns a temp file containing a secret value. The file is created mode
/// `0600` (owner read/write only) so other users on the system cannot read
/// it; same-user processes still can — `shtum`'s threat model treats the
/// local user as trusted (see PLAN.md §9).
///
/// `Drop` unlinks the file. A crash that bypasses Drop (SIGKILL, panic in a
/// thread that doesn't unwind, etc.) will leak the file; a startup sweep is
/// deferred to v2.
pub struct TempFileGuard {
    path: PathBuf,
}

impl TempFileGuard {
    pub fn create_with_value(name_hint: &str, value: &[u8]) -> Result<Self> {
        let dir = std::env::var_os("TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        let pid = std::process::id();
        let suffix = random_suffix()?;
        let path = dir.join(format!("shtum-{pid}-{suffix}-{name_hint}"));

        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("creating tempfile {}", path.display()))?;
        file.write_all(value)
            .with_context(|| format!("writing tempfile {}", path.display()))?;
        file.sync_all()
            .with_context(|| format!("flushing tempfile {}", path.display()))?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn random_suffix() -> Result<String> {
    let mut buf = [0u8; 8];
    let mut f = std::fs::File::open("/dev/urandom").context("opening /dev/urandom")?;
    f.read_exact(&mut buf).context("reading /dev/urandom")?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

//! Locating and executing the genuine `probe-rs` binary.
//!
//! Two callers:
//!
//! * **Local fallback** ([`exec_local`]): no fleet selector set ⇒ run the real
//!   `probe-rs` transparently with the original argv, so local developer
//!   experience is unchanged.
//! * **Fleet proxy** ([`build_remote_env`]): a board was leased ⇒ run the real
//!   `probe-rs` but point it at the sidecar's local relay endpoint via
//!   `PROBE_RS_REMOTE_HOST` / `PROBE_RS_REMOTE_TOKEN`. The genuine client does
//!   probe + chip selection in-band and computes the exit code itself.
//!
//! In both cases we hand the genuine client an unaltered argv and propagate its
//! exit code.
//!
//! ## Recursion guard
//!
//! The sidecar is installed as a `probe-rs` shim on `PATH` (argv0 dispatch). If
//! we naively re-ran the first `probe-rs` on `PATH` we would re-invoke
//! *ourselves*. [`find_real_probe_rs`] therefore skips any `PATH` entry whose
//! canonicalised target equals our own executable.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Environment variable names the genuine probe-rs client honours for remote
/// operation (probe-rs 0.31).
pub mod remote_env {
    /// Remote host the probe-rs client connects to as its remote. Must be a
    /// `ws://`/`wss://` base URL (the client appends `/worker` and dials it as
    /// a WebSocket), e.g. `ws://127.0.0.1:51001`.
    pub const HOST: &str = "PROBE_RS_REMOTE_HOST";
    /// Bearer token the probe-rs client presents to the remote.
    pub const TOKEN: &str = "PROBE_RS_REMOTE_TOKEN";
}

/// Errors from locating / running the real probe-rs.
#[derive(Debug, thiserror::Error)]
pub enum LocalError {
    /// No `probe-rs` binary (other than our own shim) was found on `PATH`.
    #[error("no real `probe-rs` binary found on PATH (is probe-rs installed?)")]
    NotFound,
    /// Failed to spawn the real probe-rs.
    #[error("failed to execute `{path}`: {source}")]
    Spawn {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Locate the real `probe-rs` binary on `PATH`, skipping `self_exe` (our own
/// shim) so we never recurse into ourselves.
///
/// `path_var` is the raw `PATH` string; `self_exe` is the canonicalised path of
/// the currently-running executable (see [`std::env::current_exe`]). Splitting
/// these out keeps the function unit-testable without touching the real env.
///
/// # Errors
///
/// Returns [`LocalError::NotFound`] if no suitable binary exists on `PATH`.
pub fn find_real_probe_rs(
    path_var: &str,
    self_exe: Option<&Path>,
) -> Result<PathBuf, LocalError> {
    let exe_name = if cfg!(windows) {
        "probe-rs.exe"
    } else {
        "probe-rs"
    };
    let self_canon = self_exe.and_then(|p| std::fs::canonicalize(p).ok());

    for dir in std::env::split_paths(path_var) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        let candidate = dir.join(exe_name);
        if !is_executable_file(&candidate) {
            continue;
        }
        // Skip our own shim (compare canonicalised paths to see through
        // symlinks / hardlinks).
        let cand_canon = std::fs::canonicalize(&candidate).unwrap_or_else(|_| candidate.clone());
        if let Some(self_canon) = &self_canon {
            if &cand_canon == self_canon {
                continue;
            }
        }
        return Ok(candidate);
    }
    Err(LocalError::NotFound)
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(meta) => meta.is_file() && (meta.permissions().mode() & 0o111 != 0),
        Err(_) => false,
    }
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

/// Build the environment overrides that point the genuine probe-rs client at
/// the sidecar's local relay endpoint.
///
/// Returns the `(key, value)` pairs to set on the child process: the remote
/// host (the sidecar's local endpoint as a `ws://` base URL, e.g.
/// `ws://127.0.0.1:51001`) and, if a lease token is present, the remote token.
#[must_use]
pub fn build_remote_env(remote_host: &str, token: Option<&str>) -> Vec<(String, String)> {
    let mut env = vec![(remote_env::HOST.to_owned(), remote_host.to_owned())];
    if let Some(token) = token {
        env.push((remote_env::TOKEN.to_owned(), token.to_owned()));
    }
    env
}

/// Spawn the real probe-rs with `args` (the original argv after `argv[0]`) and
/// the given extra environment, returning its exit code.
///
/// On success the returned `i32` is the child's exit code (or, on Unix, the
/// `128 + signal` convention if it was killed by a signal). This is the value
/// the sidecar should exit with, giving free exit-code propagation.
///
/// # Errors
///
/// Returns [`LocalError::Spawn`] if the child could not be launched or waited
/// on.
pub fn run_real_probe_rs<I, A>(
    real: &Path,
    args: I,
    extra_env: &[(String, String)],
) -> Result<i32, LocalError>
where
    I: IntoIterator<Item = A>,
    A: AsRef<OsStr>,
{
    let mut cmd = std::process::Command::new(real);
    cmd.args(args);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let status = cmd.status().map_err(|source| LocalError::Spawn {
        path: real.to_path_buf(),
        source,
    })?;
    Ok(exit_code_from_status(status))
}

/// Map a child [`ExitStatus`](std::process::ExitStatus) to the process exit
/// code we should propagate.
///
/// * normal exit ⇒ that code;
/// * killed by signal (Unix) ⇒ `128 + signal` (shell convention);
/// * otherwise ⇒ `1`.
#[must_use]
pub fn exit_code_from_status(status: std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return 128 + sig;
        }
    }
    1
}

/// Transparent local fallback: locate and run the real probe-rs with the
/// original argv (after `argv[0]`), no remote env. Returns its exit code.
///
/// # Errors
///
/// Returns [`LocalError`] if no real probe-rs is found or it fails to launch.
pub fn exec_local<I, A>(args: I) -> Result<i32, LocalError>
where
    I: IntoIterator<Item = A>,
    A: AsRef<OsStr>,
{
    let path_var = std::env::var_os("PATH").unwrap_or_default();
    let path_var = path_var.to_string_lossy();
    let self_exe = std::env::current_exe().ok();
    let real = find_real_probe_rs(&path_var, self_exe.as_deref())?;
    run_real_probe_rs(&real, args, &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_remote_env_with_token() {
        let env = build_remote_env("127.0.0.1:51001", Some("tok"));
        assert_eq!(
            env,
            vec![
                (remote_env::HOST.to_owned(), "127.0.0.1:51001".to_owned()),
                (remote_env::TOKEN.to_owned(), "tok".to_owned()),
            ]
        );
    }

    #[test]
    fn build_remote_env_without_token() {
        let env = build_remote_env("127.0.0.1:51001", None);
        assert_eq!(
            env,
            vec![(remote_env::HOST.to_owned(), "127.0.0.1:51001".to_owned())]
        );
    }

    #[cfg(unix)]
    #[test]
    fn finds_real_probe_rs_and_skips_self() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("frs-test-{}", std::process::id()));
        let shim_dir = dir.join("shim");
        let real_dir = dir.join("real");
        std::fs::create_dir_all(&shim_dir).unwrap();
        std::fs::create_dir_all(&real_dir).unwrap();

        let shim = shim_dir.join("probe-rs");
        let real = real_dir.join("probe-rs");
        std::fs::write(&shim, b"#!/bin/sh\n").unwrap();
        std::fs::write(&real, b"#!/bin/sh\n").unwrap();
        for p in [&shim, &real] {
            let mut perms = std::fs::metadata(p).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(p, perms).unwrap();
        }

        // PATH lists the shim dir first, then the real dir. With self_exe ==
        // shim, the shim must be skipped and the real one found.
        let path_var = std::env::join_paths([&shim_dir, &real_dir])
            .unwrap()
            .into_string()
            .unwrap();

        let found = find_real_probe_rs(&path_var, Some(&shim)).unwrap();
        assert_eq!(
            std::fs::canonicalize(&found).unwrap(),
            std::fs::canonicalize(&real).unwrap()
        );

        // Without a self_exe, the first match (the shim) wins.
        let found_any = find_real_probe_rs(&path_var, None).unwrap();
        assert_eq!(
            std::fs::canonicalize(&found_any).unwrap(),
            std::fs::canonicalize(&shim).unwrap()
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn not_found_on_empty_path() {
        let err = find_real_probe_rs("", None).unwrap_err();
        assert!(matches!(err, LocalError::NotFound));
    }

    #[cfg(unix)]
    #[test]
    fn exit_code_success_and_failure() {
        // `true` exits 0, `false` exits 1 — exercise real status propagation.
        let zero = run_real_probe_rs(Path::new("/bin/sh"), ["-c", "exit 0"], &[]).unwrap();
        assert_eq!(zero, 0);
        let seven = run_real_probe_rs(Path::new("/bin/sh"), ["-c", "exit 7"], &[]).unwrap();
        assert_eq!(seven, 7);
    }

    #[cfg(unix)]
    #[test]
    fn exit_code_from_signal() {
        // Kill self with SIGKILL (9) → 128 + 9 = 137.
        let code =
            run_real_probe_rs(Path::new("/bin/sh"), ["-c", "kill -9 $$"], &[]).unwrap();
        assert_eq!(code, 137);
    }

    #[test]
    fn spawn_error_for_missing_binary() {
        let err = run_real_probe_rs(
            Path::new("/nonexistent/probe-rs-xyz"),
            ["run"],
            &[],
        )
        .unwrap_err();
        assert!(matches!(err, LocalError::Spawn { .. }));
    }
}

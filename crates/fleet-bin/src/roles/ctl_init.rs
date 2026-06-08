//! The `ctl init` subcommand: import an enrollment bundle and write
//! `client.toml` so both `ctl` and the `probe-rs` sidecar shim discover the
//! coordinator endpoint + client credentials from one place.
//!
//! Run on a workstation / CI host after `coordinator enroll <user> --kind
//! client` has produced a bundle. The coordinator endpoint comes from the
//! shared `--coordinator` flag (or `PROBE_RS_FLEET_COORDINATOR`).

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::cli::{CtlClientArgs, CtlInitArgs};
use crate::config::render_client_config;
use crate::paths;
use crate::secrets::{import_public, import_secret, write_public};

/// Imported credential filenames under the data dir.
const CLIENT_CERT_FILE: &str = "client-cert.pem";
const CLIENT_KEY_FILE: &str = "client-key.pem";
const CLIENT_CA_FILE: &str = "client-ca.pem";
const CLIENT_CONFIG_FILE: &str = "client.toml";

/// Bundle filenames produced by `coordinator enroll`.
const BUNDLE_CERT_FILE: &str = "cert.pem";
const BUNDLE_KEY_FILE: &str = "key.pem";
const BUNDLE_CA_FILE: &str = "client-ca.pem";

/// Run `ctl init`.
///
/// # Errors
///
/// Returns an error if the coordinator endpoint or credentials cannot be
/// resolved, any file cannot be imported, or (without `--force`) a target file
/// already exists.
pub fn run(args: CtlInitArgs, client: CtlClientArgs) -> Result<()> {
    let CtlInitArgs {
        bundle,
        config_dir,
        data_dir,
        force,
    } = args;
    let CtlClientArgs {
        coordinator,
        cert,
        key,
        ca,
    } = client;

    let config_dir = match config_dir {
        Some(dir) => dir,
        None => paths::config_dir()?,
    };
    let data_dir = match data_dir {
        Some(dir) => dir,
        None => paths::data_dir()?,
    };

    let coordinator = coordinator
        .context("--coordinator (or PROBE_RS_FLEET_COORDINATOR) is required for `ctl init`")?;

    let (src_cert, src_key, src_ca) = resolve_sources(bundle.as_deref(), cert, key, ca)?;

    std::fs::create_dir_all(&config_dir)
        .with_context(|| format!("creating config dir {}", config_dir.display()))?;
    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("creating data dir {}", data_dir.display()))?;

    let cert_path = data_dir.join(CLIENT_CERT_FILE);
    let key_path = data_dir.join(CLIENT_KEY_FILE);
    let ca_path = data_dir.join(CLIENT_CA_FILE);
    let config_path = config_dir.join(CLIENT_CONFIG_FILE);

    // Idempotency guard.
    if !force {
        let existing: Vec<&Path> = [
            cert_path.as_path(),
            key_path.as_path(),
            ca_path.as_path(),
            config_path.as_path(),
        ]
        .into_iter()
        .filter(|p| p.exists())
        .collect();
        if !existing.is_empty() {
            let list = existing
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join("\n  ");
            bail!("refusing to overwrite existing file(s); pass --force to regenerate:\n  {list}");
        }
    }

    import_public(&src_cert, &cert_path)
        .with_context(|| format!("importing client cert from {}", src_cert.display()))?;
    import_secret(&src_key, &key_path)
        .with_context(|| format!("importing client key from {}", src_key.display()))?;
    import_public(&src_ca, &ca_path)
        .with_context(|| format!("importing CA from {}", src_ca.display()))?;

    let config_toml = render_client_config(&coordinator, &cert_path, &key_path, &ca_path);
    write_public(&config_path, config_toml.as_bytes())
        .with_context(|| format!("writing client config {}", config_path.display()))?;

    print_summary(&config_path, &coordinator, &cert_path, &key_path, &ca_path);
    Ok(())
}

/// Resolve cert/key/ca source paths from explicit flags and/or the bundle.
/// Explicit flags override bundle files.
fn resolve_sources(
    bundle: Option<&Path>,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    ca: Option<PathBuf>,
) -> Result<(PathBuf, PathBuf, PathBuf)> {
    let (bundle_cert, bundle_key, bundle_ca) = if let Some(bundle) = bundle {
        (
            Some(bundle.join(BUNDLE_CERT_FILE)),
            Some(bundle.join(BUNDLE_KEY_FILE)),
            Some(bundle.join(BUNDLE_CA_FILE)),
        )
    } else {
        (None, None, None)
    };

    let cert = cert
        .or(bundle_cert)
        .context("provide --bundle or an explicit --cert")?;
    let key = key
        .or(bundle_key)
        .context("provide --bundle or an explicit --key")?;
    let ca = ca
        .or(bundle_ca)
        .context("provide --bundle or an explicit --ca")?;
    Ok((cert, key, ca))
}

/// Print a summary + next steps.
fn print_summary(
    config_path: &Path,
    coordinator: &str,
    cert_path: &Path,
    key_path: &Path,
    ca_path: &Path,
) {
    println!("Initialised client config for coordinator '{coordinator}':");
    println!("  config  {}", config_path.display());
    println!("  cert    {}", cert_path.display());
    println!("  key     {}", key_path.display());
    println!("  ca      {}", ca_path.display());
    println!();
    println!("This configures both `ctl` and the `probe-rs` sidecar shim.");
    println!("Next steps:");
    println!("  probe-rs-fleet ctl list");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roles::enroll::issue_client_cert;
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose,
    };

    fn mint_ca() -> (String, String) {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "probe-rs-fleet client CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        (ca_cert.pem(), ca_key.serialize_pem())
    }

    fn make_bundle(dir: &Path) {
        let (ca_pem, ca_key_pem) = mint_ca();
        let issued = issue_client_cert("alice", &ca_pem, &ca_key_pem).unwrap();
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(BUNDLE_CERT_FILE), issued.cert_pem).unwrap();
        std::fs::write(dir.join(BUNDLE_KEY_FILE), issued.key_pem).unwrap();
        std::fs::write(dir.join(BUNDLE_CA_FILE), ca_pem).unwrap();
    }

    fn args_for(tmp: &Path, bundle: &Path) -> (CtlInitArgs, CtlClientArgs) {
        (
            CtlInitArgs {
                bundle: Some(bundle.to_path_buf()),
                config_dir: Some(tmp.join("config")),
                data_dir: Some(tmp.join("data")),
                force: false,
            },
            CtlClientArgs {
                coordinator: Some("coord.example:7000".to_owned()),
                cert: None,
                key: None,
                ca: None,
            },
        )
    }

    #[test]
    fn writes_loadable_client_config() {
        let tmp = tempfile::tempdir().unwrap();
        let bundle = tmp.path().join("bundle");
        make_bundle(&bundle);
        let (a, c) = args_for(tmp.path(), &bundle);
        run(a, c).unwrap();

        let config_path = tmp.path().join("config").join(CLIENT_CONFIG_FILE);
        let cfg = crate::config::load_client_config(&config_path).unwrap();
        assert_eq!(cfg.coordinator, "coord.example:7000");
        assert!(cfg.cert.ends_with(CLIENT_CERT_FILE));
        assert!(cfg.key.ends_with(CLIENT_KEY_FILE));
        assert!(cfg.ca.ends_with(CLIENT_CA_FILE));
    }

    #[cfg(unix)]
    #[test]
    fn imported_key_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let bundle = tmp.path().join("bundle");
        make_bundle(&bundle);
        let (a, c) = args_for(tmp.path(), &bundle);
        run(a, c).unwrap();
        let key = tmp.path().join("data").join(CLIENT_KEY_FILE);
        let mode = std::fs::metadata(&key).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn refuses_overwrite_without_force() {
        let tmp = tempfile::tempdir().unwrap();
        let bundle = tmp.path().join("bundle");
        make_bundle(&bundle);
        let (a, c) = args_for(tmp.path(), &bundle);
        run(a, c).unwrap();

        let (a2, c2) = args_for(tmp.path(), &bundle);
        assert!(run(a2, c2).is_err());

        let (mut a3, c3) = args_for(tmp.path(), &bundle);
        a3.force = true;
        run(a3, c3).unwrap();
    }

    #[test]
    fn requires_coordinator() {
        let tmp = tempfile::tempdir().unwrap();
        let bundle = tmp.path().join("bundle");
        make_bundle(&bundle);
        let (a, mut c) = args_for(tmp.path(), &bundle);
        c.coordinator = None;
        assert!(run(a, c).is_err());
    }
}

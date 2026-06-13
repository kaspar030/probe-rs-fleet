//! Shared bootstrap-enrollment client logic for `agent init` / `ctl init`.
//!
//! Decodes an enrollment token, opens a pinned bootstrap TLS connection to the
//! coordinator (verifying the server leaf against the token's SHA-256 hash —
//! not blind trust-on-first-use), generates a keypair + CSR **locally** (the
//! private key never leaves this host), redeems the one-time secret, and
//! returns the CA-signed client certificate.

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use fleet_coordinator::proto::{read_frame, write_frame};
use fleet_proto::enroll::{EnrollRequest, EnrollResponse, EnrollmentToken};

/// The outcome of a successful bootstrap enrollment.
pub struct Enrolled {
    /// The CA-signed client certificate (PEM).
    pub client_cert_pem: String,
    /// The locally-generated client private key (PEM); never left this host.
    pub client_key_pem: String,
    /// The client CA certificate (PEM), for runtime mTLS server verification.
    pub ca_cert_pem: String,
    /// Hex-encoded ed25519 public key of the coordinator's token signer.
    pub coordinator_token_pubkey: String,
    /// The coordinator address (`host:port`) carried in the token.
    pub coordinator_addr: String,
}

/// Redeem `token` against the coordinator over a pinned bootstrap TLS
/// connection, returning the issued credentials.
///
/// # Errors
///
/// Returns an error if the token is malformed, the bootstrap connection or
/// handshake fails, the CSR cannot be generated, or the coordinator rejects the
/// enrollment.
pub async fn enroll(token: &str) -> Result<Enrolled> {
    let token =
        EnrollmentToken::from_compact_string(token).context("decoding enrollment token")?;

    // Generate a keypair + CSR locally. The coordinator overrides the subject
    // (CN), so we don't set a meaningful CN here.
    let key_pair = KeyPair::generate().context("generating client key pair")?;
    let csr = CertificateParams::default()
        .serialize_request(&key_pair)
        .context("building CSR")?;
    let csr_pem = csr.pem().context("encoding CSR as PEM")?;

    // Pinned bootstrap TLS: verify the server leaf against the token's hash.
    let tls_config = fleet_tls::bootstrap_client_config(token.server_cert_sha256);
    let connector = TlsConnector::from(Arc::new(tls_config));

    let tcp = TcpStream::connect(&token.coordinator_addr)
        .await
        .with_context(|| format!("connecting to coordinator {}", token.coordinator_addr))?;
    let _ = tcp.set_nodelay(true);

    let server_name = server_name(&token.coordinator_addr)?;
    let tls = connector
        .connect(server_name, tcp)
        .await
        .context("bootstrap TLS handshake (server cert pin mismatch?)")?;

    let (mut reader, mut writer) = tokio::io::split(tls);

    let req = EnrollRequest {
        secret: token.secret,
        csr_pem,
    };
    write_frame(&mut writer, &req)
        .await
        .context("sending enrollment request")?;

    let resp: EnrollResponse = read_frame(&mut reader)
        .await
        .context("reading enrollment response")?;

    match resp {
        EnrollResponse::Accepted {
            client_cert_pem,
            ca_cert_pem,
            coordinator_token_pubkey,
        } => Ok(Enrolled {
            client_cert_pem,
            client_key_pem: key_pair.serialize_pem(),
            ca_cert_pem,
            coordinator_token_pubkey,
            coordinator_addr: token.coordinator_addr,
        }),
        EnrollResponse::Rejected { reason } => {
            bail!("enrollment rejected by coordinator: {reason}")
        }
    }
}

/// Derive a TLS `ServerName` from a `host:port` address (IP or DNS).
fn server_name(addr: &str) -> Result<ServerName<'static>> {
    let host = addr.rsplit_once(':').map_or(addr, |(h, _)| h);
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(ServerName::IpAddress(ip.into()));
    }
    ServerName::try_from(host.to_owned())
        .map_err(|e| anyhow::anyhow!("invalid server name '{host}': {e}"))
}

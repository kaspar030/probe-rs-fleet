//! Mutual-TLS configuration and certificate-pinning helpers for probe-rs-fleet.
//!
//! This crate builds [`rustls`] configurations and exposes small helpers; it
//! deliberately performs **no I/O**. It does not open sockets, run an accept
//! loop, or speak any application protocol. Callers wrap the resulting configs
//! in [`tokio_rustls::TlsAcceptor`] / [`tokio_rustls::TlsConnector`] around a
//! tokio `TcpStream`, and the control-plane RPC (postcard-rpc) rides on top of
//! the resulting `TlsStream` (which is `AsyncRead + AsyncWrite`).
//!
//! # Topology
//!
//! * The **coordinator** is the only listener. It uses [`server_config`] to
//!   require client authentication (mTLS): every peer must present a client
//!   certificate signed by a trusted CA.
//! * **Agents** (persistent connection) and **sidecars** (per-session
//!   connection) dial out to the coordinator. They use [`client_config`] to
//!   present their own client certificate + key and to verify the
//!   coordinator's server certificate against a trusted CA.
//!
//! # Identity
//!
//! Once a handshake completes, the coordinator derives a peer identity from the
//! verified end-entity certificate:
//!
//! * [`principal_from_cert`] extracts a [`Principal`] from the certificate's
//!   Subject Common Name (CN), falling back to the first DNS Subject
//!   Alternative Name. See the function docs for the rationale.
//! * [`cert_fingerprint`] returns the lowercase-hex SHA-256 of the
//!   certificate DER. The coordinator pins agent identities by this
//!   fingerprint (configuration maps fingerprint → [`AgentId`]).
//!
//! No `unsafe` code is used.

use std::io;
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

use fleet_proto::{AgentId, Principal};

/// Errors produced while loading PEM material or building a TLS config.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// Failed to read a file from disk.
    #[error("failed to read {path}: {source}")]
    Read {
        /// The path that could not be read.
        path: String,
        /// The underlying I/O error.
        source: io::Error,
    },

    /// Failed to parse PEM contents.
    #[error("failed to parse PEM from {path}: {source}")]
    Pem {
        /// The path whose contents failed to parse.
        path: String,
        /// The underlying I/O error.
        source: io::Error,
    },

    /// A certificate file contained no certificates.
    #[error("no certificates found in {path}")]
    NoCertificates {
        /// The offending path.
        path: String,
    },

    /// A key file contained no usable private key.
    #[error("no private key found in {path}")]
    NoPrivateKey {
        /// The offending path.
        path: String,
    },

    /// A certificate could not be added to a trust-anchor store.
    #[error("invalid trust anchor: {0}")]
    InvalidTrustAnchor(rustls::Error),

    /// Building the client-certificate verifier failed.
    #[error("failed to build client cert verifier: {0}")]
    Verifier(rustls::server::VerifierBuilderError),

    /// rustls rejected the supplied configuration (e.g. bad cert/key pair).
    #[error("rustls configuration error: {0}")]
    Rustls(#[from] rustls::Error),
}

/// Error raised while deriving a [`Principal`]/[`AgentId`] from a peer cert.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// The certificate DER could not be parsed.
    #[error("failed to parse certificate: {0}")]
    Parse(String),

    /// The certificate carried no Common Name or usable SAN to derive an
    /// identity from.
    #[error("certificate has no usable subject identity (no CN or DNS SAN)")]
    NoSubject,
}

/// Read a PEM certificate chain from `path`.
///
/// Returns the certificates in file order (leaf first by convention).
///
/// # Errors
///
/// Returns [`TlsError::Read`] / [`TlsError::Pem`] on I/O or parse failure, and
/// [`TlsError::NoCertificates`] if the file contains no certificates.
pub fn load_cert_chain(path: impl AsRef<Path>) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let path = path.as_ref();
    let display = path.display().to_string();
    let pem = std::fs::read(path).map_err(|source| TlsError::Read {
        path: display.clone(),
        source,
    })?;
    let mut reader = io::BufReader::new(&pem[..]);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| TlsError::Pem {
            path: display.clone(),
            source,
        })?;
    if certs.is_empty() {
        return Err(TlsError::NoCertificates { path: display });
    }
    Ok(certs)
}

/// Read a PEM private key from `path`.
///
/// Accepts PKCS#8, PKCS#1 (RSA), and SEC1 (EC) keys. The first private key in
/// the file is returned.
///
/// # Errors
///
/// Returns [`TlsError::Read`] / [`TlsError::Pem`] on I/O or parse failure, and
/// [`TlsError::NoPrivateKey`] if the file contains no private key.
pub fn load_private_key(path: impl AsRef<Path>) -> Result<PrivateKeyDer<'static>, TlsError> {
    let path = path.as_ref();
    let display = path.display().to_string();
    let pem = std::fs::read(path).map_err(|source| TlsError::Read {
        path: display.clone(),
        source,
    })?;
    let mut reader = io::BufReader::new(&pem[..]);
    let key = rustls_pemfile::private_key(&mut reader).map_err(|source| TlsError::Pem {
        path: display.clone(),
        source,
    })?;
    key.ok_or(TlsError::NoPrivateKey { path: display })
}

/// Build a [`RootCertStore`] from a PEM file of trust-anchor (CA) certificates.
///
/// # Errors
///
/// Returns a [`TlsError`] if the file cannot be read/parsed, contains no
/// certificates, or a certificate is not a valid trust anchor.
pub fn load_root_store(path: impl AsRef<Path>) -> Result<RootCertStore, TlsError> {
    let certs = load_cert_chain(path)?;
    root_store_from_certs(certs)
}

/// Build a [`RootCertStore`] from already-parsed CA certificates.
///
/// # Errors
///
/// Returns [`TlsError::InvalidTrustAnchor`] if a certificate cannot be used as
/// a trust anchor.
pub fn root_store_from_certs(
    certs: impl IntoIterator<Item = CertificateDer<'static>>,
) -> Result<RootCertStore, TlsError> {
    let mut store = RootCertStore::empty();
    for cert in certs {
        store.add(cert).map_err(TlsError::InvalidTrustAnchor)?;
    }
    Ok(store)
}

/// Build a mutual-TLS [`ServerConfig`] for the coordinator (the only listener).
///
/// Presents `server_cert_chain` + `server_key` and verifies any client
/// certificate against `client_ca`. Client authentication is **optional**: a
/// peer that presents a valid client certificate is authenticated (runtime
/// mTLS), while a peer that presents *no* certificate is allowed to complete
/// the handshake so it can reach the bootstrap/enrollment path. The
/// application layer (the coordinator) branches on client-cert presence: a
/// connection with no client cert may ONLY perform bootstrap enrollment; the
/// runtime agent/sidecar dispatch is reachable only with a verified client
/// cert. A client cert that is present but *not* verifiable against
/// `client_ca` is still rejected during the handshake.
///
/// # Errors
///
/// Returns a [`TlsError`] if the verifier cannot be built or the
/// certificate/key pair is rejected by rustls.
pub fn server_config(
    server_cert_chain: Vec<CertificateDer<'static>>,
    server_key: PrivateKeyDer<'static>,
    client_ca: RootCertStore,
) -> Result<ServerConfig, TlsError> {
    let verifier = WebPkiClientVerifier::builder(Arc::new(client_ca))
        .allow_unauthenticated()
        .build()
        .map_err(TlsError::Verifier)?;

    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_cert_chain, server_key)?;

    Ok(config)
}

/// Build a mutual-TLS [`ClientConfig`] for agents and sidecars (dial-out).
///
/// Presents `client_cert_chain` + `client_key` to the coordinator and verifies
/// the coordinator's server certificate against `server_ca`.
///
/// # Errors
///
/// Returns a [`TlsError`] if the certificate/key pair is rejected by rustls.
pub fn client_config(
    client_cert_chain: Vec<CertificateDer<'static>>,
    client_key: PrivateKeyDer<'static>,
    server_ca: RootCertStore,
) -> Result<ClientConfig, TlsError> {
    let config = ClientConfig::builder()
        .with_root_certificates(server_ca)
        .with_client_auth_cert(client_cert_chain, client_key)?;

    Ok(config)
}

/// Compute the raw SHA-256 digest of a certificate's DER bytes.
fn cert_sha256(cert: &CertificateDer<'_>) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(cert.as_ref()).into()
}

/// A [`rustls::client::danger::ServerCertVerifier`] that accepts a server leaf
/// **iff** its DER SHA-256 equals a pinned hash.
///
/// This is used ONLY for the one-time bootstrap/enrollment handshake, where the
/// client does not yet trust the coordinator's CA but carries the server-cert
/// hash inside its enrollment token (our improvement over a blind
/// trust-on-first-use verifier). It accepts self-signed / leaf-only chains and
/// ignores the server name and intermediates; the pin is the sole check. It is
/// never used for runtime traffic, which stays full mTLS.
#[derive(Debug)]
pub struct PinnedServerCertVerifier {
    pin: [u8; 32],
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl PinnedServerCertVerifier {
    /// Build a verifier that accepts the server leaf whose DER SHA-256 is
    /// `pin`.
    #[must_use]
    pub fn new(pin: [u8; 32]) -> Self {
        Self {
            pin,
            provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        }
    }
}

impl rustls::client::danger::ServerCertVerifier for PinnedServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if cert_sha256(end_entity) == self.pin {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "bootstrap server certificate does not match the pinned hash".to_owned(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Build a bootstrap [`ClientConfig`] that pins the coordinator's server
/// certificate by its DER SHA-256 (`pin`) and presents no client certificate.
///
/// Used ONLY for the one-time enrollment handshake (`agent init` / `ctl init`):
/// the server cert is verified against the pin carried in the enrollment token,
/// then the client sends an `fleet_proto::enroll::EnrollRequest`. Runtime
/// traffic uses [`client_config`] (full mTLS) instead.
#[must_use]
pub fn bootstrap_client_config(pin: [u8; 32]) -> ClientConfig {
    ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedServerCertVerifier::new(pin)))
        .with_no_client_auth()
}


/// Compute the lowercase-hex SHA-256 fingerprint of a certificate's DER bytes.
///
/// This is the value the coordinator pins agent identities against: its config
/// maps a fingerprint to an [`AgentId`]. Operators can reproduce it with, e.g.
/// `openssl x509 -in agent.pem -noout -fingerprint -sha256` (after stripping
/// the colons and lowercasing).
#[must_use]
pub fn cert_fingerprint(cert: &CertificateDer<'_>) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(cert.as_ref());
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        // Infallible: writing to a String never fails.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Derive a [`Principal`] from a verified peer end-entity certificate.
///
/// # Identity choice
///
/// We use the certificate's Subject **Common Name (CN)** as the principal
/// string, falling back to the first **DNS Subject Alternative Name** if no CN
/// is present. CN is chosen because fleet certificates are issued internally
/// (a private CA) with the operator-assigned identity placed in the CN — this
/// keeps the mapping human-meaningful and matches how the certs are minted.
/// The SAN fallback accommodates modern certs that omit the CN.
///
/// The certificate is assumed to have already been *verified* by rustls during
/// the handshake; this function only parses the subject, it does not validate
/// trust.
///
/// # Errors
///
/// Returns [`IdentityError::Parse`] if the DER cannot be parsed and
/// [`IdentityError::NoSubject`] if neither a CN nor a DNS SAN is present.
pub fn principal_from_cert(cert: &CertificateDer<'_>) -> Result<Principal, IdentityError> {
    let name = subject_identity(cert)?;
    Ok(Principal(name))
}

/// Derive an [`AgentId`] from a verified agent end-entity certificate.
///
/// Uses the same subject-string extraction as [`principal_from_cert`] (CN, then
/// DNS SAN). Note the coordinator additionally *pins* agents by
/// [`cert_fingerprint`]; this helper provides the human-readable identity that
/// accompanies the pin.
///
/// # Errors
///
/// Returns [`IdentityError::Parse`] if the DER cannot be parsed and
/// [`IdentityError::NoSubject`] if neither a CN nor a DNS SAN is present.
pub fn agent_id_from_cert(cert: &CertificateDer<'_>) -> Result<AgentId, IdentityError> {
    let name = subject_identity(cert)?;
    Ok(AgentId(name))
}

/// Extract the subject identity string (CN, then first DNS SAN) from a cert.
fn subject_identity(cert: &CertificateDer<'_>) -> Result<String, IdentityError> {
    use x509_parser::extensions::GeneralName;
    use x509_parser::prelude::FromDer;

    let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(cert.as_ref())
        .map_err(|e| IdentityError::Parse(e.to_string()))?;

    // Prefer the Subject Common Name.
    if let Some(cn) = parsed
        .subject()
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
    {
        let cn = cn.trim();
        if !cn.is_empty() {
            return Ok(cn.to_owned());
        }
    }

    // Fall back to the first DNS Subject Alternative Name.
    if let Ok(Some(san)) = parsed.subject_alternative_name() {
        for name in &san.value.general_names {
            if let GeneralName::DNSName(dns) = name {
                let dns = dns.trim();
                if !dns.is_empty() {
                    return Ok((*dns).to_owned());
                }
            }
        }
    }

    Err(IdentityError::NoSubject)
}

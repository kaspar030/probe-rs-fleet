//! Client-side TLS trust configuration for probe-rs-fleet.
//!
//! Architecture revision 2 (§3.5, §6.2) deletes the private CA: there are no
//! client certificates, no CSRs, no fingerprint pinning of *agents*. Connection
//! authentication is a bearer token on the WebSocket upgrade
//! (`fleet-auth`); TLS is back to doing the one job it is good at, namely
//! authenticating the **server**.
//!
//! What survives here:
//!
//! * [`client_trust_config`] — the single trust path every outbound connection
//!   in the tree uses. `WebPKI` roots by default; optionally a pinned server-leaf
//!   SHA-256 for a self-hosted coordinator with no public DNS name. Both the WS
//!   dialer (`fleet_wire::client`) and the CLI's HTTP client for the `/auth/*`
//!   and `/node/*` surfaces build from this one function, so
//!   `--server-cert-sha256` covers both. If that ever forks, pinning silently
//!   stops covering the token exchange.
//! * [`PinnedServerCertVerifier`] — the pin itself, no longer a *bootstrap*
//!   mechanism (there is no bootstrap handshake any more) but a deployment
//!   option for self-hosting.
//! * [`server_config`] — a plain server config with **no client auth**, for the
//!   optional case where the coordinator terminates TLS itself. In the hosted
//!   deployment a reverse proxy terminates TLS and the coordinator speaks plain
//!   HTTP on loopback.
//!
//! The crate still performs **no I/O** beyond reading PEM files from disk: it
//! opens no sockets and speaks no application protocol.
//!
//! No `unsafe` code is used.

use std::io;
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};

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

    /// rustls rejected the supplied configuration (e.g. bad cert/key pair).
    #[error("rustls configuration error: {0}")]
    Rustls(#[from] rustls::Error),
}

/// Install the `ring` crypto provider as rustls's process default, exactly once.
///
/// rustls panics if `install_default` is called twice, and returns an error if a
/// provider is already installed — both of which are trivially reachable once
/// the node, the coordinator and the token-exchange client all build configs in
/// one process (`fleet-bin` links all three). Every entry point that builds a
/// rustls config calls this first; it is idempotent and cheap.
pub fn install_crypto_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // An error means another provider is already installed, which is fine:
        // the point is that exactly one ends up installed, not that ours wins.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
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

/// Build the [`ClientConfig`] every outbound fleet connection uses.
///
/// * `pin = None` — verify the coordinator against the **`WebPKI` roots** compiled
///   into the binary (the `webpki-roots` crate, not the platform store: a
///   platform store would reintroduce a native dependency on musl and differ
///   between the Pi and the developer's laptop).
/// * `pin = Some(sha256)` — accept exactly the server leaf whose DER SHA-256
///   matches. This is the self-hosted escape hatch for a coordinator with no
///   public DNS name and therefore no publicly trusted certificate.
///
/// Presents **no client certificate** in either case; there are none any more.
#[must_use]
pub fn client_trust_config(pin: Option<[u8; 32]>) -> ClientConfig {
    install_crypto_provider();
    if let Some(pin) = pin {
        return ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedServerCertVerifier::new(pin)))
            .with_no_client_auth();
    }
    let roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// Build a [`ServerConfig`] for a coordinator that terminates TLS itself.
///
/// **No client authentication**: the peer proves who it is with a bearer token
/// on the WebSocket upgrade, not with a certificate. This exists for
/// self-hosted/dev deployments; the hosted deployment puts a reverse proxy in
/// front and the coordinator speaks plain HTTP on loopback.
///
/// # Errors
///
/// Returns a [`TlsError`] if the certificate/key pair is rejected by rustls.
pub fn server_config(
    server_cert_chain: Vec<CertificateDer<'static>>,
    server_key: PrivateKeyDer<'static>,
) -> Result<ServerConfig, TlsError> {
    install_crypto_provider();
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(server_cert_chain, server_key)?;
    Ok(config)
}

/// Compute the raw SHA-256 digest of a certificate's DER bytes.
#[must_use]
pub fn cert_sha256(cert: &CertificateDer<'_>) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(cert.as_ref()).into()
}

/// Compute the lowercase-hex SHA-256 fingerprint of a certificate's DER bytes.
///
/// This is the value an operator passes as `--server-cert-sha256` when
/// self-hosting without a publicly trusted certificate. It is reproducible with
/// `openssl x509 -in coordinator.pem -noout -fingerprint -sha256` (after
/// stripping the colons and lowercasing).
#[must_use]
pub fn cert_fingerprint(cert: &CertificateDer<'_>) -> String {
    let digest = cert_sha256(cert);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        // Infallible: writing to a String never fails.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Parse a lowercase-hex SHA-256 fingerprint into raw bytes.
///
/// # Errors
///
/// Returns `None` if `hex` is not 64 hex characters.
#[must_use]
pub fn parse_fingerprint(hex: &str) -> Option<[u8; 32]> {
    let hex = hex.trim();
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// A [`rustls::client::danger::ServerCertVerifier`] that accepts a server leaf
/// **iff** its DER SHA-256 equals a pinned hash.
///
/// The one surviving remnant of the deleted pinning code. It is no longer a
/// bootstrap mechanism — there is no bootstrap handshake — but the way a
/// self-hosted deployment without public DNS establishes trust: the operator
/// reads the fingerprint off the coordinator host and passes it to
/// `node up --server-cert-sha256` / `login --server-cert-sha256`.
///
/// It accepts self-signed / leaf-only chains and ignores the server name and
/// intermediates; the pin is the sole check.
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
            provider: Arc::new(rustls::crypto::ring::default_provider()),
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
                "server certificate does not match the pinned hash".to_owned(),
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

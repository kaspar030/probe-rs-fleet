//! Integration tests for `fleet-tls`'s client trust configuration.
//!
//! Replaces the deleted `mtls.rs`. There are no client certificates any more, so
//! what is left to prove is the *server* trust decision, which is the whole
//! remaining job of this crate:
//!
//! * a pinned server-cert SHA-256 accepts exactly the matching leaf and rejects
//!   any other one (the self-hosted deployment path, architecture §10 Q1);
//! * the default `WebPKI`-roots configuration rejects a self-signed leaf — i.e.
//!   omitting the pin does not silently degrade into trust-on-first-use.

use std::sync::Arc;

use rcgen::{CertificateParams, DnType, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use sha2::{Digest, Sha256};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use fleet_tls::{cert_fingerprint, client_trust_config, parse_fingerprint, server_config};

/// A minted self-signed cert plus its private key, in rustls DER form.
struct Minted {
    cert_der: CertificateDer<'static>,
    key_der: PrivateKeyDer<'static>,
}

/// Mint a self-signed end-entity certificate for `dns`.
///
/// Self-signed is the realistic shape here: a self-hosted coordinator with no
/// public DNS name is exactly the case the pin exists for.
fn make_self_signed(dns: &str) -> Minted {
    let mut params = CertificateParams::new(vec![dns.to_owned()]).unwrap();
    params.distinguished_name.push(DnType::CommonName, dns);
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    Minted {
        cert_der: cert.der().clone(),
        key_der: PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
    }
}

/// Run a handshake over an in-memory duplex; `true` if the client succeeded.
async fn handshake(server: rustls::ServerConfig, client: rustls::ClientConfig) -> bool {
    let acceptor = TlsAcceptor::from(Arc::new(server));
    let connector = TlsConnector::from(Arc::new(client));
    let (server_io, client_io) = tokio::io::duplex(16 * 1024);
    let server_task = tokio::spawn(async move { acceptor.accept(server_io).await.is_ok() });
    let name = ServerName::try_from("coordinator.fleet.test").unwrap();
    let client_ok = connector.connect(name, client_io).await.is_ok();
    let _ = server_task.await;
    client_ok
}

#[tokio::test]
async fn pinned_config_accepts_the_matching_leaf() {
    let server = make_self_signed("coordinator.fleet.test");
    let pin: [u8; 32] = Sha256::digest(server.cert_der.as_ref()).into();
    let s_config = server_config(vec![server.cert_der.clone()], server.key_der).unwrap();

    assert!(
        handshake(s_config, client_trust_config(Some(pin))).await,
        "a client pinning the server's own leaf must connect"
    );
}

#[tokio::test]
async fn pinned_config_rejects_a_different_leaf() {
    let server = make_self_signed("coordinator.fleet.test");
    // The pin of a *different* certificate: what a MITM would present.
    let other = make_self_signed("coordinator.fleet.test");
    let wrong_pin: [u8; 32] = Sha256::digest(other.cert_der.as_ref()).into();
    let s_config = server_config(vec![server.cert_der.clone()], server.key_der).unwrap();

    assert!(
        !handshake(s_config, client_trust_config(Some(wrong_pin))).await,
        "a client with a mismatched pin must be rejected"
    );
}

/// Without a pin the client verifies against the compiled-in `WebPKI` roots, so a
/// self-signed coordinator is refused. This is the property that stops the
/// default configuration from quietly becoming trust-on-first-use.
#[tokio::test]
async fn webpki_roots_config_rejects_a_self_signed_leaf() {
    let server = make_self_signed("coordinator.fleet.test");
    let s_config = server_config(vec![server.cert_der.clone()], server.key_der).unwrap();

    assert!(
        !handshake(s_config, client_trust_config(None)).await,
        "WebPKI roots must not accept a self-signed leaf"
    );
}

#[test]
fn fingerprint_round_trips_through_its_hex_form() {
    let leaf = make_self_signed("coordinator.fleet.test");
    let hex = cert_fingerprint(&leaf.cert_der);
    assert_eq!(hex.len(), 64);
    assert!(hex
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));

    // This is the operator's round trip: read the fingerprint off the
    // coordinator, paste it into `--server-cert-sha256`, get the same bytes.
    let parsed = parse_fingerprint(&hex).expect("64 hex chars parse");
    let expected: [u8; 32] = Sha256::digest(leaf.cert_der.as_ref()).into();
    assert_eq!(parsed, expected);

    assert_eq!(parsed, fleet_tls::cert_sha256(&leaf.cert_der));
    assert!(parse_fingerprint("too-short").is_none());
    assert!(parse_fingerprint(&"z".repeat(64)).is_none());
}

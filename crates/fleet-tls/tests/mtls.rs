//! Integration tests for `fleet-tls`.
//!
//! These spin up a self-signed test CA, mint server and client end-entity
//! certificates, and run a real rustls handshake over an in-memory
//! `tokio::io::duplex` pair to prove the mTLS configs interoperate. They also
//! exercise the subject-id / fingerprint extraction helpers on a known cert.

use std::fmt::Write as _;
use std::sync::Arc;

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use fleet_tls::{
    agent_id_from_cert, cert_fingerprint, client_config, root_store_from_certs, subject_id_from_cert,
    server_config,
};

/// A minted cert plus its private key, in rustls DER form.
struct Minted {
    cert_der: CertificateDer<'static>,
    key_der: PrivateKeyDer<'static>,
}

fn make_ca() -> (Certificate, KeyPair) {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, "fleet-test-ca");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    (cert, key)
}

/// Mint an end-entity cert with the given CN (and matching DNS SAN), signed by
/// the CA.
fn make_leaf(cn: &str, dns: &str, ca: &Certificate, ca_key: &KeyPair) -> Minted {
    let mut params = CertificateParams::new(vec![dns.to_owned()]).unwrap();
    params.distinguished_name.push(DnType::CommonName, cn);
    let key = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, ca, ca_key).unwrap();
    Minted {
        cert_der: cert.der().clone(),
        key_der: PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
    }
}

#[tokio::test]
async fn mtls_handshake_round_trip() {
    let (ca, ca_key) = make_ca();
    let ca_der = ca.der().clone();

    let server = make_leaf("coordinator.fleet.test", "coordinator.fleet.test", &ca, &ca_key);
    let client = make_leaf("agent-01", "agent-01.fleet.test", &ca, &ca_key);

    // Both sides trust the same test CA.
    let client_ca = root_store_from_certs([ca_der.clone()]).unwrap();
    let server_ca = root_store_from_certs([ca_der.clone()]).unwrap();

    let s_config = server_config(vec![server.cert_der.clone()], server.key_der, client_ca).unwrap();
    let c_config = client_config(vec![client.cert_der.clone()], client.key_der, server_ca).unwrap();

    let acceptor = TlsAcceptor::from(Arc::new(s_config));
    let connector = TlsConnector::from(Arc::new(c_config));

    let (server_io, client_io) = tokio::io::duplex(16 * 1024);

    let server_task = tokio::spawn(async move {
        let mut tls = acceptor.accept(server_io).await.expect("server handshake");

        // The coordinator can recover the client's verified end-entity cert.
        let peer = {
            let (_, conn) = tls.get_ref();
            conn.peer_certificates()
                .expect("client presented a cert")
                .first()
                .expect("at least one cert")
                .clone()
                .into_owned()
        };
        let subject_id = subject_id_from_cert(&peer).unwrap();
        assert_eq!(subject_id, "agent-01");

        let mut buf = [0u8; 5];
        tls.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
        tls.write_all(b"world").await.unwrap();
        tls.flush().await.unwrap();
    });

    let server_name = ServerName::try_from("coordinator.fleet.test").unwrap();
    let mut tls = connector
        .connect(server_name, client_io)
        .await
        .expect("client handshake");
    tls.write_all(b"hello").await.unwrap();
    tls.flush().await.unwrap();
    let mut buf = [0u8; 5];
    tls.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"world");

    server_task.await.unwrap();
}

#[tokio::test]
async fn handshake_rejects_untrusted_client() {
    let (ca, ca_key) = make_ca();
    let (rogue_ca, rogue_ca_key) = make_ca();
    let ca_der = ca.der().clone();

    let server = make_leaf("coordinator.fleet.test", "coordinator.fleet.test", &ca, &ca_key);
    // Client cert signed by a CA the coordinator does NOT trust.
    let rogue = make_leaf("rogue", "rogue.fleet.test", &rogue_ca, &rogue_ca_key);

    let client_ca = root_store_from_certs([ca_der.clone()]).unwrap();
    let server_ca = root_store_from_certs([ca_der.clone()]).unwrap();

    let s_config = server_config(vec![server.cert_der.clone()], server.key_der, client_ca).unwrap();
    let c_config = client_config(vec![rogue.cert_der.clone()], rogue.key_der, server_ca).unwrap();

    let acceptor = TlsAcceptor::from(Arc::new(s_config));
    let connector = TlsConnector::from(Arc::new(c_config));

    let (server_io, client_io) = tokio::io::duplex(16 * 1024);

    let server_task = tokio::spawn(async move { acceptor.accept(server_io).await.is_ok() });

    let server_name = ServerName::try_from("coordinator.fleet.test").unwrap();
    // The client side may report success or failure depending on timing, but
    // the server must reject the untrusted client cert.
    let _ = connector.connect(server_name, client_io).await;

    let server_ok = server_task.await.unwrap();
    assert!(!server_ok, "server must reject an untrusted client cert");
}

#[test]
fn subject_id_and_agent_id_from_cn() {
    let (ca, ca_key) = make_ca();
    let leaf = make_leaf("agent-42", "agent-42.fleet.test", &ca, &ca_key);

    let subject_id = subject_id_from_cert(&leaf.cert_der).unwrap();
    assert_eq!(subject_id, "agent-42");

    let agent_id = agent_id_from_cert(&leaf.cert_der).unwrap();
    assert_eq!(agent_id.0, "agent-42");
}

#[test]
fn fingerprint_is_stable_lowercase_hex_sha256() {
    let (ca, ca_key) = make_ca();
    let leaf = make_leaf("agent-7", "agent-7.fleet.test", &ca, &ca_key);

    let fp = cert_fingerprint(&leaf.cert_der);
    // SHA-256 => 32 bytes => 64 hex chars.
    assert_eq!(fp.len(), 64);
    assert!(fp.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    // Deterministic.
    assert_eq!(fp, cert_fingerprint(&leaf.cert_der));

    // Matches an independent SHA-256 of the DER.
    let expected = Sha256::digest(leaf.cert_der.as_ref());
    let mut expected_hex = String::new();
    for byte in expected {
        write!(expected_hex, "{byte:02x}").unwrap();
    }
    assert_eq!(fp, expected_hex);
}

#[tokio::test]
async fn bootstrap_pin_verifier_accepts_match_rejects_mismatch() {
    use fleet_tls::bootstrap_client_config;

    let (ca, ca_key) = make_ca();
    let server = make_leaf("coordinator.fleet.test", "coordinator.fleet.test", &ca, &ca_key);

    // Server requires no client auth for the bootstrap handshake; reuse the
    // server cert as a leaf-only chain.
    let server_ca = root_store_from_certs([ca.der().clone()]).unwrap();
    let _ = server_ca; // not needed for the bootstrap server side

    let s_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![server.cert_der.clone()], server.key_der)
        .unwrap();

    // Correct pin = SHA-256 of the server leaf DER.
    let pin: [u8; 32] = Sha256::digest(server.cert_der.as_ref()).into();

    // --- matching pin: handshake succeeds ---
    {
        let acceptor = TlsAcceptor::from(Arc::new(s_config.clone()));
        let connector = TlsConnector::from(Arc::new(bootstrap_client_config(pin)));
        let (server_io, client_io) = tokio::io::duplex(16 * 1024);
        let server_task = tokio::spawn(async move { acceptor.accept(server_io).await.is_ok() });
        let server_name = ServerName::try_from("coordinator.fleet.test").unwrap();
        let client_ok = connector.connect(server_name, client_io).await.is_ok();
        assert!(client_ok, "client with matching pin must connect");
        let _ = server_task.await;
    }

    // --- wrong pin: handshake fails ---
    {
        let wrong = [0u8; 32];
        let acceptor = TlsAcceptor::from(Arc::new(s_config));
        let connector = TlsConnector::from(Arc::new(bootstrap_client_config(wrong)));
        let (server_io, client_io) = tokio::io::duplex(16 * 1024);
        let server_task = tokio::spawn(async move { acceptor.accept(server_io).await.is_ok() });
        let server_name = ServerName::try_from("coordinator.fleet.test").unwrap();
        let client_ok = connector.connect(server_name, client_io).await.is_ok();
        assert!(!client_ok, "client with wrong pin must be rejected");
        let _ = server_task.await;
    }
}

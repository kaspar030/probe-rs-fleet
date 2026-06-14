//! Integration test: bootstrap enrollment over the real coordinator serve loop.
//!
//! Spins up a coordinator with on-disk TLS material + an in-memory-equivalent
//! (temp-file) database, seeds a one-time enrollment secret, then drives a
//! pinned bootstrap client (no client cert) that generates a CSR locally and
//! redeems the secret for a CA-signed client cert. Asserts: valid secret ->
//! cert signed + auto-pinned in the DB; reuse -> rejected.

use std::sync::Arc;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use fleet_coordinator::config::{CoordinatorConfig, SigningKeySource};
use fleet_coordinator::core::Coordinator;
use fleet_coordinator::proto::{read_frame, write_frame};
use fleet_coordinator::{clock::SystemClock, Db, Ed25519Signer};
use fleet_core::policy::Policy;
use fleet_core::scheduler::Scheduler;
use fleet_proto::enroll::{EnrollRequest, EnrollResponse};

struct Material {
    ca_cert_pem: String,
    ca_key_pem: String,
    server_cert_pem: String,
    server_key_pem: String,
    server_cert_sha256: [u8; 32],
}

fn mint_material() -> Material {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "probe-rs-fleet client CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let mut server_params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    server_params
        .subject_alt_names
        .push(SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)));
    server_params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    let server_key = KeyPair::generate().unwrap();
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .unwrap();

    let server_cert_sha256 = {
        use sha2::{Digest, Sha256};
        Sha256::digest(server_cert.der().as_ref()).into()
    };

    Material {
        ca_cert_pem: ca_cert.pem(),
        ca_key_pem: ca_key.serialize_pem(),
        server_cert_pem: server_cert.pem(),
        server_key_pem: server_key.serialize_pem(),
        server_cert_sha256,
    }
}

async fn start_coordinator(
    mat: &Material,
    dir: &std::path::Path,
) -> (std::net::SocketAddr, Arc<Coordinator>) {
    let server_cert = dir.join("coordinator-cert.pem");
    let server_key = dir.join("coordinator-key.pem");
    let ca_cert = dir.join("client-ca.pem");
    let ca_key = dir.join("client-ca-key.pem");
    std::fs::write(&server_cert, &mat.server_cert_pem).unwrap();
    std::fs::write(&server_key, &mat.server_key_pem).unwrap();
    std::fs::write(&ca_cert, &mat.ca_cert_pem).unwrap();
    std::fs::write(&ca_key, &mat.ca_key_pem).unwrap();

    let config = CoordinatorConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        advertise_addr: None,
        tls_cert: server_cert,
        tls_key: server_key,
        client_ca: ca_cert,
        client_ca_key: ca_key,
        sqlite_path: ":memory:".into(),
        signing_key: SigningKeySource::Seed([9u8; 32]),
        policy: Policy::default(),
        pinned_agents: std::collections::HashMap::new(),
        sweep_interval_secs: 5,
    };

    // Build the cert chain / acceptor directly so we keep a handle to the
    // Coordinator (build() consumes config and returns the shared coordinator).
    let cert_chain = fleet_tls::load_cert_chain(&config.tls_cert).unwrap();
    let key = fleet_tls::load_private_key(&config.tls_key).unwrap();
    let client_ca = fleet_tls::load_root_store(&config.client_ca).unwrap();
    let tls_config = fleet_tls::server_config(cert_chain, key, client_ca).unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));

    let db = Db::connect_in_memory().await.unwrap();
    let scheduler = Scheduler::new(config.policy.clone());
    let signer = Ed25519Signer::from_seed(&[9u8; 32]);
    let coord = Arc::new(Coordinator::new(
        config,
        scheduler,
        db,
        signer,
        Arc::new(SystemClock),
    ));

    // Bind explicitly so we know the chosen port, then run the accept loop.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let coord_clone = Arc::clone(&coord);
    tokio::spawn(async move {
        loop {
            let Ok((sock, _peer)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let coord = Arc::clone(&coord_clone);
            tokio::spawn(async move {
                fleet_coordinator::server::handle_connection_for_test(coord, acceptor, sock).await
            });
        }
    });

    (addr, coord)
}

async fn bootstrap_enroll(
    addr: std::net::SocketAddr,
    pin: [u8; 32],
    secret: [u8; 32],
) -> EnrollResponse {
    let key = KeyPair::generate().unwrap();
    let csr_pem = CertificateParams::default()
        .serialize_request(&key)
        .unwrap()
        .pem()
        .unwrap();

    let tls_config = fleet_tls::bootstrap_client_config(pin);
    let connector = TlsConnector::from(Arc::new(tls_config));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::IpAddress(addr.ip().into());
    let tls = connector.connect(server_name, tcp).await.unwrap();
    let (mut reader, mut writer) = tokio::io::split(tls);

    write_frame(&mut writer, &EnrollRequest { secret, csr_pem })
        .await
        .unwrap();
    read_frame(&mut reader).await.unwrap()
}

#[tokio::test]
async fn enroll_valid_then_reuse_rejected_and_autopinned() {
    let mat = mint_material();
    let dir = tempfile::tempdir().unwrap();
    let (addr, coord) = start_coordinator(&mat, dir.path()).await;

    // Seed a one-time agent secret.
    let secret = [7u8; 32];
    let secret_hash = fleet_coordinator::enroll::hash_secret(&secret);
    coord
        .db()
        .insert_enroll_token(&secret_hash, "rpi-1", "agent", 0, i64::MAX)
        .await
        .unwrap();

    // Valid -> CSR signed, cert chains to the CA, fingerprint auto-pinned.
    let resp = bootstrap_enroll(addr, mat.server_cert_sha256, secret).await;
    let cert_pem = match resp {
        EnrollResponse::Accepted {
            client_cert_pem, ..
        } => client_cert_pem,
        EnrollResponse::Rejected { reason } => panic!("expected Accepted, got rejected: {reason}"),
    };

    // The issued cert's CN maps to the principal.
    let der = {
        let mut reader = std::io::BufReader::new(cert_pem.as_bytes());
        let cert = rustls_pemfile::certs(&mut reader).next().unwrap().unwrap();
        cert
    };
    let agent_id = fleet_tls::agent_id_from_cert(&der).unwrap();
    assert_eq!(agent_id.0, "rpi-1");

    // It was auto-pinned in the DB.
    let fp = fleet_tls::cert_fingerprint(&der);
    assert_eq!(
        coord.db().agent_pin_for_fingerprint(&fp).await.unwrap(),
        Some("rpi-1".to_owned())
    );

    // Reuse -> rejected (single-use).
    let resp = bootstrap_enroll(addr, mat.server_cert_sha256, secret).await;
    assert!(matches!(resp, EnrollResponse::Rejected { .. }));
}

#[tokio::test]
async fn enroll_wrong_secret_rejected() {
    let mat = mint_material();
    let dir = tempfile::tempdir().unwrap();
    let (addr, coord) = start_coordinator(&mat, dir.path()).await;

    let secret_hash = fleet_coordinator::enroll::hash_secret(&[1u8; 32]);
    coord
        .db()
        .insert_enroll_token(&secret_hash, "rpi-1", "agent", 0, i64::MAX)
        .await
        .unwrap();

    // Present a different secret.
    let resp = bootstrap_enroll(addr, mat.server_cert_sha256, [2u8; 32]).await;
    assert!(matches!(resp, EnrollResponse::Rejected { .. }));
}

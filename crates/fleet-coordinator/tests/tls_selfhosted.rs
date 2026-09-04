//! Coordinator-terminated TLS (the self-hosted path).
//!
//! The hosted deployment puts an HTTPS reverse proxy in front and the
//! coordinator serves plain HTTP on loopback. This test covers the *other*
//! configuration — a `[tls]` table — because it has a failure mode that is
//! invisible in the default one:
//!
//! **`axum::serve` cannot carry `WebSocket` upgrades over a manual TLS accept
//! loop.** Upgrades need
//! `hyper_util::server::conn::auto::Builder::serve_connection_with_upgrades`.
//! Get it wrong and `/agent` 400s *only* when `[tls]` is configured — which is
//! exactly the configuration a developer is least likely to exercise by
//! accident. So this test dials a real `wss://` `WebSocket`, not just an HTTPS
//! request.
//!
//! It also covers the pin, which is the one surviving piece of the deleted
//! certificate-pinning code: a self-hosted coordinator has no publicly trusted
//! certificate, so the operator passes its SHA-256 to `agent up` / `login`.

mod common;

use std::sync::Arc;

use common::TestCoordinator;

use fleet_proto::agent_api::AgentReport;
use fleet_wire::client::{dial, DialOpts};
use fleet_wire::AgentToCoord;

/// A TLS-terminating coordinator on a real socket, plus its cert's SHA-256.
struct TlsFleet {
    fleet: TestCoordinator,
    base_url: String,
    pin: [u8; 32],
    server: tokio::task::JoinHandle<()>,
}

impl Drop for TlsFleet {
    fn drop(&mut self) {
        self.server.abort();
    }
}

/// Start a coordinator that terminates TLS itself, with a generated self-signed
/// certificate.
async fn start_tls_fleet() -> TlsFleet {
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::service::TowerToHyperService;
    use rcgen::{CertificateParams, DnType, KeyPair};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    // The coordinator itself: reuse the plain harness for the database and
    // credential seeding, and serve a second listener over TLS.
    let fleet = TestCoordinator::start().await;

    let mut params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(std::net::IpAddr::V4(
            std::net::Ipv4Addr::LOCALHOST,
        )));
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let pin = fleet_tls::cert_sha256(&cert_der);
    let key_der = PrivateKeyDer::try_from(key.serialize_der()).unwrap();

    let server_config = fleet_tls::server_config(vec![cert_der], key_der).unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

    let router = fleet_coordinator::http::router(Arc::clone(&fleet.coord));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                continue;
            };
            let acceptor = acceptor.clone();
            let service = TowerToHyperService::new(router.clone());
            tokio::spawn(async move {
                let Ok(stream) = acceptor.accept(sock).await else {
                    return;
                };
                // The load-bearing call: `_with_upgrades`. Without it the
                // handshake succeeds and every `/agent` upgrade 400s.
                let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                let _ = builder
                    .serve_connection_with_upgrades(TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    TlsFleet {
        fleet,
        // 127.0.0.1 rather than `localhost`: the pinned verifier ignores the
        // server name entirely (the pin is the whole check), and a literal IP
        // needs no resolver, which some build sandboxes do not have.
        base_url: format!("https://127.0.0.1:{}", addr.port()),
        pin,
        server,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pinning_client_completes_a_wss_websocket_upgrade() {
    let tls = start_tls_fleet().await;
    let (token, node) = tls.fleet.seed_node("default", "rpi-1").await;

    let (mut tx, _rx) = dial(DialOpts {
        url: tls.base_url.clone(),
        path: "/agent",
        bearer: token,
        pin: Some(tls.pin),
    })
    .await
    .expect("a pinning client must complete the wss upgrade");

    // Prove it is a working WebSocket, not merely a completed handshake: this
    // is what catches a `serve_connection` that lacks `_with_upgrades`.
    fleet_wire::send(
        &mut tx,
        &AgentToCoord::Report(AgentReport::Register {
            agent: node.clone(),
            protocol_version: fleet_proto::PROTOCOL_VERSION,
        }),
    )
    .await
    .unwrap();

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if tls.fleet.coord.agents().get(&node).await.is_some() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the node never registered over wss"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_with_the_wrong_pin_is_refused() {
    let tls = start_tls_fleet().await;
    let (token, _node) = tls.fleet.seed_node("default", "rpi-1").await;

    let result = dial(DialOpts {
        url: tls.base_url.clone(),
        path: "/agent",
        bearer: token,
        pin: Some([0xAA; 32]),
    })
    .await;
    assert!(
        result.is_err(),
        "a mismatched pin must fail the TLS handshake"
    );
}

/// Without a pin the client verifies against the public `WebPKI` roots, which a
/// self-signed coordinator certificate cannot satisfy. This is the property that
/// stops omitting `--server-cert-sha256` from silently degrading into
/// trust-on-first-use.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unpinned_client_refuses_a_self_signed_coordinator() {
    let tls = start_tls_fleet().await;
    let (token, _node) = tls.fleet.seed_node("default", "rpi-1").await;

    let result = dial(DialOpts {
        url: tls.base_url.clone(),
        path: "/agent",
        bearer: token,
        pin: None,
    })
    .await;
    assert!(
        result.is_err(),
        "WebPKI roots must not accept a self-signed coordinator"
    );
}

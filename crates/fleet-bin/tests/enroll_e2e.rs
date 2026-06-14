//! End-to-end bootstrap-enrollment test driving the real role handlers.
//!
//! Flow (acceptance):
//!   `coordinator init` -> `coordinator enroll <p> --kind agent|client` (mint
//!   token) -> coordinator serve loop -> `agent init`/`ctl init --token <t>`
//!   opens pinned bootstrap TLS, generates a local CSR, receives a CA-signed
//!   client cert, writes the per-profile config + creds -> a second profile
//!   coexists -> a runtime **mTLS** connection with the issued cert is
//!   authenticated by the coordinator from the client cert.

use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::Arc;

use fleet_bin::cli::{AgentInitArgs, CtlInitArgs, EnrollKind, InitArgs};
use fleet_bin::roles;

use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Pick a currently-free localhost TCP port.
fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

/// Rewrite the coordinator config's `listen_addr` to `127.0.0.1:<port>`.
fn set_listen_addr(config_path: &Path, port: u16) {
    let text = std::fs::read_to_string(config_path).unwrap();
    let rewritten = text
        .lines()
        .map(|line| {
            if line.trim_start().starts_with("listen_addr") {
                format!("listen_addr = \"127.0.0.1:{port}\"")
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(config_path, rewritten).unwrap();
}

/// Wait until `addr` accepts a TCP connection (coordinator is listening).
async fn wait_listening(addr: &str) {
    for _ in 0..100 {
        if TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("coordinator never started listening on {addr}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enroll_e2e_agent_and_client_mtls() {
    let tmp = tempfile::tempdir().unwrap();
    let coord_config = tmp.path().join("coord-config");
    let coord_data = tmp.path().join("coord-data");

    // 1. coordinator init (temp dirs, XDG-independent overrides).
    roles::init::run(InitArgs {
        config_dir: Some(coord_config.clone()),
        data_dir: Some(coord_data.clone()),
        hostname: vec!["localhost".to_owned()],
        ip: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        force: false,
    })
    .unwrap();

    // Bind the coordinator to a free localhost port and point the SQLite db at
    // a stable file (so enroll + serve share it).
    let port = free_port();
    let config_path = coord_config.join("coordinator.toml");
    set_listen_addr(&config_path, port);
    let addr = format!("127.0.0.1:{port}");

    // 2. enroll an agent and a client, capturing their tokens.
    let agent_token =
        roles::enroll::mint_token("rpi-1", EnrollKind::Agent, 3600, None, &config_path, &coord_data)
            .await
            .unwrap();
    let client_token = roles::enroll::mint_token(
        "alice",
        EnrollKind::Client,
        3600,
        None,
        &config_path,
        &coord_data,
    )
    .await
    .unwrap();

    // 3. start the coordinator serve loop.
    let cfg = fleet_bin::config::load_coordinator_config(&config_path).unwrap();
    let coord_handle = tokio::spawn(async move { fleet_coordinator::run(cfg).await });
    wait_listening(&addr).await;

    // 4. agent init for two coexisting profiles.
    let agent_cfg_root = tmp.path().join("agent-config");
    let agent_data_root = tmp.path().join("agent-data");
    for profile in ["lab1", "lab2"] {
        // A fresh token per init (single-use); reuse the agent token for lab1,
        // mint another for lab2.
        let token = if profile == "lab1" {
            agent_token.clone()
        } else {
            roles::enroll::mint_token(
                "rpi-1",
                EnrollKind::Agent,
                3600,
                None,
                &config_path,
                &coord_data,
            )
            .await
            .unwrap()
        };
        roles::agent_init::run(
            AgentInitArgs {
                token,
                config_dir: Some(agent_cfg_root.join(profile)),
                data_dir: Some(agent_data_root.join(profile)),
                boards_path: None,
                force: false,
            },
            profile.to_owned(),
        )
        .await
        .unwrap();

        // Issued files exist under the per-profile dirs.
        let data = agent_data_root.join(profile);
        assert!(agent_cfg_root.join(profile).join("agent.toml").exists());
        assert!(data.join("agent-cert.pem").exists());
        assert!(data.join("agent-key.pem").exists());
        assert!(data.join("client-ca.pem").exists());
    }

    // 5. ctl init (client role coexists with the agent role on this host).
    let client_cfg_root = tmp.path().join("client-config");
    let client_data_root = tmp.path().join("client-data");
    roles::ctl_init::run(
        CtlInitArgs {
            token: client_token,
            config_dir: Some(client_cfg_root.join("ci")),
            data_dir: Some(client_data_root.join("ci")),
            force: false,
        },
        "ci".to_owned(),
    )
    .await
    .unwrap();
    assert!(client_cfg_root.join("ci").join("client.toml").exists());
    assert!(client_data_root.join("ci").join("client-cert.pem").exists());

    // 6. runtime mTLS: connect with the issued agent (lab1) cert and confirm
    // the coordinator completes the mTLS handshake (authenticating the client
    // cert against its CA + the DB-backed pin recorded at enrollment).
    let data = agent_data_root.join("lab1");
    let chain = fleet_tls::load_cert_chain(data.join("agent-cert.pem")).unwrap();
    let key = fleet_tls::load_private_key(data.join("agent-key.pem")).unwrap();
    let server_ca = fleet_tls::load_root_store(data.join("client-ca.pem")).unwrap();
    let client_config = fleet_tls::client_config(chain, key, server_ca).unwrap();
    let connector = TlsConnector::from(Arc::new(client_config));
    let tcp = TcpStream::connect(&addr).await.unwrap();
    let server_name = ServerName::IpAddress(Ipv4Addr::LOCALHOST.into());
    let tls = connector.connect(server_name, tcp).await;
    assert!(
        tls.is_ok(),
        "runtime mTLS handshake with the issued cert must succeed: {:?}",
        tls.err()
    );

    coord_handle.abort();
}

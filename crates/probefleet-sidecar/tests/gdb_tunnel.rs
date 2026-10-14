//! End-to-end gdb-tunnel byte path: a user's gdb client ↔ sidecar listener ↔
//! (simulated coordinator relay) ↔ agent splice ↔ board-local gdb stub.
//!
//! This exercises *both* halves of the tunnel together — the sidecar-side pump
//! ([`probefleet_sidecar::gdb::splice`]) and the agent-side pump
//! ([`probefleet_agent::gdb::splice`]) — wired through an in-memory `DataFrame`
//! relay that stands in for the coordinator. It proves bytes round-trip both
//! directions, in order and without loss, across the full two-hop path, with no
//! real coordinator, TLS, or probe-rs binary.

use probefleet_proto::{ChannelId, DataFrame};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// Forward every `DataFrame` from `rx` into `tx`, standing in for the
/// coordinator's opaque byte relay (which never inspects the frames).
fn pump_relay(mut rx: mpsc::Receiver<DataFrame>, tx: mpsc::Sender<DataFrame>) {
    tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            if tx.send(frame).await.is_err() {
                break;
            }
        }
    });
}

#[tokio::test]
async fn gdb_tunnel_round_trips_end_to_end() {
    let channel = ChannelId(42);

    // --- sidecar local listener + the user's gdb client ------------------
    let listen = probefleet_sidecar::gdb::resolve_listen_addr(Some("127.0.0.1:0")).unwrap();
    let listener = probefleet_sidecar::gdb::bind(listen).await.unwrap();
    let listen_addr = listener.local_addr().unwrap();

    let client_connect = TcpStream::connect(listen_addr);
    let sidecar_accept = probefleet_sidecar::gdb::accept(&listener);
    let (client, sidecar_client_stream) = tokio::join!(client_connect, sidecar_accept);
    let mut gdb_client = client.unwrap();
    let sidecar_client_stream = sidecar_client_stream.unwrap();

    // --- agent-side board-local gdb stub (loopback pair) -----------------
    let (agent_stub_stream, mut stub) = {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let connect = TcpStream::connect(addr);
        let accept = l.accept();
        let (c, a) = tokio::join!(connect, accept);
        (c.unwrap(), a.unwrap().0)
    };

    // --- the two relay legs (sidecar <-> coordinator <-> agent) ----------
    // sidecar -> coordinator -> agent
    let (side_to_coord_tx, side_to_coord_rx) = mpsc::channel::<DataFrame>(16);
    let (coord_to_agent_tx, coord_to_agent_rx) = mpsc::channel::<DataFrame>(16);
    pump_relay(side_to_coord_rx, coord_to_agent_tx);
    // agent -> coordinator -> sidecar
    let (agent_to_coord_tx, agent_to_coord_rx) = mpsc::channel::<DataFrame>(16);
    let (coord_to_side_tx, coord_to_side_rx) = mpsc::channel::<DataFrame>(16);
    pump_relay(agent_to_coord_rx, coord_to_side_tx);

    // Sidecar splice: gdb client <-> (to coordinator / from coordinator).
    let sidecar_task = tokio::spawn(probefleet_sidecar::gdb::splice(
        channel,
        sidecar_client_stream,
        side_to_coord_tx,
        coord_to_side_rx,
    ));
    // Agent splice: board stub <-> (to coordinator / from coordinator).
    let agent_task = tokio::spawn(probefleet_agent::gdb::splice(
        channel,
        agent_stub_stream,
        agent_to_coord_tx,
        coord_to_agent_rx,
    ));

    // client -> ... -> stub
    gdb_client.write_all(b"$qSupported#37").await.unwrap();
    gdb_client.flush().await.unwrap();
    let mut buf = vec![0u8; 14];
    stub.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"$qSupported#37");

    // stub -> ... -> client
    stub.write_all(b"+$T05thread:01;#hh").await.unwrap();
    stub.flush().await.unwrap();
    let mut back = vec![0u8; 18];
    gdb_client.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"+$T05thread:01;#hh");

    // Clean shutdown when the gdb client disconnects.
    drop(gdb_client);
    let sidecar_result = sidecar_task.await.unwrap();
    assert!(sidecar_result.is_ok());
    // The agent splice ends once its relay leg closes.
    drop(stub);
    let agent_result = agent_task.await.unwrap();
    assert!(agent_result.is_ok());
}

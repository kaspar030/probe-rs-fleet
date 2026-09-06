//! Connection registries: agents, sidecars, and relay channels.
//!
//! Three shared tables, all behind `tokio::sync` locks:
//!
//! * [`AgentRegistry`] maps an [`AgentId`] to a handle for sending
//!   [`CoordinatorCommand`]s (and [`DataFrame`]s) down that agent's persistent
//!   dial-out connection. The per-connection writer task drains the channel, so
//!   the relay and the expiry sweep can push without sharing the TLS stream.
//! * [`SidecarRegistry`] maps a [`RequesterId`] — one per *connection*, not per
//!   subject — to that connection's [`SidecarHandle`], so the coordinator can
//!   push an unsolicited message (today: a queue promotion) to the client that
//!   asked for it.
//! * [`ChannelTable`] maps a [`ChannelId`] to the routing endpoints of an open
//!   relay channel, so a [`DataFrame`] arriving from either side can be
//!   forwarded to the other.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio::sync::Notify;

use fleet_core::scheduler::RequesterId;
use fleet_proto::agent_api::CoordinatorCommand;
use fleet_proto::ids::{AgentId, LeaseId};
use fleet_proto::{ChannelId, DataFrame};

use crate::proto::CoordToSidecar;

/// A message bound for an agent's dial-out connection writer task.
#[derive(Debug, Clone)]
pub enum AgentMessage {
    /// A control-plane command.
    Command(CoordinatorCommand),
    /// An opaque data-plane frame to splice onto an open session.
    Data(DataFrame),
}

/// A handle to push messages to a connected agent's writer task.
///
/// Carries a **shutdown signal** alongside the message channel. That is not
/// redundant with dropping the handle: [`crate::server::handle_agent`] keeps its
/// own `out_tx` alive for the life of the read loop (rotation pushes go through
/// it), so the registry holds a *clone* and removing the entry closes nothing.
/// A caller that needs the socket actually torn down — node deletion, which is
/// a revocation — must say so explicitly.
#[derive(Debug, Clone)]
pub struct AgentHandle {
    tx: mpsc::Sender<AgentMessage>,
    shutdown: Arc<Notify>,
}

impl AgentHandle {
    /// Wrap a sender into the agent writer task.
    #[must_use]
    pub fn new(tx: mpsc::Sender<AgentMessage>) -> Self {
        Self {
            tx,
            shutdown: Arc::new(Notify::new()),
        }
    }

    /// Ask the owning connection task to close this agent's connection.
    ///
    /// Uses `notify_one` rather than `notify_waiters` deliberately: it stores a
    /// permit when nobody is waiting yet, which closes the race between
    /// [`AgentRegistry::insert`] and the read loop reaching its `select!`. A
    /// signal delivered in that window must not be dropped on the floor — the
    /// caller has already deleted the node row.
    pub fn shutdown(&self) {
        self.shutdown.notify_one();
    }

    /// The signal the owning connection task waits on.
    ///
    /// The waiter must create its [`Notify::notified`] future **once** and hold
    /// it across `select!` iterations (see [`crate::server::handle_agent`]): a
    /// future that is polled and then dropped each time round can consume the
    /// stored permit and lose it.
    #[must_use]
    pub fn shutdown_signal(&self) -> Arc<Notify> {
        Arc::clone(&self.shutdown)
    }

    /// Send a control command to the agent.
    ///
    /// # Errors
    ///
    /// Returns the message back if the agent's writer task has gone away.
    pub async fn send_command(
        &self,
        cmd: CoordinatorCommand,
    ) -> Result<(), mpsc::error::SendError<AgentMessage>> {
        self.tx.send(AgentMessage::Command(cmd)).await
    }

    /// Send a data frame to the agent.
    ///
    /// # Errors
    ///
    /// Returns the message back if the agent's writer task has gone away.
    pub async fn send_data(
        &self,
        frame: DataFrame,
    ) -> Result<(), mpsc::error::SendError<AgentMessage>> {
        self.tx.send(AgentMessage::Data(frame)).await
    }
}

/// A message bound for a sidecar connection's writer task.
pub type SidecarHandle = mpsc::Sender<CoordToSidecar>;

/// Registry of connected sidecar/ctl connections, keyed by [`RequesterId`].
///
/// Exists so the coordinator can push a message a client did not ask for on
/// this round trip. v1 has exactly one such push: a queued lease request that
/// gets promoted when a board frees up, which is the difference between a CI
/// leg waiting its turn and a CI leg failing.
///
/// Keyed per **connection**, not per subject: one subject may hold several
/// connections at once and a promotion belongs to the one that queued. That is
/// also what lets [`Scheduler::remove_waiters`] drop exactly the right waiters
/// when a socket closes.
///
/// [`Scheduler::remove_waiters`]: fleet_core::scheduler::Scheduler::remove_waiters
#[derive(Debug, Clone, Default)]
pub struct SidecarRegistry {
    inner: Arc<Mutex<HashMap<RequesterId, SidecarHandle>>>,
    next: Arc<AtomicU64>,
}

impl SidecarRegistry {
    /// A new, empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Mint a fresh [`RequesterId`], never reused for the life of the process.
    ///
    /// Starts at 1: [`RequesterId::DETACHED`] is 0 and must never collide with
    /// a real connection, or a detached call path would inherit somebody's
    /// promotion channel.
    pub fn mint(&self) -> RequesterId {
        RequesterId(self.next.fetch_add(1, Ordering::Relaxed) + 1)
    }

    /// Register a connection's handle.
    pub async fn insert(&self, id: RequesterId, handle: SidecarHandle) {
        self.inner.lock().await.insert(id, handle);
    }

    /// Remove a connection (on disconnect).
    ///
    /// **Does not close the connection**, and cannot: the connection task holds
    /// its own sender clone, so dropping the registry's changes nothing — the
    /// same property [`AgentRegistry::remove`] documents. This is the right
    /// call from the connection's own teardown, where the socket is already
    /// going away.
    pub async fn remove(&self, id: RequesterId) {
        self.inner.lock().await.remove(&id);
    }

    /// Get a clone of a connection's handle, if it is still registered.
    pub async fn get(&self, id: RequesterId) -> Option<SidecarHandle> {
        self.inner.lock().await.get(&id).cloned()
    }

    /// Number of connected sidecars.
    pub async fn len(&self) -> usize {
        self.inner.lock().await.len()
    }

    /// Whether no sidecars are connected.
    pub async fn is_empty(&self) -> bool {
        self.inner.lock().await.is_empty()
    }
}

/// Registry of connected agents, keyed by [`AgentId`]. Cloneable handle over a
/// shared map.
#[derive(Debug, Clone, Default)]
pub struct AgentRegistry {
    inner: Arc<Mutex<HashMap<AgentId, AgentHandle>>>,
}

impl AgentRegistry {
    /// A new, empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register (or replace) an agent's handle.
    pub async fn insert(&self, agent: AgentId, handle: AgentHandle) {
        self.inner.lock().await.insert(agent, handle);
    }

    /// Remove an agent (on disconnect).
    ///
    /// **Does not close the connection**, and cannot: the connection task holds
    /// its own sender clone, so dropping the registry's changes nothing. This
    /// is the right call from `handle_agent`'s own teardown, where the socket
    /// is already going away. A caller that is *revoking* a node wants
    /// [`AgentRegistry::remove_and_close`].
    pub async fn remove(&self, agent: &AgentId) {
        self.inner.lock().await.remove(agent);
    }

    /// Remove an agent **and** tear its connection down.
    ///
    /// The revocation path (node deletion): unrouting the node is not enough,
    /// because an already-open socket would otherwise linger until it dropped
    /// of its own accord — an operator who deleted a node would still have the
    /// machine attached to the fleet. Returns whether an entry was present.
    pub async fn remove_and_close(&self, agent: &AgentId) -> bool {
        let handle = self.inner.lock().await.remove(agent);
        if let Some(handle) = handle {
            handle.shutdown();
            true
        } else {
            false
        }
    }

    /// Get a clone of an agent's handle, if connected.
    pub async fn get(&self, agent: &AgentId) -> Option<AgentHandle> {
        self.inner.lock().await.get(agent).cloned()
    }

    /// Number of connected agents.
    pub async fn len(&self) -> usize {
        self.inner.lock().await.len()
    }

    /// Whether no agents are connected.
    pub async fn is_empty(&self) -> bool {
        self.inner.lock().await.is_empty()
    }
}

/// Routing endpoints for one open relay channel.
#[derive(Debug, Clone)]
pub struct ChannelRoute {
    /// The lease that authorised this channel.
    pub lease: LeaseId,
    /// The agent that owns the board on the far side.
    pub agent: AgentId,
    /// Sender into the sidecar connection that opened the channel.
    pub sidecar: SidecarHandle,
    /// Which plane this channel carries (data vs. gdb). The relay treats both
    /// identically; this is bookkeeping for diagnostics and teardown.
    pub kind: fleet_proto::ChannelKind,
}

/// Table of open relay channels, keyed by [`ChannelId`]. Also owns the monotonic
/// channel-id allocator.
#[derive(Debug, Clone, Default)]
pub struct ChannelTable {
    inner: Arc<Mutex<ChannelTableInner>>,
}

#[derive(Debug, Default)]
struct ChannelTableInner {
    next_id: u64,
    routes: HashMap<ChannelId, ChannelRoute>,
}

impl ChannelTable {
    /// A new, empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate a fresh, never-before-used [`ChannelId`].
    pub async fn allocate(&self) -> ChannelId {
        let mut inner = self.inner.lock().await;
        let id = inner.next_id;
        inner.next_id += 1;
        ChannelId(id)
    }

    /// Register a route for an allocated channel.
    pub async fn insert(&self, channel: ChannelId, route: ChannelRoute) {
        self.inner.lock().await.routes.insert(channel, route);
    }

    /// Look up a channel's route.
    pub async fn get(&self, channel: ChannelId) -> Option<ChannelRoute> {
        self.inner.lock().await.routes.get(&channel).cloned()
    }

    /// Remove a channel route (on close); returns it if present.
    pub async fn remove(&self, channel: ChannelId) -> Option<ChannelRoute> {
        self.inner.lock().await.routes.remove(&channel)
    }

    /// All channels currently routed to the given lease.
    pub async fn channels_for_lease(&self, lease: LeaseId) -> Vec<ChannelId> {
        self.inner
            .lock()
            .await
            .routes
            .iter()
            .filter(|(_, r)| r.lease == lease)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Number of open channels.
    pub async fn len(&self) -> usize {
        self.inner.lock().await.routes.len()
    }

    /// Whether no channels are open.
    pub async fn is_empty(&self) -> bool {
        self.inner.lock().await.routes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn agent_registry_insert_get_remove() {
        let reg = AgentRegistry::new();
        let (tx, mut rx) = mpsc::channel(4);
        let agent = AgentId("agent-a".to_owned());
        reg.insert(agent.clone(), AgentHandle::new(tx)).await;
        assert_eq!(reg.len().await, 1);

        let handle = reg.get(&agent).await.unwrap();
        handle.send_command(CoordinatorCommand::QueryState).await.unwrap();
        let got = rx.recv().await.unwrap();
        assert!(matches!(
            got,
            AgentMessage::Command(CoordinatorCommand::QueryState)
        ));

        reg.remove(&agent).await;
        assert!(reg.is_empty().await);
        assert!(reg.get(&agent).await.is_none());
    }

    #[tokio::test]
    async fn sidecar_registry_mints_unique_ids_and_never_the_detached_one() {
        let reg = SidecarRegistry::new();
        let a = reg.mint();
        let b = reg.mint();
        assert_ne!(a, b);
        assert_ne!(a, RequesterId::DETACHED);
        assert_ne!(b, RequesterId::DETACHED);

        let (tx, mut rx) = mpsc::channel(4);
        reg.insert(a, tx).await;
        assert_eq!(reg.len().await, 1);
        reg.get(a)
            .await
            .unwrap()
            .send(CoordToSidecar::Queued { position: 0 })
            .await
            .unwrap();
        assert!(matches!(
            rx.recv().await.unwrap(),
            CoordToSidecar::Queued { position: 0 }
        ));

        reg.remove(a).await;
        assert!(reg.is_empty().await);
        assert!(reg.get(a).await.is_none());
    }

    #[tokio::test]
    async fn channel_table_allocates_monotonically() {
        let table = ChannelTable::new();
        let a = table.allocate().await;
        let b = table.allocate().await;
        let c = table.allocate().await;
        assert_eq!(a, ChannelId(0));
        assert_eq!(b, ChannelId(1));
        assert_eq!(c, ChannelId(2));
    }

    #[tokio::test]
    async fn channel_table_route_lifecycle() {
        let table = ChannelTable::new();
        let (tx, _rx) = mpsc::channel(4);
        let ch = table.allocate().await;
        table
            .insert(
                ch,
                ChannelRoute {
                    lease: LeaseId(1),
                    agent: AgentId("agent-a".to_owned()),
                    sidecar: tx,
                    kind: fleet_proto::ChannelKind::Data,
                },
            )
            .await;
        assert_eq!(table.len().await, 1);
        assert_eq!(table.channels_for_lease(LeaseId(1)).await, vec![ch]);
        assert!(table.channels_for_lease(LeaseId(2)).await.is_empty());

        let route = table.get(ch).await.unwrap();
        assert_eq!(route.lease, LeaseId(1));

        let removed = table.remove(ch).await.unwrap();
        assert_eq!(removed.agent, AgentId("agent-a".to_owned()));
        assert!(table.is_empty().await);
    }
}

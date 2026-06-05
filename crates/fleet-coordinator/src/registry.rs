//! Connection registries: agents and relay channels.
//!
//! Two shared tables, both behind `tokio::sync` locks:
//!
//! * [`AgentRegistry`] maps an [`AgentId`] to a handle for sending
//!   [`CoordinatorCommand`]s (and [`DataFrame`]s) down that agent's persistent
//!   dial-out connection. The per-connection writer task drains the channel, so
//!   the relay and the expiry sweep can push without sharing the TLS stream.
//! * [`ChannelTable`] maps a [`ChannelId`] to the routing endpoints of an open
//!   relay channel, so a [`DataFrame`] arriving from either side can be
//!   forwarded to the other.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::sync::Mutex;

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
#[derive(Debug, Clone)]
pub struct AgentHandle {
    tx: mpsc::Sender<AgentMessage>,
}

impl AgentHandle {
    /// Wrap a sender into the agent writer task.
    #[must_use]
    pub fn new(tx: mpsc::Sender<AgentMessage>) -> Self {
        Self { tx }
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
    pub async fn remove(&self, agent: &AgentId) {
        self.inner.lock().await.remove(agent);
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

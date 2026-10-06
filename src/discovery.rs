// SPDX-License-Identifier: MPL-2.0
// Portions of Veilid, Copyright Veilid contributors.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. https://mozilla.org/MPL/2.0/
// Upstream dd8e2cdd72b5bf817172ac31c20872b168c5c8fc:
// rpc_processor/fanout/fanout_queue.rs (unique nodes, sorted queue, one dispatch).
//! Bounded iterative discovery state. Mesh drives actual concurrent RPCs/deadlines.
//! Nodes enter only with verified original PeerInfo; transport validates endpoints.
use crate::{
    Error,
    network::NodeId,
    rpc::peers::{DHTV, VerifiedExtensionPeer},
};
use std::{collections::BTreeMap, num::NonZeroUsize, sync::Arc};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Queued,
    InProgress,
    Answered,
    Failed,
}
struct Entry {
    peer: Arc<VerifiedExtensionPeer>,
    stage: Stage,
}
/// One lookup, with no fixed population or operator record storage. Dynamic peer
/// hints enter the same XOR-sorted queue. A node is dispatched at most once.
pub struct Discovery {
    target: NodeId,
    own_node: NodeId,
    maximum: usize,
    nodes: BTreeMap<NodeId, Entry>,
    limited: bool,
}
impl Discovery {
    /// Begin one bounded lookup. This bound limits memory/work, not replication or
    /// record lifetime. Resource exhaustion remains explicit incomplete knowledge.
    pub fn new(target: NodeId, own_node: NodeId, maximum: NonZeroUsize) -> Self {
        Self {
            target,
            own_node,
            maximum: maximum.get(),
            nodes: BTreeMap::new(),
            limited: false,
        }
    }
    /// Admit an independently authenticated, transport-checked bootstrap or hint.
    /// Repeated identities never gain another query or another consensus vote.
    pub fn insert(&mut self, peer: Arc<VerifiedExtensionPeer>) -> Result<(), Error> {
        let node = *peer.node_id();
        if node == self.own_node || self.nodes.contains_key(&node) {
            return Ok(());
        }
        if self.nodes.len() == self.maximum {
            self.limited = true;
            return Err(Error::Unavailable);
        }
        self.nodes.insert(
            node,
            Entry {
                peer,
                stage: Stage::Queued,
            },
        );
        Ok(())
    }
    /// Reserve the closest unasked node for one actual RPC lane. A timeout must
    /// complete that reservation as failed; it must never be requeued silently.
    pub fn next_peer(&mut self) -> Option<Arc<VerifiedExtensionPeer>> {
        let key = self
            .nodes
            .iter()
            .filter(|(_, entry)| entry.stage == Stage::Queued)
            .min_by_key(|(node, _)| distance(node, &self.target))
            .map(|(node, _)| *node)?;
        let entry = self.nodes.get_mut(&key).expect("selected existing entry");
        entry.stage = Stage::InProgress;
        Some(entry.peer.clone())
    }
    /// Finish precisely one dispatched RPC after authenticating its answer. New
    /// hints are inserted separately only after their own signatures/endpoint checks.
    pub fn finish(&mut self, node: &NodeId, answered: bool) -> Result<(), Error> {
        let entry = self.nodes.get_mut(node).ok_or(Error::UnknownRecord)?;
        if entry.stage != Stage::InProgress {
            return Err(Error::Conflict);
        }
        entry.stage = if answered {
            Stage::Answered
        } else {
            Stage::Failed
        };
        Ok(())
    }
    /// Whether all discovered nodes have actually completed a query. A bounded
    /// stop, queue with pending lanes or timeout is never convergence or absence.
    pub fn exhausted(&self) -> bool {
        !self.limited
            && self
                .nodes
                .values()
                .all(|entry| matches!(entry.stage, Stage::Answered | Stage::Failed))
    }
    /// Whether any hints could not be retained because the caller's bound was hit.
    pub fn limited(&self) -> bool {
        self.limited
    }
    /// Responsive storage nodes ordered by XOR distance. Bootstrap nodes without
    /// DHTV and unreachable nodes cannot become storage holders by assertion.
    pub fn storage_peers(&self) -> Vec<Arc<VerifiedExtensionPeer>> {
        let mut peers: Vec<_> = self
            .nodes
            .values()
            .filter(|entry| {
                entry.stage == Stage::Answered
                    && entry.peer.advertisement().capabilities.contains(&DHTV)
            })
            .map(|entry| entry.peer.clone())
            .collect();
        peers.sort_unstable_by_key(|peer| distance(peer.node_id(), &self.target));
        peers.truncate(crate::network::MAX_FANOUT_NODES);
        peers
    }
}
fn distance(a: &NodeId, b: &NodeId) -> NodeId {
    std::array::from_fn(|i| a[i] ^ b[i])
}

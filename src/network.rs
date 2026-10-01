//! Transport-independent Veilid record fanout. Mesh supplies the network port.
//!
//! Peers are ordered by XOR distance. Sets seek five agreeing holders; reads seek
//! three, returning signed partial results with explicit agreement evidence.
use crate::{
    Backend, Change, Descriptor, Error, RecordKey, SetOutcome, SignedValue, Verifier, WatchId,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    sync::Mutex,
};

/// VLD0 node coordinate used for closest-node selection.
pub type NodeId = [u8; 32];
/// Upstream set-value replication target.
pub const SET_VALUE_COUNT: usize = 5;
/// Upstream get-value agreement target.
pub const GET_VALUE_COUNT: usize = 3;
/// Bounded discovery candidates for one operation.
pub const MAX_FANOUT_NODES: usize = 20;

/// Node RPCs implemented by Mesh's Tor or Veilid adapter. This port transports
/// existing signatures, sequence numbers, ciphertext and nonces verbatim.
///
/// The adapter authenticates peer identities, bounds replies and RPC deadlines,
/// discovers closer peers, and drives each node's watch clock. A node's `set`
/// validates descriptor and value before storing either. Nodes are independent;
/// cloning an adapter must not turn them into a shared record store.
pub trait Network {
    /// Monotonic runtime time used to throttle rehydration checks.
    fn now_ms(&self) -> u64;
    /// Discover candidate storage nodes. Duplicates never count towards agreement.
    fn closest(&self, key: &RecordKey) -> impl Future<Output = Result<Vec<NodeId>, Error>>;
    /// Fetch an owner-signed descriptor from one node.
    fn descriptor(
        &self,
        node: &NodeId,
        key: &RecordKey,
    ) -> impl Future<Output = Result<Option<Descriptor>, Error>>;
    /// Fetch one node's value, without silently querying other nodes. A reachable
    /// node with no record/subkey returns `Ok(None)`; silence is `Unavailable`.
    fn get(
        &self,
        node: &NodeId,
        key: &RecordKey,
        subkey: u32,
    ) -> impl Future<Output = Result<Option<SignedValue>, Error>>;
    /// Validate and store a descriptor/value at one node. A stale/equal-conflicting
    /// write returns the existing signed value; an identical write is idempotent.
    fn set(
        &self,
        node: &NodeId,
        descriptor: &Descriptor,
        subkey: u32,
        value: &SignedValue,
    ) -> impl Future<Output = Result<SetOutcome, Error>>;
    /// Subscribe on one storage node. The adapter maintains the bounded lease.
    fn watch(&self, node: &NodeId, key: &RecordKey)
    -> impl Future<Output = Result<WatchId, Error>>;
    /// Cancel that node's subscription.
    fn cancel_watch(
        &self,
        node: &NodeId,
        watch: WatchId,
    ) -> impl Future<Output = Result<(), Error>>;
    /// Change hints. Lease loss must return an error so the client refreshes.
    fn changes(
        &self,
        node: &NodeId,
        watch: WatchId,
    ) -> impl Future<Output = Result<Vec<Change>, Error>>;
}

/// Read evidence. A valid partial result is not quorum or proof of absence.
#[derive(Clone, Debug)]
pub struct ReadReport {
    /// Highest valid signed value found.
    pub value: Option<SignedValue>,
    /// Distinct nodes holding exactly that value.
    pub agreement: usize,
    /// Distinct nodes queried, including unavailable or invalid responders.
    pub contacted: usize,
}

impl ReadReport {
    /// Whether the read reached Veilid's target of three agreeing holders.
    pub fn has_consensus(&self) -> bool {
        self.value.is_some() && self.agreement >= GET_VALUE_COUNT
    }
}

struct RemoteWatch {
    node: NodeId,
    remote: WatchId,
    key: RecordKey,
}

/// Record replication over a caller-owned network port. Own records remain in
/// `Dht::state`; remote-node capacity belongs to each node's independent store.
pub struct NetworkBackend<N: Network, V: Verifier> {
    network: N,
    verifier: V,
    descriptors: Mutex<BTreeMap<RecordKey, Descriptor>>,
    watches: Mutex<BTreeMap<WatchId, RemoteWatch>>,
    next_watch: Mutex<u64>,
    rechecked: Mutex<BTreeMap<(RecordKey, u32), (u64, u32)>>,
}

impl<N: Network, V: Verifier> NetworkBackend<N, V> {
    /// Wrap a Mesh network capability and a signature verifier.
    pub fn new(network: N, verifier: V) -> Self {
        Self {
            network,
            verifier,
            descriptors: Mutex::new(BTreeMap::new()),
            watches: Mutex::new(BTreeMap::new()),
            next_watch: Mutex::new(1),
            rechecked: Mutex::new(BTreeMap::new()),
        }
    }

    /// Access the transport capability for lifecycle and health management.
    pub fn network(&self) -> &N {
        &self.network
    }

    async fn peers(&self, key: &RecordKey) -> Result<Vec<NodeId>, Error> {
        let nodes: BTreeSet<_> = self.network.closest(key).await?.into_iter().collect();
        let mut nodes: Vec<_> = nodes.into_iter().collect();
        nodes.sort_by_cached_key(|node| {
            let mut distance = [0; 32];
            for i in 0..32 {
                distance[i] = node[i] ^ key.0[i];
            }
            distance
        });
        nodes.truncate(MAX_FANOUT_NODES);
        if nodes.is_empty() {
            return Err(Error::Unavailable);
        }
        Ok(nodes)
    }

    fn cached_descriptor(&self, key: &RecordKey) -> Result<Descriptor, Error> {
        self.descriptors
            .lock()
            .map_err(|_| Error::Unavailable)?
            .get(key)
            .cloned()
            .ok_or(Error::UnknownRecord)
    }

    /// Read through the actual fanout and retain explicit agreement evidence.
    /// Like Veilid, exhaustion may return a validated value below the target.
    pub async fn read(&self, key: &RecordKey, subkey: u32) -> Result<ReadReport, Error> {
        self.read_target(key, subkey, GET_VALUE_COUNT).await
    }

    async fn read_target(
        &self,
        key: &RecordKey,
        subkey: u32,
        target: usize,
    ) -> Result<ReadReport, Error> {
        let descriptor = self.cached_descriptor(key)?;
        let schema = descriptor.validate_for(key, &self.verifier)?;
        if subkey as usize >= schema.subkey_count() {
            return Err(Error::SubkeyOutOfRange);
        }
        let mut report = ReadReport {
            value: None,
            agreement: 0,
            contacted: 0,
        };
        let mut reachable = 0;
        for node in self.peers(key).await? {
            report.contacted += 1;
            let Ok(response) = self.network.get(&node, key, subkey).await else {
                continue;
            };
            let Some(value) = response else {
                reachable += 1;
                continue;
            };
            if value
                .validate(key, &descriptor.owner, &schema, subkey, &self.verifier)
                .is_err()
            {
                continue;
            }
            reachable += 1;
            match &report.value {
                Some(current) if current.same_value(&value) => report.agreement += 1,
                Some(current) if current.seq >= value.seq => {}
                _ => {
                    report.value = Some(value);
                    report.agreement = 1;
                }
            }
            if report.agreement >= target {
                break;
            }
        }
        if reachable == 0 {
            return Err(Error::Unavailable);
        }
        Ok(report)
    }
}

impl<N: Network, V: Verifier> Backend for NetworkBackend<N, V> {
    async fn create(&self, descriptor: &Descriptor) -> Result<(), Error> {
        descriptor.validate(&self.verifier)?;
        self.descriptors
            .lock()
            .map_err(|_| Error::Unavailable)?
            .insert(descriptor.key(), descriptor.clone());
        Ok(())
    }

    async fn descriptor(&self, key: &RecordKey) -> Result<Option<Descriptor>, Error> {
        if let Ok(descriptor) = self.cached_descriptor(key) {
            return Ok(Some(descriptor));
        }
        let mut reachable = false;
        for node in self.peers(key).await? {
            match self.network.descriptor(&node, key).await {
                Ok(Some(descriptor)) => {
                    if descriptor.validate_for(key, &self.verifier).is_ok() {
                        self.create(&descriptor).await?;
                        return Ok(Some(descriptor));
                    }
                }
                Ok(None) => reachable = true,
                Err(_) => {}
            }
        }
        if reachable {
            Ok(None)
        } else {
            Err(Error::Unavailable)
        }
    }

    async fn get(&self, key: &RecordKey, subkey: u32) -> Result<Option<SignedValue>, Error> {
        Ok(self.read(key, subkey).await?.value)
    }

    async fn set(
        &self,
        key: &RecordKey,
        subkey: u32,
        value: &SignedValue,
    ) -> Result<SetOutcome, Error> {
        let descriptor = self.cached_descriptor(key)?;
        let schema = descriptor.validate_for(key, &self.verifier)?;
        value.validate(key, &descriptor.owner, &schema, subkey, &self.verifier)?;
        let peers = self.peers(key).await?;
        let mut candidate = value.clone();
        // Upstream restarts its fanout on a newer/equal-conflicting signed value.
        // Bound this in an adversarial oscillation; the caller keeps its pending write.
        for _ in 0..MAX_FANOUT_NODES {
            let mut agreement = 0;
            let mut restart = false;
            for node in &peers {
                match self
                    .network
                    .set(node, &descriptor, subkey, &candidate)
                    .await
                {
                    Ok(SetOutcome::Accepted) => agreement += 1,
                    Ok(SetOutcome::Newer(current)) => {
                        if current
                            .validate(key, &descriptor.owner, &schema, subkey, &self.verifier)
                            .is_err()
                            || current.seq < candidate.seq
                        {
                            continue;
                        }
                        if current.same_value(&candidate) {
                            agreement += 1;
                        } else {
                            candidate = current;
                            restart = true;
                            break;
                        }
                    }
                    Err(_) => {}
                }
                if agreement >= SET_VALUE_COUNT {
                    return Ok(if candidate.same_value(value) {
                        SetOutcome::Accepted
                    } else {
                        SetOutcome::Newer(candidate)
                    });
                }
            }
            if !restart {
                return Err(Error::Unavailable);
            }
        }
        Err(Error::Unavailable)
    }

    async fn rehydrate(
        &self,
        key: &RecordKey,
        subkey: u32,
        value: &SignedValue,
    ) -> Result<SetOutcome, Error> {
        let now = self.network.now_ms();
        if self
            .rechecked
            .lock()
            .map_err(|_| Error::Unavailable)?
            .get(&(*key, subkey))
            .is_some_and(|(time, seq)| *seq == value.seq && now.saturating_sub(*time) < 300_000)
        {
            return Ok(SetOutcome::Accepted);
        }
        // Upstream rehydrate.rs requires at least one answered inspection. Silence
        // is not evidence of absence and must not trigger blind republishing.
        let report = self.read_target(key, subkey, SET_VALUE_COUNT).await?;
        if report.agreement >= SET_VALUE_COUNT
            && let Some(remote) = report.value
            && remote.seq >= value.seq
        {
            self.rechecked
                .lock()
                .map_err(|_| Error::Unavailable)?
                .insert((*key, subkey), (now, remote.seq));
            return Ok(if remote.same_value(value) {
                SetOutcome::Accepted
            } else {
                SetOutcome::Newer(remote)
            });
        }
        let result = self.set(key, subkey, value).await;
        if result.is_ok() {
            self.rechecked
                .lock()
                .map_err(|_| Error::Unavailable)?
                .insert((*key, subkey), (now, value.seq));
        }
        result
    }

    async fn watch(&self, key: &RecordKey) -> Result<WatchId, Error> {
        self.cached_descriptor(key)?;
        for node in self.peers(key).await? {
            if let Ok(remote) = self.network.watch(&node, key).await {
                let mut watches = self.watches.lock().map_err(|_| Error::Unavailable)?;
                let mut next = self.next_watch.lock().map_err(|_| Error::Unavailable)?;
                let id = WatchId(*next);
                *next = next.checked_add(1).ok_or(Error::Unavailable)?;
                watches.insert(
                    id,
                    RemoteWatch {
                        node,
                        remote,
                        key: *key,
                    },
                );
                return Ok(id);
            }
        }
        Err(Error::Unavailable)
    }

    async fn cancel_watch(&self, id: WatchId) -> Result<(), Error> {
        let watch = self
            .watches
            .lock()
            .map_err(|_| Error::Unavailable)?
            .remove(&id);
        if let Some(watch) = watch {
            self.network.cancel_watch(&watch.node, watch.remote).await?;
        }
        Ok(())
    }

    async fn changes(&self, id: WatchId) -> Result<Vec<Change>, Error> {
        let (node, remote, key) = {
            let watches = self.watches.lock().map_err(|_| Error::Unavailable)?;
            let watch = watches.get(&id).ok_or(Error::UnknownWatch)?;
            (watch.node, watch.remote, watch.key)
        };
        let descriptor = self.cached_descriptor(&key)?;
        let schema = descriptor.validate_for(&key, &self.verifier)?;
        let changes = self.network.changes(&node, remote).await?;
        if changes.len() > schema.subkey_count()
            || changes.iter().any(|c| {
                c.key != key || c.subkey as usize >= schema.subkey_count() || c.seq > crate::MAX_SEQ
            })
        {
            return Err(Error::Encoding);
        }
        Ok(changes)
    }
}

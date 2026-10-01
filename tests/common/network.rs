//! A deterministic transport simulator. All storage and protocol logic is cdht's.
#![allow(dead_code)]
use super::TestVerifier;
use cdht::{
    Backend, Capacity, Change, Descriptor, Error, LocalBackend, Network, NodeId, RecordKey,
    SetOutcome, SignedValue, WatchId,
};
use std::sync::{Arc, Mutex};

struct Node {
    id: NodeId,
    online: bool,
    store: LocalBackend<TestVerifier>,
}
#[derive(Clone)]
pub struct SimNetwork {
    nodes: Arc<Mutex<Vec<Node>>>,
    capacity: Capacity,
    local: Option<NodeId>,
    clock: Arc<std::sync::atomic::AtomicU64>,
    reads_silent: Arc<std::sync::atomic::AtomicBool>,
}
impl SimNetwork {
    pub fn new(population: usize, capacity: Capacity) -> Self {
        let nodes = (0..population)
            .map(|i| Node {
                id: *blake3::hash(&(i as u64).to_le_bytes()).as_bytes(),
                online: true,
                store: LocalBackend::with_capacity(TestVerifier, capacity),
            })
            .collect();
        Self {
            nodes: Arc::new(Mutex::new(nodes)),
            capacity,
            local: None,
            clock: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            reads_silent: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }
    pub fn for_node(&self, index: usize) -> Self {
        let mut network = self.clone();
        network.local = Some(self.id(index));
        network
    }
    pub fn online(&self, index: usize, online: bool) {
        self.nodes.lock().unwrap()[index].online = online;
    }
    pub fn replace(&self, index: usize) {
        self.nodes.lock().unwrap()[index].store =
            LocalBackend::with_capacity(TestVerifier, self.capacity);
    }
    pub fn store(&self, index: usize) -> LocalBackend<TestVerifier> {
        self.nodes.lock().unwrap()[index].store.clone()
    }
    pub fn id(&self, index: usize) -> NodeId {
        self.nodes.lock().unwrap()[index].id
    }
    pub fn advance_to(&self, now: u64) {
        self.clock
            .fetch_max(now, std::sync::atomic::Ordering::Relaxed);
        for node in self.nodes.lock().unwrap().iter() {
            node.store.advance_to(now);
        }
    }
    pub fn evictions(&self) -> usize {
        self.nodes
            .lock()
            .unwrap()
            .iter()
            .map(|n| n.store.usage().2)
            .sum()
    }
    pub fn silence_reads(&self, silent: bool) {
        self.reads_silent
            .store(silent, std::sync::atomic::Ordering::Relaxed);
    }
    fn node(&self, id: &NodeId) -> Result<LocalBackend<TestVerifier>, Error> {
        self.nodes
            .lock()
            .unwrap()
            .iter()
            .find(|n| n.id == *id && n.online)
            .map(|n| n.store.clone())
            .ok_or(Error::Unavailable)
    }
}
impl Network for SimNetwork {
    fn now_ms(&self) -> u64 {
        self.clock.load(std::sync::atomic::Ordering::Relaxed)
    }
    async fn closest(&self, _: &RecordKey) -> Result<Vec<NodeId>, Error> {
        Ok(self
            .nodes
            .lock()
            .unwrap()
            .iter()
            .filter(|n| n.online && self.local != Some(n.id))
            .map(|n| n.id)
            .collect())
    }
    async fn descriptor(
        &self,
        node: &NodeId,
        key: &RecordKey,
    ) -> Result<Option<Descriptor>, Error> {
        self.node(node)?.descriptor(key).await
    }
    async fn get(
        &self,
        node: &NodeId,
        key: &RecordKey,
        subkey: u32,
    ) -> Result<Option<SignedValue>, Error> {
        if self.reads_silent.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(Error::Unavailable);
        }
        match self.node(node)?.get(key, subkey).await {
            Err(Error::UnknownRecord) => Ok(None),
            result => result,
        }
    }
    async fn set(
        &self,
        node: &NodeId,
        descriptor: &Descriptor,
        subkey: u32,
        value: &SignedValue,
    ) -> Result<SetOutcome, Error> {
        // Reject the complete arrival before changing storage, including its descriptor.
        let schema = descriptor.validate(&TestVerifier)?;
        value.validate(
            &descriptor.key(),
            &descriptor.owner,
            &schema,
            subkey,
            &TestVerifier,
        )?;
        let store = self.node(node)?;
        store.create(descriptor).await?;
        store.set(&descriptor.key(), subkey, value).await
    }
    async fn watch(&self, node: &NodeId, key: &RecordKey) -> Result<WatchId, Error> {
        self.node(node)?.watch(key).await
    }
    async fn cancel_watch(&self, node: &NodeId, id: WatchId) -> Result<(), Error> {
        self.node(node)?.cancel_watch(id).await
    }
    async fn changes(&self, node: &NodeId, id: WatchId) -> Result<Vec<Change>, Error> {
        self.node(node)?.changes(id).await
    }
}

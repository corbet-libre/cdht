//! A deterministic transport simulator. All storage and protocol logic is cdht's.
#![allow(dead_code)]
use super::TestVerifier;
use cdht::{
    Backend, Capacity, Change, Descriptor, Error, LocalBackend, Network, NodeId, RecordKey,
    SetOutcome, SignedValue, WatchId,
};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct ReplyGate {
    paused: std::sync::atomic::AtomicBool,
    waiter: Mutex<Option<std::task::Waker>>,
}
impl ReplyGate {
    fn pause(&self, paused: bool) {
        self.paused
            .store(paused, std::sync::atomic::Ordering::SeqCst);
        if !paused && let Some(waiter) = self.waiter.lock().unwrap().take() {
            waiter.wake();
        }
    }
    async fn wait(&self) {
        std::future::poll_fn(|cx| {
            let mut waiter = self.waiter.lock().unwrap();
            if self.paused.load(std::sync::atomic::Ordering::SeqCst) {
                *waiter = Some(cx.waker().clone());
                std::task::Poll::Pending
            } else {
                std::task::Poll::Ready(())
            }
        })
        .await;
    }
}

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
    watch_gate: Arc<ReplyGate>,
    get_gate: Arc<ReplyGate>,
    corrupt_descriptors: Arc<std::sync::atomic::AtomicBool>,
    corrupt_values: Arc<std::sync::atomic::AtomicBool>,
    corrupt_changes: Arc<std::sync::atomic::AtomicU8>,
    replayed_set_value: Arc<Mutex<Option<Vec<u8>>>>,
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
            watch_gate: Arc::new(ReplyGate::default()),
            get_gate: Arc::new(ReplyGate::default()),
            corrupt_descriptors: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            corrupt_values: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            corrupt_changes: Arc::new(std::sync::atomic::AtomicU8::new(0)),
            replayed_set_value: Arc::new(Mutex::new(None)),
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
    /// Delay only the reply after the actual node has allocated its lease.
    pub fn pause_watch_replies(&self, paused: bool) {
        self.watch_gate.pause(paused);
    }
    pub fn pause_get_replies(&self, paused: bool) {
        self.get_gate.pause(paused);
    }
    /// Flip only received signature bytes; independent stored records stay intact.
    pub fn corrupt_record_replies(&self, descriptors: bool, values: bool) {
        self.corrupt_descriptors
            .store(descriptors, std::sync::atomic::Ordering::Relaxed);
        self.corrupt_values
            .store(values, std::sync::atomic::Ordering::Relaxed);
    }
    /// Corrupt a received real notification, never the node's own watch state.
    pub fn corrupt_change_replies(&self, mode: u8) {
        self.corrupt_changes
            .store(mode, std::sync::atomic::Ordering::Relaxed);
    }
    /// Retain an actual observed signed value as a transport replay packet.
    pub fn replay_set_value(&self, value: &SignedValue) {
        *self.replayed_set_value.lock().unwrap() = Some(
            cdht::rpc::ValueBytes::encode(value)
                .unwrap()
                .as_bytes()
                .to_vec(),
        );
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
        let mut result = self.node(node)?.descriptor(key).await?;
        if self
            .corrupt_descriptors
            .load(std::sync::atomic::Ordering::Relaxed)
            && let Some(descriptor) = result.as_mut()
        {
            descriptor.signature[0] ^= 1;
        }
        Ok(result)
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
        let mut result = match self.node(node)?.get(key, subkey).await {
            Err(Error::UnknownRecord) => Ok(None),
            result => result,
        }?;
        if self
            .corrupt_values
            .load(std::sync::atomic::Ordering::Relaxed)
            && let Some(value) = result.as_mut()
        {
            value.signature[0] ^= 1;
        }
        self.get_gate.wait().await;
        Ok(result)
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
        let mut result = store.set(&descriptor.key(), subkey, value).await?;
        if let Some(bytes) = self.replayed_set_value.lock().unwrap().clone() {
            return Ok(SetOutcome::Newer(
                cdht::rpc::ValueBytes::from_bytes(bytes)?.decode()?,
            ));
        }
        if self
            .corrupt_values
            .load(std::sync::atomic::Ordering::Relaxed)
            && let SetOutcome::Newer(current) = &mut result
        {
            current.signature[0] ^= 1;
        }
        Ok(result)
    }
    async fn watch(&self, node: &NodeId, key: &RecordKey) -> Result<WatchId, Error> {
        let result = self.node(node)?.watch(key).await;
        self.watch_gate.wait().await;
        result
    }
    async fn cancel_watch(&self, node: &NodeId, id: WatchId) -> Result<(), Error> {
        self.node(node)?.cancel_watch(id).await
    }
    async fn changes(&self, node: &NodeId, id: WatchId) -> Result<Vec<Change>, Error> {
        let mut changes = self.node(node)?.changes(id).await?;
        if let Some(first) = changes.first_mut() {
            match self
                .corrupt_changes
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                1 => first.key.0[0] ^= 1,
                2 => first.subkey = u32::MAX,
                3 => first.seq = u32::MAX,
                4 => {
                    let duplicate = *first;
                    changes.push(duplicate);
                }
                _ => {}
            }
        }
        Ok(changes)
    }
}

//! Validating node storage and the backend port. There is no record expiry.
//! Remote transports are supplied by Mesh; this module opens no sockets.

use crate::crypto::Verifier;
use crate::{Descriptor, Error, RecordKey, SignedValue};
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

/// Result of offering a value to a backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SetOutcome {
    /// Stored (or already stored, identical).
    Accepted,
    /// The backend holds a newer or conflicting value for that subkey; here it is.
    Newer(SignedValue),
}

/// A subkey changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Change {
    /// The record.
    pub key: RecordKey,
    /// The subkey.
    pub subkey: u32,
    /// Its new sequence number.
    pub seq: u32,
}

/// Identifies one watch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WatchId(pub u64);

/// Storage and replication of records. Methods return [`Error::Unavailable`] when the
/// network (or the simulated network) is unreachable; the client then queues writes.
pub trait Backend {
    /// Publish a new record's descriptor.
    fn create(&self, descriptor: &Descriptor) -> impl Future<Output = Result<(), Error>>;
    /// Fetch a record's descriptor.
    fn descriptor(
        &self,
        key: &RecordKey,
    ) -> impl Future<Output = Result<Option<Descriptor>, Error>>;
    /// Fetch the current value of a subkey.
    fn get(
        &self,
        key: &RecordKey,
        subkey: u32,
    ) -> impl Future<Output = Result<Option<SignedValue>, Error>>;
    /// Offer a value for a subkey.
    fn set(
        &self,
        key: &RecordKey,
        subkey: u32,
        value: &SignedValue,
    ) -> impl Future<Output = Result<SetOutcome, Error>>;
    /// Check and repair replication of an existing signed value on open.
    /// Backends may inspect agreement first; the default republishes unchanged bytes.
    fn rehydrate(
        &self,
        key: &RecordKey,
        subkey: u32,
        value: &SignedValue,
    ) -> impl Future<Output = Result<SetOutcome, Error>> {
        self.set(key, subkey, value)
    }
    /// Start watching a record for changes.
    fn watch(&self, key: &RecordKey) -> impl Future<Output = Result<WatchId, Error>>;
    /// Stop a watch.
    fn cancel_watch(&self, id: WatchId) -> impl Future<Output = Result<(), Error>>;
    /// Take the changes observed by a watch since the last call.
    fn changes(&self, id: WatchId) -> impl Future<Output = Result<Vec<Change>, Error>>;
}

struct StoredRecord {
    descriptor: Descriptor,
    schema: crate::Schema,
    values: BTreeMap<u32, SignedValue>,
    touched: u64,
}

struct Watch {
    key: RecordKey,
    changes: BTreeMap<u32, Change>,
    expires: u64,
    remaining: u32,
}

struct LocalState {
    online: bool,
    records: BTreeMap<RecordKey, StoredRecord>,
    watches: BTreeMap<WatchId, Watch>,
    next_watch: u64,
    capacity: Capacity,
    clock: u64,
    access: u64,
    evictions: usize,
}

/// Veilid's remote record capacity defaults. Limits apply to others' records.
#[derive(Clone, Copy, Debug)]
pub struct Capacity {
    /// Maximum remote records.
    pub records: usize,
    /// Maximum stored logical bytes (descriptor, signatures, metadata and payload).
    pub bytes: usize,
}

impl Capacity {
    /// Native defaults from veilid_config.rs at dd8e2cdd.
    pub const NATIVE: Self = Self {
        records: 128,
        bytes: 256 * 1024 * 1024,
    };
    /// Browser defaults from the same source.
    pub const BROWSER: Self = Self {
        records: 64,
        bytes: 128 * 1024 * 1024,
    };
}

/// Maximum watch duration (ten minutes); records themselves never expire.
pub const MAX_WATCH_MS: u64 = 600_000;
/// Maximum public subscriptions to a record on one node.
pub const PUBLIC_WATCH_LIMIT: usize = 32;

impl StoredRecord {
    fn bytes(&self) -> usize {
        self.descriptor.schema.len()
            + 96
            + self
                .values
                .values()
                .map(|v| v.data.len() + 32 + 64 + 4 + v.nonce.map_or(0, |_| 24))
                .sum::<usize>()
    }
}

impl LocalState {
    fn touch(&mut self, key: &RecordKey) {
        self.access = self.access.saturating_add(1);
        if let Some(record) = self.records.get_mut(key) {
            record.touched = self.access;
        }
    }

    fn enforce_capacity(&mut self, protected: &RecordKey) {
        while self.records.len() > self.capacity.records
            || self
                .records
                .values()
                .map(StoredRecord::bytes)
                .sum::<usize>()
                > self.capacity.bytes
        {
            let oldest = self
                .records
                .iter()
                .filter(|(key, _)| *key != protected)
                .min_by_key(|(_, record)| record.touched)
                .map(|(key, _)| *key)
                // create and set admit only a protected record that fits by itself.
                // Exceeding capacity therefore always leaves another record to evict.
                .expect("admitted protected record fits capacity");
            self.records.remove(&oldest);
            self.watches.retain(|_, w| w.key != oldest);
            self.evictions += 1;
        }
    }
}

/// The in-memory filling. Clone it to give several clients the same "network".
pub struct LocalBackend<V: Verifier> {
    verifier: Arc<V>,
    state: Arc<Mutex<LocalState>>,
}

impl<V: Verifier> Clone for LocalBackend<V> {
    fn clone(&self) -> Self {
        Self {
            verifier: Arc::clone(&self.verifier),
            state: Arc::clone(&self.state),
        }
    }
}

impl<V: Verifier> LocalBackend<V> {
    /// An empty, online store that validates writes with `verifier`.
    pub fn new(verifier: V) -> Self {
        #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
        let capacity = Capacity::BROWSER;
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        let capacity = Capacity::NATIVE;
        Self::with_capacity(verifier, capacity)
    }

    /// A node store with explicit capacity (use BROWSER for browser nodes).
    pub fn with_capacity(verifier: V, capacity: Capacity) -> Self {
        Self {
            verifier: Arc::new(verifier),
            state: Arc::new(Mutex::new(LocalState {
                online: true,
                records: BTreeMap::new(),
                watches: BTreeMap::new(),
                next_watch: 1,
                capacity,
                clock: 0,
                access: 0,
                evictions: 0,
            })),
        }
    }

    /// Simulate losing or regaining the network: while offline every call fails with
    /// [`Error::Unavailable`].
    pub fn set_online(&self, online: bool) {
        self.lock_any().online = online;
    }

    /// Advance the node's monotonic clock. The network runtime calls this before
    /// requests and during maintenance. Only watch leases expire, never records.
    pub fn advance_to(&self, now_ms: u64) {
        let mut state = self.lock_any();
        state.clock = state.clock.max(now_ms);
        let clock = state.clock;
        state.watches.retain(|_, w| w.expires > clock);
    }

    /// Stored records, stored bytes, and cumulative LRU evictions.
    pub fn usage(&self) -> (usize, usize, usize) {
        let state = self.lock_any();
        (
            state.records.len(),
            state.records.values().map(StoredRecord::bytes).sum(),
            state.evictions,
        )
    }

    /// Create a bounded public watch. Its notifications are hints; clients validate reads.
    pub fn watch_for(
        &self,
        key: &RecordKey,
        duration_ms: u64,
        count: u32,
    ) -> Result<WatchId, Error> {
        let mut state = self.lock()?;
        if !state.records.contains_key(key) {
            return Err(Error::UnknownRecord);
        }
        if duration_ms == 0
            || count == 0
            || state.watches.values().filter(|w| w.key == *key).count() >= PUBLIC_WATCH_LIMIT
        {
            return Err(Error::Unavailable);
        }
        let id = WatchId(state.next_watch);
        state.next_watch = state.next_watch.checked_add(1).ok_or(Error::Unavailable)?;
        let expires = state.clock.saturating_add(duration_ms.min(MAX_WATCH_MS));
        state.watches.insert(
            id,
            Watch {
                key: *key,
                changes: BTreeMap::new(),
                expires,
                remaining: count,
            },
        );
        Ok(id)
    }

    /// Renew an existing public watch within the upstream lease limit.
    pub fn renew_watch(&self, id: WatchId, duration_ms: u64) -> Result<(), Error> {
        let mut state = self.lock()?;
        let expires = state.clock.saturating_add(duration_ms.min(MAX_WATCH_MS));
        if duration_ms == 0 {
            return Err(Error::UnknownWatch);
        }
        state
            .watches
            .get_mut(&id)
            .ok_or(Error::UnknownWatch)?
            .expires = expires;
        Ok(())
    }

    fn lock_any(&self) -> std::sync::MutexGuard<'_, LocalState> {
        // A panic while holding the lock cannot leave the maps inconsistent: every
        // mutation below is a single insert or push.
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, LocalState>, Error> {
        let state = self.lock_any();
        if !state.online {
            return Err(Error::Unavailable);
        }
        Ok(state)
    }
}

impl<V: Verifier> Backend for LocalBackend<V> {
    async fn create(&self, descriptor: &Descriptor) -> Result<(), Error> {
        let schema = descriptor.validate(self.verifier.as_ref())?;
        let key = descriptor.key();
        let mut state = self.lock()?;
        if let Some(existing) = state.records.get(&key) {
            // Upstream cmp_no_sig compares authenticated owner and schema.
            // A second valid signature does not define a different record.
            return if existing.descriptor.owner == descriptor.owner
                && existing.descriptor.schema == descriptor.schema
            {
                Ok(())
            } else {
                Err(Error::WrongRecord)
            };
        }
        if state.capacity.records == 0 || descriptor.schema.len() + 96 > state.capacity.bytes {
            return Err(Error::Unavailable);
        }
        state.records.insert(
            key,
            StoredRecord {
                descriptor: descriptor.clone(),
                schema,
                values: BTreeMap::new(),
                touched: 0,
            },
        );
        state.touch(&key);
        state.enforce_capacity(&key);
        Ok(())
    }

    async fn descriptor(&self, key: &RecordKey) -> Result<Option<Descriptor>, Error> {
        let mut state = self.lock()?;
        state.touch(key);
        Ok(state
            .records
            .get(key)
            .map(|record| record.descriptor.clone()))
    }

    async fn get(&self, key: &RecordKey, subkey: u32) -> Result<Option<SignedValue>, Error> {
        let mut state = self.lock()?;
        state.touch(key);
        let record = state.records.get(key).ok_or(Error::UnknownRecord)?;
        if subkey as usize >= record.schema.subkey_count() {
            return Err(Error::SubkeyOutOfRange);
        }
        Ok(record.values.get(&subkey).cloned())
    }

    async fn set(
        &self,
        key: &RecordKey,
        subkey: u32,
        value: &SignedValue,
    ) -> Result<SetOutcome, Error> {
        let mut state = self.lock()?;
        let record = state.records.get(key).ok_or(Error::UnknownRecord)?;
        value.validate(
            key,
            &record.descriptor.owner,
            &record.schema,
            subkey,
            self.verifier.as_ref(),
        )?;
        state.touch(key);
        let byte_limit = state.capacity.bytes;
        // The same lock has retained the validated record throughout this call.
        let record = state
            .records
            .get_mut(key)
            .expect("validated record retained");
        if let Some(current) = record.values.get(&subkey) {
            if current.same_value(value) {
                return Ok(SetOutcome::Accepted);
            }
            if current.seq >= value.seq {
                return Ok(SetOutcome::Newer(current.clone()));
            }
        }
        let old = record.values.insert(subkey, value.clone());
        if record.bytes() > byte_limit {
            if let Some(old) = old {
                record.values.insert(subkey, old);
            } else {
                record.values.remove(&subkey);
            }
            return Err(Error::Unavailable);
        }
        state.enforce_capacity(key);
        let change = Change {
            key: *key,
            subkey,
            seq: value.seq,
        };
        for watch in state.watches.values_mut() {
            // Zero-count watches are removed atomically by changes().
            if watch.key == *key {
                watch.changes.insert(subkey, change);
            }
        }
        Ok(SetOutcome::Accepted)
    }

    async fn watch(&self, key: &RecordKey) -> Result<WatchId, Error> {
        self.watch_for(key, MAX_WATCH_MS, u32::MAX)
    }

    async fn cancel_watch(&self, id: WatchId) -> Result<(), Error> {
        self.lock()?.watches.remove(&id);
        Ok(())
    }

    async fn changes(&self, id: WatchId) -> Result<Vec<Change>, Error> {
        let mut state = self.lock()?;
        let watch = state.watches.get_mut(&id).ok_or(Error::UnknownWatch)?;
        let changes: Vec<_> = std::mem::take(&mut watch.changes).into_values().collect();
        if !changes.is_empty() {
            watch.remaining -= 1;
        }
        if watch.remaining == 0 {
            state.watches.remove(&id);
        }
        Ok(changes)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "../tests/support/backend_state.rs"]
mod tests;

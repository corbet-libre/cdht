//! The backend port and its local filling.
//!
//! A backend stores descriptors and subkey values and notifies watchers. Fillings:
//!
//! - [`LocalBackend`] (here): in memory, for tests and debugging. It behaves like a DHT
//!   node: it validates every write against the owner-signed schema and the writer's
//!   signature, keeps the highest sequence number, and reports changes to watchers.
//!   Clones share one store, so several clients can act as the devices of one member.
//! - **Client DHT over Tor** (TODO, plugs into `cmsh`'s DHT capability): the community's
//!   member clients store encrypted records for each other, reachable via their onion
//!   services; the operator stores nothing.
//! - **Veilid DHT** (TODO, plugs into `cmsh`'s DHT capability, which reaches the one
//!   `veilid-core` in `cvln`): `create` maps to `create_dht_record` with an SMPL schema and
//!   the delegated owner key, `set` to `set_dht_value` with the delegated writer key,
//!   `watch` to `watch_dht_values`.
//!
//! `cdht` never reaches a network itself (no layer skipping): remote fillings are
//! `Backend` implementations provided through `cmsh`. The client ([`crate::Dht`])
//! validates everything a backend returns, so a remote filling needs no trust.

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
}

struct Watch {
    key: RecordKey,
    changes: Vec<Change>,
}

struct LocalState {
    online: bool,
    records: BTreeMap<RecordKey, StoredRecord>,
    watches: BTreeMap<WatchId, Watch>,
    next_watch: u64,
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
        Self {
            verifier: Arc::new(verifier),
            state: Arc::new(Mutex::new(LocalState {
                online: true,
                records: BTreeMap::new(),
                watches: BTreeMap::new(),
                next_watch: 0,
            })),
        }
    }

    /// Simulate losing or regaining the network: while offline every call fails with
    /// [`Error::Unavailable`].
    pub fn set_online(&self, online: bool) {
        self.lock_any().online = online;
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
            return if existing.descriptor == *descriptor {
                Ok(())
            } else {
                Err(Error::WrongRecord)
            };
        }
        state.records.insert(
            key,
            StoredRecord {
                descriptor: descriptor.clone(),
                schema,
                values: BTreeMap::new(),
            },
        );
        Ok(())
    }

    async fn descriptor(&self, key: &RecordKey) -> Result<Option<Descriptor>, Error> {
        Ok(self
            .lock()?
            .records
            .get(key)
            .map(|record| record.descriptor.clone()))
    }

    async fn get(&self, key: &RecordKey, subkey: u32) -> Result<Option<SignedValue>, Error> {
        let state = self.lock()?;
        let record = state.records.get(key).ok_or(Error::UnknownRecord)?;
        Ok(record.values.get(&subkey).cloned())
    }

    async fn set(
        &self,
        key: &RecordKey,
        subkey: u32,
        value: &SignedValue,
    ) -> Result<SetOutcome, Error> {
        let mut state = self.lock()?;
        let record = state.records.get_mut(key).ok_or(Error::UnknownRecord)?;
        value.validate(
            key,
            &record.descriptor.owner,
            &record.schema,
            subkey,
            self.verifier.as_ref(),
        )?;
        if let Some(current) = record.values.get(&subkey) {
            if current == value {
                return Ok(SetOutcome::Accepted);
            }
            if current.seq >= value.seq {
                return Ok(SetOutcome::Newer(current.clone()));
            }
        }
        record.values.insert(subkey, value.clone());
        let change = Change {
            key: *key,
            subkey,
            seq: value.seq,
        };
        for watch in state.watches.values_mut() {
            if watch.key == *key {
                watch.changes.push(change);
            }
        }
        Ok(SetOutcome::Accepted)
    }

    async fn watch(&self, key: &RecordKey) -> Result<WatchId, Error> {
        let mut state = self.lock()?;
        if !state.records.contains_key(key) {
            return Err(Error::UnknownRecord);
        }
        let id = WatchId(state.next_watch);
        state.next_watch += 1;
        state.watches.insert(
            id,
            Watch {
                key: *key,
                changes: Vec::new(),
            },
        );
        Ok(id)
    }

    async fn cancel_watch(&self, id: WatchId) -> Result<(), Error> {
        self.lock()?.watches.remove(&id);
        Ok(())
    }

    async fn changes(&self, id: WatchId) -> Result<Vec<Change>, Error> {
        let mut state = self.lock()?;
        let watch = state.watches.get_mut(&id).ok_or(Error::UnknownWatch)?;
        Ok(std::mem::take(&mut watch.changes))
    }
}

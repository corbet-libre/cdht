//! The client: open, read, write and watch records over any backend, with a local cache,
//! an offline write queue and epochs.
//!
//! The client trusts no backend: descriptors and values are validated on arrival. Writes
//! that cannot reach the backend are applied to the local cache and queued; [`Dht::flush`]
//! sends them later. The cache and queue are plain data ([`ClientState`]) so the caller
//! (the vault) can persist them in its encrypted store.
//!
//! **Epochs.** A schema never changes (the record key is derived from it), so a new
//! writer set means a new record. Subkey 0 of every record belongs to the owner and holds
//! the [`Header`]: the epoch number and links to the predecessor and successor records.
//! [`Dht::rotate`] creates the next epoch and links the old record to it; readers
//! follow the links with [`Dht::latest`].

use crate::backend::{Backend, Change, SetOutcome, WatchId};
use crate::crypto::{EncryptionKey, Signer, Verifier};
use crate::{Descriptor, Error, RecordKey, Schema, SignedValue};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// The owner subkey that holds the record header.
pub const HEADER_SUBKEY: u32 = 0;
/// Longest successor chain [`Dht::latest`] follows.
pub const MAX_EPOCH_HOPS: usize = 64;

/// Record header in owner subkey 0.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Header {
    /// Epoch number, starting at 0.
    pub epoch: u32,
    /// The record this one replaces.
    pub predecessor: Option<RecordKey>,
    /// The record that replaces this one, once rotated.
    pub successor: Option<RecordKey>,
}

/// What happened to a write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WriteOutcome {
    /// The backend accepted it.
    Written {
        /// Sequence number used.
        seq: u32,
    },
    /// The backend was unreachable: applied locally and queued for [`Dht::flush`].
    Queued {
        /// Sequence number used.
        seq: u32,
    },
    /// The backend holds a newer value; nothing was written. Read, merge, write again.
    Stale {
        /// The backend's sequence number.
        current_seq: u32,
    },
}

/// Result of [`Dht::flush`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FlushReport {
    /// Queued writes the backend accepted.
    pub written: usize,
    /// Queued writes dropped because the backend already held a newer value.
    pub stale: Vec<(RecordKey, u32)>,
    /// Writes still queued (the backend became unreachable again).
    pub remaining: usize,
}

/// A write waiting for the backend.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueuedWrite {
    /// Record.
    pub key: RecordKey,
    /// Subkey.
    pub subkey: u32,
    /// The signed value.
    pub value: SignedValue,
}

/// Persistent client state: opened descriptors, last known values, queued writes.
/// Contains only signed, possibly encrypted record data — never a secret key.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientState {
    descriptors: BTreeMap<RecordKey, Descriptor>,
    values: BTreeMap<RecordKey, BTreeMap<u32, SignedValue>>,
    queue: Vec<QueuedWrite>,
}

impl ClientState {
    /// Queued writes, oldest first.
    pub fn queue(&self) -> &[QueuedWrite] {
        &self.queue
    }
}

/// A `cdht` client over backend `B`, validating with `V`.
pub struct Dht<B: Backend, V: Verifier> {
    backend: B,
    verifier: V,
    state: ClientState,
}

impl<B: Backend, V: Verifier> Dht<B, V> {
    /// A client with empty state.
    pub fn new(backend: B, verifier: V) -> Self {
        Self::with_state(backend, verifier, ClientState::default())
    }

    /// A client resuming persisted state. Every stored descriptor and value is
    /// re-validated: persisted state is not trusted either.
    pub fn with_state(backend: B, verifier: V, state: ClientState) -> Self {
        let mut client = Self {
            backend,
            verifier,
            state: ClientState::default(),
        };
        for (key, descriptor) in state.descriptors {
            if let Ok(schema) = descriptor.validate_for(&key, &client.verifier) {
                if let Some(values) = state.values.get(&key) {
                    let valid: BTreeMap<u32, SignedValue> = values
                        .iter()
                        .filter(|(subkey, value)| {
                            value
                                .validate(
                                    &key,
                                    &descriptor.owner,
                                    &schema,
                                    **subkey,
                                    &client.verifier,
                                )
                                .is_ok()
                        })
                        .map(|(subkey, value)| (*subkey, value.clone()))
                        .collect();
                    client.state.values.insert(key, valid);
                }
                client.state.descriptors.insert(key, descriptor);
            }
        }
        client.state.queue = state
            .queue
            .into_iter()
            .filter(|write| {
                client.validated(&write.key).is_ok_and(|(owner, schema)| {
                    write
                        .value
                        .validate(&write.key, &owner, &schema, write.subkey, &client.verifier)
                        .is_ok()
                })
            })
            .collect();
        client
    }

    /// The state to persist.
    pub fn state(&self) -> &ClientState {
        &self.state
    }

    /// The backend.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    fn validated(&self, key: &RecordKey) -> Result<([u8; 32], Schema), Error> {
        let descriptor = self.state.descriptors.get(key).ok_or(Error::NotOpen)?;
        Ok((
            descriptor.owner,
            descriptor.validate_for(key, &self.verifier)?,
        ))
    }

    /// Create a record owned by `owner` with `schema`, and write its header (epoch 0).
    pub async fn create(
        &mut self,
        schema: &Schema,
        owner: &impl Signer,
        encryption: Option<&EncryptionKey>,
    ) -> Result<RecordKey, Error> {
        self.create_with_header(
            schema,
            owner,
            encryption,
            &Header {
                epoch: 0,
                predecessor: None,
                successor: None,
            },
        )
        .await
    }

    async fn create_with_header(
        &mut self,
        schema: &Schema,
        owner: &impl Signer,
        encryption: Option<&EncryptionKey>,
        header: &Header,
    ) -> Result<RecordKey, Error> {
        let descriptor = Descriptor::create(schema, owner)?;
        descriptor.validate(&self.verifier)?;
        let key = descriptor.key();
        self.backend.create(&descriptor).await?;
        self.state.descriptors.insert(key, descriptor);
        self.write_header(&key, header, owner, encryption).await?;
        Ok(key)
    }

    /// Open a record: fetch and validate its descriptor (or use the cached one when the
    /// backend is unreachable). Returns its schema.
    pub async fn open(&mut self, key: &RecordKey) -> Result<Schema, Error> {
        match self.backend.descriptor(key).await {
            Ok(Some(descriptor)) => {
                let schema = descriptor.validate_for(key, &self.verifier)?;
                self.state.descriptors.insert(*key, descriptor);
                Ok(schema)
            }
            Ok(None) => Err(Error::UnknownRecord),
            Err(Error::Unavailable) => Ok(self.validated(key)?.1),
            Err(error) => Err(error),
        }
    }

    /// The owner and schema of an opened record.
    pub fn schema(&self, key: &RecordKey) -> Result<([u8; 32], Schema), Error> {
        self.validated(key)
    }

    /// Read a subkey: the newer of the backend's and the cached value (the cache alone
    /// when the backend is unreachable), decrypted if `encryption` is given.
    pub async fn get(
        &mut self,
        key: &RecordKey,
        subkey: u32,
        encryption: Option<&EncryptionKey>,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
        match self.get_signed(key, subkey).await? {
            None => Ok(None),
            Some(value) => Ok(Some(match encryption {
                Some(encryption) => encryption.open(&key.0, subkey, &value.data)?,
                None => Zeroizing::new(value.data),
            })),
        }
    }

    /// Read a subkey's signed value (see [`Dht::get`]).
    pub async fn get_signed(
        &mut self,
        key: &RecordKey,
        subkey: u32,
    ) -> Result<Option<SignedValue>, Error> {
        let (owner, schema) = self.validated(key)?;
        if schema.writer_of(&owner, subkey).is_none() {
            return Err(Error::SubkeyOutOfRange);
        }
        match self.backend.get(key, subkey).await {
            Ok(Some(remote)) => {
                remote.validate(key, &owner, &schema, subkey, &self.verifier)?;
                self.remember(key, subkey, remote);
            }
            Ok(None) | Err(Error::Unavailable) => {}
            Err(error) => return Err(error),
        }
        Ok(self.cached(key, subkey).cloned())
    }

    fn cached(&self, key: &RecordKey, subkey: u32) -> Option<&SignedValue> {
        self.state
            .values
            .get(key)
            .and_then(|values| values.get(&subkey))
    }

    /// Keep `value` if it is newer than the cached one.
    fn remember(&mut self, key: &RecordKey, subkey: u32, value: SignedValue) {
        let values = self.state.values.entry(*key).or_default();
        match values.get(&subkey) {
            Some(current) if current.seq >= value.seq => {}
            _ => {
                values.insert(subkey, value);
            }
        }
    }

    /// Write `data` to `subkey` as `writer`: next sequence number after the newest
    /// known value, encrypted if `encryption` is given, signed, then sent (or queued).
    pub async fn set(
        &mut self,
        key: &RecordKey,
        subkey: u32,
        data: &[u8],
        writer: &impl Signer,
        encryption: Option<&EncryptionKey>,
    ) -> Result<WriteOutcome, Error> {
        let (owner, schema) = self.validated(key)?;
        let payload = match encryption {
            Some(encryption) => encryption.seal(&key.0, subkey, data)?,
            None => data.to_vec(),
        };
        schema.check_write(&owner, subkey, &writer.public_key(), payload.len())?;
        let seq = match self.cached(key, subkey) {
            Some(current) => current.seq.checked_add(1).ok_or(Error::SeqExhausted)?,
            None => 0,
        };
        let value = SignedValue::sign(key, subkey, seq, payload, writer)?;
        self.send(key, subkey, value).await
    }

    async fn send(
        &mut self,
        key: &RecordKey,
        subkey: u32,
        value: SignedValue,
    ) -> Result<WriteOutcome, Error> {
        let seq = value.seq;
        match self.backend.set(key, subkey, &value).await {
            Ok(SetOutcome::Accepted) => {
                self.remember(key, subkey, value);
                Ok(WriteOutcome::Written { seq })
            }
            Ok(SetOutcome::Newer(current)) => {
                let (owner, schema) = self.validated(key)?;
                current.validate(key, &owner, &schema, subkey, &self.verifier)?;
                let current_seq = current.seq;
                self.remember(key, subkey, current);
                Ok(WriteOutcome::Stale { current_seq })
            }
            Err(Error::Unavailable) => {
                // A newer queued write for the same subkey supersedes an older one.
                self.state
                    .queue
                    .retain(|queued| !(queued.key == *key && queued.subkey == subkey));
                self.state.queue.push(QueuedWrite {
                    key: *key,
                    subkey,
                    value: value.clone(),
                });
                self.remember(key, subkey, value);
                Ok(WriteOutcome::Queued { seq })
            }
            Err(error) => Err(error),
        }
    }

    /// Send queued writes in order until the backend is unreachable again.
    pub async fn flush(&mut self) -> Result<FlushReport, Error> {
        let mut report = FlushReport::default();
        let queue = std::mem::take(&mut self.state.queue);
        let mut pending = queue.into_iter();
        while let Some(write) = pending.next() {
            match self
                .backend
                .set(&write.key, write.subkey, &write.value)
                .await
            {
                Ok(SetOutcome::Accepted) => report.written += 1,
                Ok(SetOutcome::Newer(current)) => {
                    let valid = self.validated(&write.key).is_ok_and(|(owner, schema)| {
                        current
                            .validate(&write.key, &owner, &schema, write.subkey, &self.verifier)
                            .is_ok()
                    });
                    if valid {
                        // Replace the optimistic local value with the backend's.
                        if let Some(values) = self.state.values.get_mut(&write.key) {
                            values.insert(write.subkey, current);
                        }
                    }
                    report.stale.push((write.key, write.subkey));
                }
                Err(Error::Unavailable) => {
                    self.state.queue.push(write);
                    break;
                }
                Err(error) => {
                    self.state.queue.push(write);
                    self.state.queue.extend(pending);
                    return Err(error);
                }
            }
        }
        self.state.queue.extend(pending);
        report.remaining = self.state.queue.len();
        Ok(report)
    }

    /// Start watching a record.
    pub async fn watch(&mut self, key: &RecordKey) -> Result<WatchId, Error> {
        self.validated(key)?;
        self.backend.watch(key).await
    }

    /// Stop watching.
    pub async fn cancel_watch(&mut self, id: WatchId) -> Result<(), Error> {
        self.backend.cancel_watch(id).await
    }

    /// Changes since the last call. Hints only: read the subkeys to get validated data.
    pub async fn changes(&mut self, id: WatchId) -> Result<Vec<Change>, Error> {
        self.backend.changes(id).await
    }

    /// Read a record's header.
    pub async fn header(
        &mut self,
        key: &RecordKey,
        encryption: Option<&EncryptionKey>,
    ) -> Result<Header, Error> {
        let data = self
            .get(key, HEADER_SUBKEY, encryption)
            .await?
            .ok_or(Error::MissingHeader)?;
        serde_json::from_slice(&data).map_err(|_| Error::Encoding)
    }

    async fn write_header(
        &mut self,
        key: &RecordKey,
        header: &Header,
        owner: &impl Signer,
        encryption: Option<&EncryptionKey>,
    ) -> Result<(), Error> {
        let bytes = serde_json::to_vec(header).map_err(|_| Error::Encoding)?;
        match self
            .set(key, HEADER_SUBKEY, &bytes, owner, encryption)
            .await?
        {
            WriteOutcome::Written { .. } | WriteOutcome::Queued { .. } => Ok(()),
            WriteOutcome::Stale { .. } => Err(Error::Conflict),
        }
    }

    /// Start the next epoch: a new record with `schema` owned by `new_owner` (and
    /// encrypted with `new_encryption`), whose header points back to `old`; then the old
    /// record's header, signed by `old_owner`, points forward to it. Use it when the
    /// writer set changes, for example when a device is removed; give the new record a
    /// new encryption key so removed writers cannot read it.
    pub async fn rotate(
        &mut self,
        old: &RecordKey,
        old_owner: &impl Signer,
        old_encryption: Option<&EncryptionKey>,
        schema: &Schema,
        new_owner: &impl Signer,
        new_encryption: Option<&EncryptionKey>,
    ) -> Result<RecordKey, Error> {
        let (owner, _) = self.validated(old)?;
        if owner != old_owner.public_key() {
            return Err(Error::WrongWriter);
        }
        let old_header = self.header(old, old_encryption).await?;
        if old_header.successor.is_some() {
            return Err(Error::Conflict);
        }
        let epoch = old_header.epoch.checked_add(1).ok_or(Error::SeqExhausted)?;
        let new = self
            .create_with_header(
                schema,
                new_owner,
                new_encryption,
                &Header {
                    epoch,
                    predecessor: Some(*old),
                    successor: None,
                },
            )
            .await?;
        self.write_header(
            old,
            &Header {
                successor: Some(new),
                ..old_header
            },
            old_owner,
            old_encryption,
        )
        .await?;
        Ok(new)
    }

    /// Follow successor links from `key` to the newest epoch. `encryption` returns the key
    /// for each record (records of different epochs usually have different keys);
    /// following stops before the first successor it cannot read.
    pub async fn latest(
        &mut self,
        key: &RecordKey,
        encryption: impl Fn(&RecordKey) -> Option<EncryptionKey>,
    ) -> Result<RecordKey, Error> {
        let mut current = *key;
        for _ in 0..MAX_EPOCH_HOPS {
            let header = self.header(&current, encryption(&current).as_ref()).await?;
            let Some(next) = header.successor else {
                return Ok(current);
            };
            self.open(&next).await?;
            let next_header = match self.header(&next, encryption(&next).as_ref()).await {
                Ok(next_header) => next_header,
                // A successor this reader cannot read (no or wrong key) ends the walk.
                Err(Error::Decrypt | Error::Encoding) => return Ok(current),
                Err(error) => return Err(error),
            };
            if next_header.predecessor != Some(current) || next_header.epoch <= header.epoch {
                return Err(Error::BrokenEpochChain);
            }
            current = next;
        }
        Err(Error::BrokenEpochChain)
    }
}

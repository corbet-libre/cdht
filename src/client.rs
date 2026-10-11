//! The client: open, read, write and watch records over any backend, with a local cache,
//! an offline write queue.
//!
//! The client trusts no backend: descriptors and values are validated on arrival. Writes
//! that cannot reach the backend are applied to the local cache and queued; [`Dht::flush`]
//! sends them later. The cache and queue are plain data ([`ClientState`]) so the caller
//! (the vault) can persist them in its encrypted store.
//!
use crate::backend::{Backend, Change, SetOutcome, WatchId};
use crate::crypto::{RecordCipher, Signer, Verifier};
use crate::{Descriptor, Error, RecordKey, Schema, SignedValue};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

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

/// Result of preparing an exact-sequence publication in the original client.
/// Neither variant attests durable storage or network replication.
pub enum QueuedPublication {
    /// The original signed value is staged in [`ClientState`]. Persist that state
    /// through the owner transaction before allowing [`Dht::flush`].
    Queued,
    /// An already authenticated local observation conflicts with the requested
    /// generation. Its original signed value is returned unchanged; nothing was queued.
    Conflict(SignedValue),
}
impl std::fmt::Debug for QueuedPublication {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Queued => "QueuedPublication::Queued",
            Self::Conflict(_) => "QueuedPublication::Conflict([redacted])",
        })
    }
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
        for write in state.queue {
            if client.validated(&write.key).is_ok_and(|(owner, schema)| {
                write
                    .value
                    .validate(&write.key, &owner, &schema, write.subkey, &client.verifier)
                    .is_ok()
            }) {
                // A cached observation is independent of the original signed
                // publication obligation. Keep both: flush must reconcile the
                // original bytes against a genuine backend outcome, including
                // a higher or equal-conflicting remote value.
                client.remember(&write.key, write.subkey, write.value.clone());
                client
                    .state
                    .queue
                    .retain(|q| !(q.key == write.key && q.subkey == write.subkey));
                client.state.queue.push(write);
            }
        }
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

    /// Sign and cache a descriptor without network I/O. Call inside the key owner's
    /// synchronous authorization callback, persist [`Self::state`], then flush queued values.
    /// This is local preparation, never evidence that peers retained the record.
    pub fn queue_create(
        &mut self,
        schema: &Schema,
        owner: &impl Signer,
    ) -> Result<RecordKey, Error> {
        let descriptor = Descriptor::create(schema, owner)?;
        descriptor.validate(&self.verifier)?;
        let key = descriptor.key();
        self.state.descriptors.insert(key, descriptor);
        Ok(key)
    }

    /// Create an ordinary Veilid record with no reserved or pre-populated subkeys.
    /// The signed descriptor is retained locally when the network is unavailable.
    pub async fn create(
        &mut self,
        schema: &Schema,
        owner: &impl Signer,
    ) -> Result<RecordKey, Error> {
        let descriptor = Descriptor::create(schema, owner)?;
        descriptor.validate(&self.verifier)?;
        let key = descriptor.key();
        match self.backend.create(&descriptor).await {
            Ok(()) | Err(Error::Unavailable) => {}
            Err(error) => return Err(error),
        }
        self.state.descriptors.insert(key, descriptor);
        Ok(key)
    }

    /// Open a record: fetch and validate its descriptor (or use the cached one when the
    /// backend is unreachable). Returns its schema.
    pub async fn open(&mut self, key: &RecordKey) -> Result<Schema, Error> {
        match self.backend.descriptor(key).await {
            Ok(Some(descriptor)) => {
                descriptor.validate_for(key, &self.verifier)?;
                self.state.descriptors.insert(*key, descriptor);
            }
            Ok(None) | Err(Error::UnknownRecord | Error::Unavailable) => {
                self.validated(key).map_err(|_| Error::UnknownRecord)?;
            }
            Err(error) => return Err(error),
        }
        // Republish cached signed values verbatim, without private signing keys.
        // The backend performs replication and returns any newer network value.
        let descriptor = self
            .state
            .descriptors
            .get(key)
            .ok_or(Error::NotOpen)?
            .clone();
        match self.backend.create(&descriptor).await {
            Ok(()) | Err(Error::Unavailable) => {}
            Err(error) => return Err(error),
        }
        let values = self.state.values.get(key).cloned().unwrap_or_default();
        for (subkey, value) in values {
            let result = self.backend.rehydrate(key, subkey, &value).await;
            // A failed inspection is retried on the next open, not converted to a
            // blind write by flush. Existing explicitly queued writes remain queued.
            if matches!(result, Err(Error::Unavailable | Error::UnknownRecord)) {
                continue;
            }
            self.accept_result(key, subkey, value, result)?;
        }
        Ok(self.validated(key)?.1)
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
        encryption: Option<&dyn RecordCipher>,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
        match self.get_signed(key, subkey).await? {
            None => Ok(None),
            Some(value) => Ok(Some(self.open_value(key, subkey, &value, encryption)?)),
        }
    }

    /// Validate and open original signed bytes synchronously under a scoped key
    /// capability. Fetch with [`Self::get_signed`] first, then call this inside the
    /// key owner's callback; neither signer nor cipher crosses a network await.
    pub fn open_value(
        &self,
        key: &RecordKey,
        subkey: u32,
        value: &SignedValue,
        encryption: Option<&dyn RecordCipher>,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let (owner, schema) = self.validated(key)?;
        value.validate(key, &owner, &schema, subkey, &self.verifier)?;
        Self::decrypt(value, encryption)
    }

    fn decrypt(
        value: &SignedValue,
        encryption: Option<&dyn RecordCipher>,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        match (encryption, value.nonce) {
            (Some(key), Some(nonce)) => key.crypt(&nonce, &value.data),
            (None, None) => Ok(Zeroizing::new(value.data.clone())),
            _ => Err(Error::Decrypt),
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
            Ok(None) => {}
            Err(Error::Unavailable | Error::UnknownRecord) => {
                if self.cached(key, subkey).is_none() {
                    return Err(Error::Unavailable);
                }
            }
            Err(error) => return Err(error),
        }
        Ok(self.cached(key, subkey).cloned())
    }

    /// Read this subkey from the original backend without an offline cache
    /// fallback. A returned value is authenticated and never below the client's
    /// observed sequence floor. A missing response after a prior value is
    /// unavailable, not evidence of deletion. This is an observation from the
    /// backend, not a claim of global currentness or authoritative absence.
    pub async fn get_signed_fresh(
        &mut self,
        key: &RecordKey,
        subkey: u32,
    ) -> Result<Option<SignedValue>, Error> {
        let (owner, schema) = self.validated(key)?;
        if schema.writer_of(&owner, subkey).is_none() {
            return Err(Error::SubkeyOutOfRange);
        }
        let remote = match self.backend.get(key, subkey).await {
            Err(Error::Unavailable | Error::UnknownRecord) => return Err(Error::Unavailable),
            result => result?,
        };
        match remote {
            Some(value) => {
                self.observe_original(key, subkey, &value)?;
                Ok(Some(value))
            }
            None if self.cached(key, subkey).is_some() => Err(Error::Unavailable),
            None => Ok(None),
        }
    }

    /// Retain an original signed observation without calling the network or
    /// changing any pending publication. This applies the same validation and
    /// observed sequence floor as [`Self::get_signed_fresh`]. A valid signature
    /// is not proof of a recent read, holder agreement or current authority.
    /// The enclosing owner must retain its actual read report independently.
    ///
    /// An equal-sequence different observation remains distinct from a queued
    /// obligation. Invalid or lower-sequence input leaves all state unchanged.
    pub fn observe_original(
        &mut self,
        key: &RecordKey,
        subkey: u32,
        value: &SignedValue,
    ) -> Result<(), Error> {
        let (owner, schema) = self.validated(key)?;
        value.validate(key, &owner, &schema, subkey, &self.verifier)?;
        if self
            .cached(key, subkey)
            .is_some_and(|prior| prior.seq > value.seq)
        {
            return Err(Error::Conflict);
        }
        self.state
            .values
            .entry(*key)
            .or_default()
            .insert(subkey, value.clone());
        Ok(())
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
        encryption: Option<&dyn RecordCipher>,
    ) -> Result<WriteOutcome, Error> {
        let value = self.signed_write(key, subkey, data, writer, encryption)?;
        let seq = value.seq;
        let outcome = self.send(key, subkey, value).await?;
        // Upstream compares decrypted ValueData with the requested value. A fresh
        // nonce for unchanged plaintext does not turn an idempotent set into a conflict.
        if matches!(outcome, WriteOutcome::Stale { current_seq } if current_seq == seq) {
            // accept_result validated the unique schema writer and retained this
            // exact stale value before returning. No second writer decision exists.
            let current = self.cached(key, subkey).expect("stale value retained");
            if Self::decrypt(current, encryption)?.as_slice() == data {
                return Ok(WriteOutcome::Written { seq });
            }
        }
        Ok(outcome)
    }

    /// Sign and queue one value synchronously, without carrying a signer across
    /// an await. Persist the signed state through the vault's protected transaction
    /// before calling [`Self::flush`]. The result is a local sequence, not a receipt.
    pub fn queue_set(
        &mut self,
        key: &RecordKey,
        subkey: u32,
        data: &[u8],
        writer: &impl Signer,
        encryption: Option<&dyn RecordCipher>,
    ) -> Result<u32, Error> {
        let value = self.signed_write(key, subkey, data, writer, encryption)?;
        let (owner, schema) = self.validated(key)?;
        value.validate(key, &owner, &schema, subkey, &self.verifier)?;
        let seq = value.seq;
        self.queue_write(key, subkey, &value);
        Ok(seq)
    }

    /// Stage already signed original descriptor/value bytes without a signer,
    /// cipher or network I/O. The enclosing owner supplies and authorizes this
    /// exact publication; signatures prove the record writer, not current member
    /// authority. Persist the complete original [`ClientState`] before flush.
    ///
    /// All cryptographic and schema checks precede mutation. Both the cached
    /// observation and an outstanding same-slot obligation fence the generation.
    /// Equal-sequence cached byte/signature differences are conflicts, including
    /// fresh encryption of the same plaintext. An outstanding obligation cannot
    /// be superseded by any nonidentical signed value. Existing descriptors must be exact.
    /// Refusal leaves every original descriptor, value and queue entry unchanged.
    pub fn queue_original(
        &mut self,
        descriptor: &Descriptor,
        subkey: u32,
        value: &SignedValue,
    ) -> Result<QueuedPublication, Error> {
        let schema = descriptor.validate(&self.verifier)?;
        let key = descriptor.key();
        value.validate(&key, &descriptor.owner, &schema, subkey, &self.verifier)?;
        if self
            .state
            .descriptors
            .get(&key)
            .is_some_and(|current| current != descriptor)
        {
            return Err(Error::Conflict);
        }
        let conflicts = |current: &SignedValue| {
            current.seq > value.seq
                || (current.seq == value.seq
                    && (!current.same_value(value) || current.signature != value.signature))
        };
        if let Some(current) = self.cached(&key, subkey)
            && conflicts(current)
        {
            return Ok(QueuedPublication::Conflict(current.clone()));
        }
        if let Some(pending) = self
            .state
            .queue
            .iter()
            .find(|queued| queued.key == key && queued.subkey == subkey)
        {
            if !pending.value.same_value(value) || pending.value.signature != value.signature {
                return Ok(QueuedPublication::Conflict(pending.value.clone()));
            }
            // Exact idempotence preserves ordering and original blob bookkeeping
            // as well as every signed byte; do not remove/reinsert this obligation.
            return Ok(QueuedPublication::Queued);
        }
        self.state.descriptors.insert(key, descriptor.clone());
        self.queue_write(&key, subkey, value);
        Ok(QueuedPublication::Queued)
    }

    /// Prepare an exact semantic sequence for a compound checkpoint. The
    /// caller supplies a generation, never a sequence inferred independently per
    /// part. An equal-sequence identical plaintext reuses the original signed
    /// bytes; a newer or different equal-sequence value is a conflict.
    ///
    /// This synchronous capability borrow performs no network I/O. Persist the
    /// complete signed [`ClientState`] through the owner transaction before
    /// flushing; a queued value is not durable merely because this call returned.
    pub fn queue_republish(
        &mut self,
        key: &RecordKey,
        subkey: u32,
        seq: u32,
        data: &[u8],
        writer: &impl Signer,
        encryption: Option<&dyn RecordCipher>,
    ) -> Result<QueuedPublication, Error> {
        let (owner, schema) = self.validated(key)?;
        schema.check_write(&owner, subkey, &writer.public_key(), data.len())?;
        if seq > crate::MAX_SEQ {
            return Err(Error::SeqExhausted);
        }
        if let Some(current) = self.cached(key, subkey) {
            if current.seq > seq
                || (current.seq == seq && Self::decrypt(current, encryption)?.as_slice() != data)
            {
                return Ok(QueuedPublication::Conflict(current.clone()));
            }
            if current.seq == seq {
                let original = current.clone();
                self.queue_write(key, subkey, &original);
                return Ok(QueuedPublication::Queued);
            }
        }
        let value = Self::signed_sequence(&owner, subkey, seq, data, writer, encryption)?;
        value.validate(key, &owner, &schema, subkey, &self.verifier)?;
        self.queue_write(key, subkey, &value);
        Ok(QueuedPublication::Queued)
    }

    fn signed_write(
        &self,
        key: &RecordKey,
        subkey: u32,
        data: &[u8],
        writer: &impl Signer,
        encryption: Option<&dyn RecordCipher>,
    ) -> Result<SignedValue, Error> {
        let (owner, schema) = self.validated(key)?;
        schema.check_write(&owner, subkey, &writer.public_key(), data.len())?;
        let seq = match self.cached(key, subkey) {
            // Cached values were validated on arrival, and check_write above
            // bound this writer to the same unique schema slot.
            Some(current) if Self::decrypt(current, encryption)?.as_slice() == data => {
                return Ok(current.clone());
            }
            Some(current) => current
                .seq
                .checked_add(1)
                .filter(|seq| *seq <= crate::MAX_SEQ)
                .ok_or(Error::SeqExhausted)?,
            None => 0,
        };
        Self::signed_sequence(&owner, subkey, seq, data, writer, encryption)
    }

    fn signed_sequence(
        owner: &[u8; 32],
        subkey: u32,
        seq: u32,
        data: &[u8],
        writer: &impl Signer,
        encryption: Option<&dyn RecordCipher>,
    ) -> Result<SignedValue, Error> {
        let (payload, nonce) = match encryption {
            Some(encryption) => {
                let mut nonce = [0; 24];
                getrandom::fill(&mut nonce).map_err(|_| Error::Randomness)?;
                (encryption.crypt(&nonce, data)?.to_vec(), Some(nonce))
            }
            None => (data.to_vec(), None),
        };
        SignedValue::sign_with_nonce(owner, subkey, seq, payload, nonce, writer)
    }

    async fn send(
        &mut self,
        key: &RecordKey,
        subkey: u32,
        value: SignedValue,
    ) -> Result<WriteOutcome, Error> {
        let (owner, schema) = self.validated(key)?;
        value.validate(key, &owner, &schema, subkey, &self.verifier)?;
        // Stage before the first await: cancellation after a partial network write
        // must leave both the signed value and its retry obligation in the snapshot.
        self.queue_write(key, subkey, &value);
        let result = self.backend.set(key, subkey, &value).await;
        self.accept_result(key, subkey, value, result)
    }

    fn queue_write(&mut self, key: &RecordKey, subkey: u32, value: &SignedValue) {
        // Retrying an identical signed obligation must preserve its original
        // position (including the retained upstream blob). Cancellation and an
        // unknown reply cannot move it behind later dependent publications.
        if self
            .state
            .queue
            .iter()
            .any(|queued| queued.key == *key && queued.subkey == subkey && &queued.value == value)
        {
            self.remember(key, subkey, value.clone());
            return;
        }
        self.state
            .queue
            .retain(|q| !(q.key == *key && q.subkey == subkey));
        self.state.queue.push(QueuedWrite {
            key: *key,
            subkey,
            value: value.clone(),
        });
        self.remember(key, subkey, value.clone());
    }

    fn accept_result(
        &mut self,
        key: &RecordKey,
        subkey: u32,
        value: SignedValue,
        result: Result<SetOutcome, Error>,
    ) -> Result<WriteOutcome, Error> {
        let seq = value.seq;
        match result {
            Ok(SetOutcome::Accepted) => {
                self.state
                    .queue
                    .retain(|q| !(q.key == *key && q.subkey == subkey));
                self.remember(key, subkey, value);
                Ok(WriteOutcome::Written { seq })
            }
            Ok(SetOutcome::Newer(current)) => {
                let (owner, schema) = self.validated(key)?;
                current.validate(key, &owner, &schema, subkey, &self.verifier)?;
                if current.seq < value.seq {
                    return Err(Error::Conflict);
                }
                let current_seq = current.seq;
                self.state
                    .queue
                    .retain(|q| !(q.key == *key && q.subkey == subkey));
                self.state
                    .values
                    .entry(*key)
                    .or_default()
                    .insert(subkey, current);
                Ok(WriteOutcome::Stale { current_seq })
            }
            Err(Error::Unavailable | Error::UnknownRecord) => {
                self.queue_write(key, subkey, &value);
                Ok(WriteOutcome::Queued { seq })
            }
            Err(error) => Err(error),
        }
    }

    /// Send queued writes in order until the backend is unreachable again.
    pub async fn flush(&mut self) -> Result<FlushReport, Error> {
        self.flush_bounded(usize::MAX).await
    }

    /// Attempt at most the oldest queued write. Return before awaiting another
    /// output so the owning durable transaction can retain the exact validated
    /// outcome and sequence floors between writes. This is a transport report,
    /// never a persistence receipt or application acknowledgment.
    pub async fn flush_one(&mut self) -> Result<FlushReport, Error> {
        self.flush_bounded(1).await
    }

    async fn flush_bounded(&mut self, maximum: usize) -> Result<FlushReport, Error> {
        let mut report = FlushReport::default();
        // Leave each queued write in place until its validated acknowledgment arrives.
        while let Some(write) = self.state.queue.first().cloned() {
            if report.written + report.stale.len() >= maximum {
                break;
            }
            let descriptor = self
                .state
                .descriptors
                .get(&write.key)
                .ok_or(Error::NotOpen)?
                .clone();
            match self.backend.create(&descriptor).await {
                Ok(()) => {}
                Err(Error::Unavailable) => break,
                Err(error) => return Err(error),
            }
            match self.send(&write.key, write.subkey, write.value).await? {
                WriteOutcome::Written { .. } => report.written += 1,
                WriteOutcome::Stale { .. } => report.stale.push((write.key, write.subkey)),
                WriteOutcome::Queued { .. } => break,
            }
        }
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
}

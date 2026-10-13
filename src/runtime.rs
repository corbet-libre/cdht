//! Whole-record runtime boundary for engines that authenticate and decrypt inside
//! maintained native code. The raw signed-byte [`crate::Backend`] remains the Tor
//! storage/network boundary; it must never be populated with fabricated signatures.
//!
//! Implementations of [`Backend`] are trusted cryptographic adapters, like the
//! injected Verifier and RecordCipher ports. They must authenticate remote records
//! inside the actual engine before producing values. This is not a wire protocol
//! and must not be implemented by deserializing an unsigned network response.
use crate::{
    Error, MAX_SEQ, MAX_SUBKEY_SIZE, RecordCipher, RecordKey, Schema, SignedValue, Verifier,
};
use std::future::Future;
use zeroize::Zeroizing;

/// Public identity authenticated by the record runtime. Contains no read secret.
#[derive(Clone, PartialEq, Eq)]
pub struct Identity {
    /// Opaque locator; includes no encryption capability.
    pub key: RecordKey,
    /// Original owner public key.
    pub owner: [u8; 32],
    /// Original compiled schema, validated before this handle can be used.
    pub schema: Schema,
    /// Scoped writer supplied to the runtime, or None for a read-only capability.
    pub writer: Option<[u8; 32]>,
}

/// Decrypted data whose signature was checked by the underlying engine.
/// Debug deliberately excludes all fields.
pub struct Value {
    /// Sequence authenticated by the engine.
    pub seq: u32,
    /// Writer authenticated by the engine.
    pub writer: [u8; 32],
    /// Original decrypted content; cleared when released.
    pub data: Zeroizing<Vec<u8>>,
}
impl std::fmt::Debug for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Value([redacted])")
    }
}

/// A native publication distinguishes local persistence from network replication.
pub enum Publication {
    /// Persisted in the runtime's own offline queue.
    Queued,
    /// The runtime completed its native record flush.
    Replicated,
    /// A newer or equal-sequence conflicting value won. No retry is implied.
    Conflict(Value),
}

/// Change hints require a subsequent authenticated read.
pub struct Changes {
    /// Inclusive changed subkey ranges.
    pub ranges: Vec<(u32, u32)>,
    /// A lost watch, lag or shutdown requires a full refresh.
    pub lost: bool,
}

/// A complete authenticated record engine, supplied through Mesh. It owns its
/// crypto, queue, watches and replica algorithm; Records does not duplicate them.
/// Credentials are narrow owner/writer/read capabilities held below this port.
pub trait Backend {
    /// Identity authenticated when opening this particular record capability.
    fn identity(&self) -> Identity;
    /// Authenticated plaintext. Unavailable replicas must return an error, not None.
    fn get(&self, subkey: u32, refresh: bool)
    -> impl Future<Output = Result<Option<Value>, Error>>;
    /// Republish this capability's own writer with the requested exact semantic
    /// sequence and plaintext. Fresh nonce/ciphertext/signature are expected.
    fn republish(
        &self,
        subkey: u32,
        seq: u32,
        data: &[u8],
    ) -> impl Future<Output = Result<Publication, Error>>;
    /// Reconcile the engine's durable queue; no application delivery ACK.
    fn flush(&self) -> impl Future<Output = Result<bool, Error>>;
    /// Request one whole-record watch; true is desired state, not remote acceptance.
    fn watch(&self) -> impl Future<Output = Result<bool, Error>>;
    /// Cancel the watch. False means no watch remains desired.
    fn cancel_watch(&self) -> impl Future<Output = Result<bool, Error>>;
    /// Bounded currently buffered hints, with explicit gap detection.
    fn changes(&self) -> Result<Changes, Error>;
}

/// Records' semantic interface over a qualified whole-record runtime. It retains
/// public identity only, never another replica store, secret or offline queue.
pub struct Record<B: Backend> {
    backend: B,
    identity: Identity,
}
impl<B: Backend> Record<B> {
    /// Bind the authenticated engine identity to its canonical schema-derived key.
    pub fn new(backend: B) -> Result<Self, Error> {
        let identity = backend.identity();
        let schema = Schema::parse(&identity.schema.compile())?;
        if RecordKey::derive(&identity.owner, &schema.compile()) != identity.key {
            return Err(Error::WrongRecord);
        }
        Ok(Self { backend, identity })
    }
    /// Public identity, never the full read key.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
    /// Consume this facade and return its runtime for explicit close.
    pub fn into_backend(self) -> B {
        self.backend
    }

    fn subkey(&self, subkey: u32) -> Result<(), Error> {
        if subkey as usize >= self.identity.schema.subkey_count() {
            return Err(Error::SubkeyOutOfRange);
        }
        Ok(())
    }
    fn validate(&self, subkey: u32, value: &Value) -> Result<(), Error> {
        self.subkey(subkey)?;
        if value.seq > MAX_SEQ {
            return Err(Error::SeqExhausted);
        }
        if value.data.len() > MAX_SUBKEY_SIZE {
            return Err(Error::ValueTooLarge);
        }
        if self.identity.schema.writer_of(&self.identity.owner, subkey) != Some(value.writer) {
            return Err(Error::WrongWriter);
        }
        Ok(())
    }
    /// Read authenticated content and validate schema, writer, sequence and bounds.
    pub async fn get(&self, subkey: u32, refresh: bool) -> Result<Option<Value>, Error> {
        self.subkey(subkey)?;
        let value = self.backend.get(subkey, refresh).await?;
        if let Some(value) = value.as_ref() {
            self.validate(subkey, value)?;
        }
        Ok(value)
    }
    /// Republish the capability's own value, preserving semantic identity.
    pub async fn republish(&self, subkey: u32, value: &Value) -> Result<Publication, Error> {
        self.validate(subkey, value)?;
        if self.identity.writer != Some(value.writer) {
            return Err(Error::WrongWriter);
        }
        let outcome = self
            .backend
            .republish(subkey, value.seq, &value.data)
            .await?;
        if let Publication::Conflict(current) = &outcome {
            self.validate(subkey, current)?;
        }
        Ok(outcome)
    }
    /// Prepare a switch from a Tor-held signed value synchronously inside the key
    /// owner's callback. Verify original bytes before decrypting, then pass the
    /// owned result to republish after the borrowed cipher capability is released.
    pub fn prepare_republish(
        &self,
        subkey: u32,
        value: &SignedValue,
        verifier: &impl Verifier,
        cipher: Option<&dyn RecordCipher>,
    ) -> Result<Value, Error> {
        value.validate(
            &self.identity.key,
            &self.identity.owner,
            &self.identity.schema,
            subkey,
            verifier,
        )?;
        if self.identity.writer != Some(value.writer) {
            return Err(Error::WrongWriter);
        }
        let data = match (cipher, value.nonce) {
            (Some(cipher), Some(nonce)) => cipher.crypt(&nonce, &value.data)?,
            (None, None) => Zeroizing::new(value.data.clone()),
            _ => return Err(Error::Decrypt),
        };
        Ok(Value {
            seq: value.seq,
            writer: value.writer,
            data,
        })
    }
    /// Let the maintained runtime reconcile its own queue.
    pub async fn flush(&self) -> Result<bool, Error> {
        self.backend.flush().await
    }
    /// Request a native watch; does not fabricate remote acceptance.
    pub async fn watch(&self) -> Result<bool, Error> {
        self.backend.watch().await
    }
    /// Cancel through the native runtime.
    pub async fn cancel_watch(&self) -> Result<bool, Error> {
        self.backend.cancel_watch().await
    }
    /// Validate bounded subkey hints. A gap asks the owner to refresh the record.
    pub fn changes(&self) -> Result<Changes, Error> {
        let changes = self.backend.changes()?;
        if changes.ranges.len() > self.identity.schema.subkey_count() {
            return Err(Error::Encoding);
        }
        for &(start, end) in &changes.ranges {
            if start > end {
                return Err(Error::Encoding);
            }
            self.subkey(end)?;
        }
        Ok(changes)
    }
}

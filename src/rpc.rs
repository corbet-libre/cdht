// SPDX-License-Identifier: MPL-2.0
// Portions of Veilid, Copyright Veilid contributors.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. https://mozilla.org/MPL/2.0/
// Upstream: veilid/veilid dd8e2cdd72b5bf817172ac31c20872b168c5c8fc,
// rpc_processor/coders/{signed_value_data,signed_value_descriptor,operations/signed_operation}.rs.
//! Bounded original Veilid record, application and signed-operation bytes. No network or keys.
use crate::crypto::{PublicKey, Signature};
use crate::{Descriptor, Error, SignedValue, Signer, Verifier, veilid_capnp as wire};
use capnp::message::{Builder, HeapAllocator, Reader, ReaderOptions, ReaderSegments};
use capnp::serialize::OwnedSegments;
mod answer;
mod application;
mod changed;
pub mod envelope;
pub mod inspect;
pub mod peers;
mod watch;
pub use answer::{Answer, Response, UnverifiedPeerInfoBytes};
pub use application::{Application, OperationKind, application, operation_kind};
pub use changed::{ChangeHint, Statement, value_changed};
pub use watch::SubkeyRanges;
#[cfg(test)]
#[path = "../tests/unit/application.rs"]
mod application_tests;
const KIND: u32 = u32::from_be_bytes(*b"VLD0");
/// Upstream ENV0 maximum uncompressed message size; transport framing is separate.
pub const MAX_RPC_BYTES: usize = 65507;

fn read(bytes: &[u8]) -> Result<Reader<OwnedSegments>, Error> {
    if bytes.len() > MAX_RPC_BYTES {
        return Err(Error::ValueTooLarge);
    }
    let mut input = bytes;
    let mut options = ReaderOptions::new();
    options.traversal_limit_in_words(Some(8192));
    options.nesting_limit(32);
    let message =
        capnp::serialize::read_message(&mut input, options).map_err(|_| Error::Encoding)?;
    if !input.is_empty() {
        return Err(Error::Encoding);
    }
    Ok(message)
}
fn canonical(message: Builder<HeapAllocator>) -> Result<Builder<HeapAllocator>, Error> {
    let message = if message.len() > 1 {
        let root = message
            .get_root_as_reader::<capnp::any_pointer::Reader>()
            .expect("generated builder owns its root");
        let size = root.target_size().map_err(|_| Error::Encoding)?.word_count + 1;
        if size > 8192 {
            return Err(Error::ValueTooLarge);
        }
        let mut canonical = Builder::new(HeapAllocator::new().first_segment_words(size as u32));
        canonical
            .set_root_canonical(root)
            .expect("builder pointers were constructed or checked during deep copy");
        canonical
    } else {
        message
    };
    if capnp::serialize::compute_serialized_size_in_words(&message) * 8 > MAX_RPC_BYTES {
        return Err(Error::ValueTooLarge);
    }
    Ok(message)
}
fn bytes(message: Builder<HeapAllocator>) -> Result<Vec<u8>, Error> {
    Ok(capnp::serialize::write_message_to_words(&canonical(
        message,
    )?))
}
fn packed(message: Builder<HeapAllocator>) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    // Upstream write_message documents only writer errors. Vec's writer appends
    // or allocation aborts; it cannot return an I/O failure.
    capnp::serialize_packed::write_message(&mut out, &canonical(message)?)
        .expect("Vec writer cannot return an I/O error");
    if out.len() > MAX_RPC_BYTES {
        return Err(Error::ValueTooLarge);
    }
    Ok(out)
}
fn read_packed(bytes: &[u8]) -> Result<Reader<OwnedSegments>, Error> {
    if bytes.len() > MAX_RPC_BYTES {
        return Err(Error::ValueTooLarge);
    }
    let mut input = bytes;
    let mut options = ReaderOptions::new();
    options.traversal_limit_in_words(Some(8192));
    options.nesting_limit(32);
    let message =
        capnp::serialize_packed::read_message(&mut input, options).map_err(|_| Error::Encoding)?;
    if !input.is_empty() {
        return Err(Error::Encoding);
    }
    Ok(message)
}
fn typed<const N: usize>(kind: u32, data: capnp::Result<&[u8]>) -> Result<[u8; N], Error> {
    if kind != KIND {
        return Err(Error::Encoding);
    }
    data.map_err(|_| Error::Encoding)?
        .try_into()
        .map_err(|_| Error::Encoding)
}
fn value_encode(
    value: &SignedValue,
    mut builder: wire::signed_value_data::Builder<'_>,
) -> Result<(), Error> {
    // raw_blob validates that its original bytes still match the decoded fields.
    builder.set_value_data(&value.raw_blob()?);
    let mut signature = builder.init_signature();
    signature.set_kind(KIND);
    signature.set_value(&value.signature);
    Ok(())
}
fn value_decode(reader: wire::signed_value_data::Reader<'_>) -> Result<SignedValue, Error> {
    let signature = reader.get_signature().map_err(|_| Error::Encoding)?;
    let signature = typed(signature.get_kind(), signature.get_value())?;
    let blob = reader.get_value_data().map_err(|_| Error::Encoding)?;
    SignedValue::from_blob(blob.to_vec(), signature)
}
fn descriptor_encode(
    descriptor: &Descriptor,
    mut builder: wire::signed_value_descriptor::Builder<'_>,
) {
    let mut owner = builder.reborrow().init_owner();
    owner.set_kind(KIND);
    owner.set_value(&descriptor.owner);
    builder.set_schema_data(&descriptor.schema);
    let mut signature = builder.init_signature();
    signature.set_kind(KIND);
    signature.set_value(&descriptor.signature);
}
fn descriptor_decode(
    reader: wire::signed_value_descriptor::Reader<'_>,
) -> Result<Descriptor, Error> {
    let owner = reader.get_owner().map_err(|_| Error::Encoding)?;
    let signature = reader.get_signature().map_err(|_| Error::Encoding)?;
    Ok(Descriptor {
        owner: typed(owner.get_kind(), owner.get_value())?,
        schema: reader
            .get_schema_data()
            .map_err(|_| Error::Encoding)?
            .to_vec(),
        signature: typed(signature.get_kind(), signature.get_value())?,
    })
}
/// Opaque upstream SignedValueData bytes. Construction checks shape; acceptance
/// still requires validation against the exact record descriptor and subkey.
pub struct ValueBytes(Vec<u8>);
impl ValueBytes {
    /// Preserve the original ValueData blob, nonce and writer signature.
    pub fn encode(value: &SignedValue) -> Result<Self, Error> {
        let mut message = Builder::new_default();
        value_encode(value, message.init_root())?;
        Ok(Self(bytes(message)?))
    }
    /// Check bounded external bytes without rewriting them.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, Error> {
        let this = Self(bytes);
        this.decode()?;
        Ok(this)
    }
    /// Exact upstream bytes for transmission, with no signing key.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// Recover the exact signed value; caller must authenticate before storage.
    pub fn decode(&self) -> Result<SignedValue, Error> {
        let message = read(&self.0)?;
        value_decode(message.get_root().map_err(|_| Error::Encoding)?)
    }
}
/// Opaque upstream SignedValueDescriptor bytes; the owner signature is retained.
pub struct DescriptorBytes(Vec<u8>);
impl DescriptorBytes {
    /// Encode an already signed descriptor. Never assigns or changes authority.
    pub fn encode(descriptor: &Descriptor) -> Result<Self, Error> {
        crate::Schema::parse(&descriptor.schema)?;
        let mut message = Builder::new_default();
        descriptor_encode(descriptor, message.init_root());
        Ok(Self(bytes(message)?))
    }
    /// Check bounded input without rewriting it.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, Error> {
        let this = Self(bytes);
        this.decode()?;
        Ok(this)
    }
    /// Original encoded descriptor for transmission.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// Decode; call Descriptor::validate_for before accepting it for a locator.
    pub fn decode(&self) -> Result<Descriptor, Error> {
        let message = read(&self.0)?;
        descriptor_decode(message.get_root().map_err(|_| Error::Encoding)?)
    }
}
/// Authenticated upstream SignedOperation, preserving its original operation blob.
/// This proves the signer and destination binding, not routing or record freshness.
pub struct SignedOperation {
    bytes: Vec<u8>,
    operation: Vec<u8>,
    signer: PublicKey,
}
fn transcript(destination: &PublicKey, operation: &[u8]) -> Vec<u8> {
    // Upstream CryptoTyped<PublicKey>::into<Vec<u8>> is kind || raw public key.
    let mut data = b"VLD0".to_vec();
    data.extend_from_slice(destination);
    data.extend_from_slice(operation);
    data
}
fn check_operation(operation: &[u8]) -> Result<(), Error> {
    let message = read(operation)?;
    let root = message
        .get_root::<wire::operation::Reader>()
        .map_err(|_| Error::Encoding)?;
    root.get_kind().which().map_err(|_| Error::Encoding)?;
    Ok(())
}
impl SignedOperation {
    /// Sign an already encoded upstream Operation inside a synchronous key-owner
    /// callback. The transcript and Cap'n Proto shape match upstream exactly.
    pub fn sign(
        operation: Vec<u8>,
        destination: &PublicKey,
        signer: &impl Signer,
    ) -> Result<Self, Error> {
        check_operation(&operation)?;
        let signature = signer.sign(&transcript(destination, &operation))?;
        let public = signer.public_key();
        let mut message = Builder::new_default();
        let mut root = message.init_root::<wire::signed_operation::Builder>();
        root.set_operation_data(&operation);
        let mut key = root.reborrow().init_signer();
        key.set_kind(KIND);
        key.set_value(&public);
        let mut sig = root.init_signature();
        sig.set_kind(KIND);
        sig.set_value(&signature);
        Ok(Self {
            bytes: packed(message)?,
            operation,
            signer: public,
        })
    }
    /// Authenticate original bytes for the exact destination and expected signer.
    /// For a node-signed RPC, bind the expected key to authenticated node information.
    /// WatchValue instead uses the watcher capability, which is distinct from the
    /// transport node. Its verified key does not grant a member quota or establish
    /// a routing coordinate; the storage owner must authorize that separately.
    pub fn verify(
        bytes: Vec<u8>,
        destination: &PublicKey,
        expected: &PublicKey,
        verifier: &impl Verifier,
    ) -> Result<Self, Error> {
        let message = read_packed(&bytes)?;
        let root = message
            .get_root::<wire::signed_operation::Reader>()
            .map_err(|_| Error::Encoding)?;
        let key = root.get_signer().map_err(|_| Error::Encoding)?;
        let signer: PublicKey = typed(key.get_kind(), key.get_value())?;
        if &signer != expected {
            return Err(Error::BadSignature);
        }
        let signature = root.get_signature().map_err(|_| Error::Encoding)?;
        let signature: Signature = typed(signature.get_kind(), signature.get_value())?;
        let operation = root
            .get_operation_data()
            .map_err(|_| Error::Encoding)?
            .to_vec();
        check_operation(&operation)?;
        if !verifier.verify(&signer, &transcript(destination, &operation), &signature) {
            return Err(Error::BadSignature);
        }
        Ok(Self {
            bytes,
            operation,
            signer,
        })
    }
    /// Send these exact signed bytes; do not reconstruct or re-sign at a relay.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Original authenticated Operation bytes for the Records RPC handler.
    pub fn operation(&self) -> &[u8] {
        &self.operation
    }
    /// Authenticated signer public key. This is not a membership credential.
    pub fn signer(&self) -> &PublicKey {
        &self.signer
    }
}

/// The supported original upstream record questions. No writer secret is accepted.
pub enum Query {
    /// Original WatchValueQ: create, renew, or cancel an upstream node lease.
    Watch {
        /// Public record locator.
        key: crate::RecordKey,
        /// Inclusive subkey ranges; empty means the complete record upstream.
        subkeys: SubkeyRanges,
        /// Requested duration in upstream TimestampDuration microseconds.
        duration_us: u64,
        /// Remaining notification count; zero cancels a nonzero watch_id.
        count: u32,
        /// Zero requests a new watch; nonzero refers to this node's existing lease.
        watch_id: u64,
    },
    /// Read one subkey and optionally its signed descriptor.
    Get {
        /// Public locator.
        key: crate::RecordKey,
        /// Subkey index.
        subkey: u32,
        /// Ask for the owner-signed schema.
        want_descriptor: bool,
    },
    /// Offer original signed bytes; the receiving node must validate against its schema.
    Set {
        /// Public locator.
        key: crate::RecordKey,
        /// Subkey index.
        subkey: u32,
        /// Original signed value.
        value: Box<SignedValue>,
        /// Optional owner-signed schema.
        descriptor: Option<Descriptor>,
    },
}
/// One original Operation with a platform-random RPC ID. Signing happens before I/O.
pub struct Question {
    id: u64,
    bytes: Vec<u8>,
}
fn key_encode(key: &crate::RecordKey, mut builder: wire::opaque_record_key::Builder<'_>) {
    builder.set_kind(KIND);
    builder.set_value(&key.0);
}
fn key_decode(reader: wire::opaque_record_key::Reader<'_>) -> Result<crate::RecordKey, Error> {
    Ok(crate::RecordKey(typed(
        reader.get_kind(),
        reader.get_value(),
    )?))
}
fn random_id() -> Result<u64, Error> {
    let mut bytes = [0; 8];
    getrandom::fill(&mut bytes).map_err(|_| Error::Randomness)?;
    Ok(u64::from_ne_bytes(bytes))
}
impl Question {
    /// Encode a supported record question using the unchanged upstream schema.
    pub fn new(query: &Query) -> Result<Self, Error> {
        Self::encode(query, random_id()?)
    }
    fn encode(query: &Query, id: u64) -> Result<Self, Error> {
        let mut message = Builder::new_default();
        let mut operation = message.init_root::<wire::operation::Builder>();
        operation.set_op_id(id);
        let mut question = operation.get_kind().init_question();
        question.reborrow().get_respond_to().set_sender(());
        let detail = question.get_detail();
        match query {
            Query::Watch {
                key,
                subkeys,
                duration_us,
                count,
                watch_id,
            } => {
                watch::encode(
                    key,
                    subkeys,
                    *duration_us,
                    *count,
                    *watch_id,
                    detail.init_watch_value_q(),
                )?;
            }
            Query::Get {
                key,
                subkey,
                want_descriptor,
            } => {
                let mut q = detail.init_get_value_q();
                key_encode(key, q.reborrow().init_key());
                q.set_subkey(*subkey);
                q.set_want_descriptor(*want_descriptor);
            }
            Query::Set {
                key,
                subkey,
                value,
                descriptor,
            } => {
                let mut q = detail.init_set_value_q();
                key_encode(key, q.reborrow().init_key());
                q.set_subkey(*subkey);
                value_encode(value, q.reborrow().init_value())?;
                if let Some(descriptor) = descriptor {
                    if descriptor.key() != *key {
                        return Err(Error::WrongRecord);
                    }
                    crate::Schema::parse(&descriptor.schema)?;
                    descriptor_encode(descriptor, q.init_descriptor());
                }
            }
        }
        Ok(Self {
            id,
            bytes: bytes(message)?,
        })
    }
    /// Random request identifier, for exact reply correlation.
    pub fn id(&self) -> u64 {
        self.id
    }
    /// Sign within the key-owner callback; no signer is retained by the question.
    pub fn sign(
        &self,
        destination: &PublicKey,
        signer: &impl Signer,
    ) -> Result<SignedOperation, Error> {
        SignedOperation::sign(self.bytes.clone(), destination, signer)
    }
    /// Original Operation bytes, for upstream interoperability evidence.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}
/// Decode a previously authenticated question. Signed values remain untrusted
/// until checked against the requested record's descriptor and subkey.
pub fn query(operation: &SignedOperation) -> Result<(u64, Query), Error> {
    decode_query(operation.operation())
}
fn decode_query(operation: &[u8]) -> Result<(u64, Query), Error> {
    let message = read(operation)?;
    // Callers hold immutable bytes from Question::encode or SignedOperation's
    // checked constructor. Nested question fields are still hostile inputs.
    let root = message
        .get_root::<wire::operation::Reader>()
        .expect("operation root checked at construction");
    let wire::operation::kind::Question(question) = root
        .get_kind()
        .which()
        .expect("operation kind checked at construction")
    else {
        return Err(Error::Encoding);
    };
    let question = question.map_err(|_| Error::Encoding)?;
    if !matches!(
        question
            .get_respond_to()
            .which()
            .map_err(|_| Error::Encoding)?,
        wire::question::respond_to::Sender(())
    ) {
        return Err(Error::Encoding);
    }
    let query = match question.get_detail().which().map_err(|_| Error::Encoding)? {
        wire::question::detail::WatchValueQ(q) => watch::decode(q.map_err(|_| Error::Encoding)?)?,
        wire::question::detail::GetValueQ(q) => {
            let q = q.map_err(|_| Error::Encoding)?;
            Query::Get {
                key: key_decode(q.get_key().map_err(|_| Error::Encoding)?)?,
                subkey: q.get_subkey(),
                want_descriptor: q.get_want_descriptor(),
            }
        }
        wire::question::detail::SetValueQ(q) => {
            let q = q.map_err(|_| Error::Encoding)?;
            Query::Set {
                key: key_decode(q.get_key().map_err(|_| Error::Encoding)?)?,
                subkey: q.get_subkey(),
                value: Box::new(value_decode(q.get_value().map_err(|_| Error::Encoding)?)?),
                descriptor: if q.has_descriptor() {
                    Some(descriptor_decode(
                        q.get_descriptor().map_err(|_| Error::Encoding)?,
                    )?)
                } else {
                    None
                },
            }
        }
        _ => return Err(Error::Encoding),
    };
    Ok((root.get_op_id(), query))
}

#[cfg(test)]
#[path = "../tests/support/rpc_encoding.rs"]
mod encoding_tests;

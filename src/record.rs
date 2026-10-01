// SPDX-License-Identifier: MPL-2.0
// Portions of Veilid, Copyright Veilid contributors.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Upstream: veilid/veilid, dd8e2cdd72b5bf817172ac31c20872b168c5c8fc.
//! Veilid record keys, signed descriptors and values.
//! Ports of veilid-core/src/veilid_api/types/dht/derivation.rs and
//! storage_manager/types/{signed_value_descriptor,signed_value_data,encrypted_value_data}.rs.

use crate::crypto::{CRYPTO_KIND_VLD0, PublicKey, Signature, Signer, Verifier};
use crate::{Error, Schema, b64};
use capnp::message::ReaderSegments;
use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

/// Highest usable sequence number.
pub const MAX_SEQ: u32 = u32::MAX - 1;

/// A record's key: the BLAKE3 hash of kind, owner and compiled schema. Text form
/// `VLD0:<base64url>` like Veilid's typed keys.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordKey(pub [u8; 32]);

impl RecordKey {
    /// Veilid's opaque record key derivation.
    pub fn derive(owner: &PublicKey, schema: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&CRYPTO_KIND_VLD0);
        hasher.update(owner);
        hasher.update(schema);
        Self(*hasher.finalize().as_bytes())
    }
}

impl fmt::Display for RecordKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VLD0:{}", BASE64URL_NOPAD.encode(&self.0))
    }
}

impl fmt::Debug for RecordKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RecordKey({self})")
    }
}

impl FromStr for RecordKey {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        let value = s.strip_prefix("VLD0:").ok_or(Error::Encoding)?;
        let bytes = BASE64URL_NOPAD
            .decode(value.as_bytes())
            .map_err(|_| Error::Encoding)?;
        Ok(Self(bytes.try_into().map_err(|_| Error::Encoding)?))
    }
}

impl Serialize for RecordKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for RecordKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// The owner-signed schema of a record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Descriptor {
    /// The owner's public key.
    #[serde(with = "b64")]
    pub owner: PublicKey,
    /// The compiled schema.
    #[serde(with = "b64")]
    pub schema: Vec<u8>,
    /// The owner's signature over the compiled schema.
    #[serde(with = "b64")]
    pub signature: Signature,
}

impl Descriptor {
    /// Sign `schema` as its owner.
    pub fn create(schema: &Schema, owner: &impl Signer) -> Result<Self, Error> {
        let compiled = schema.compile();
        let descriptor = Self {
            owner: owner.public_key(),
            signature: owner.sign(&compiled)?,
            schema: compiled,
        };
        Ok(descriptor)
    }

    /// The record key this descriptor defines.
    pub fn key(&self) -> RecordKey {
        RecordKey::derive(&self.owner, &self.schema)
    }

    /// Verify the owner's signature and parse the schema.
    pub fn validate(&self, verifier: &impl Verifier) -> Result<Schema, Error> {
        let schema = Schema::parse(&self.schema)?;
        if !verifier.verify(&self.owner, &self.schema, &self.signature) {
            return Err(Error::BadSignature);
        }
        Ok(schema)
    }

    /// [`Descriptor::validate`] plus a check that it belongs to `key`.
    pub fn validate_for(&self, key: &RecordKey, verifier: &impl Verifier) -> Result<Schema, Error> {
        if self.key() != *key {
            return Err(Error::WrongRecord);
        }
        self.validate(verifier)
    }
}

/// One subkey value, signed by its writer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedValue {
    /// Sequence number; a higher one replaces a lower one.
    pub seq: u32,
    /// The data (ciphertext for encrypted records).
    #[serde(with = "b64")]
    pub data: Vec<u8>,
    /// Separate VLD0 nonce. Presence selects the encrypted signature format.
    pub nonce: Option<[u8; 24]>,
    /// Original upstream blob, preserved for forwarding non-canonical input bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    blob: Option<Vec<u8>>,
    /// The writer's public key.
    #[serde(with = "b64")]
    pub writer: PublicKey,
    /// The writer's signature over [`SignedValue::signed_bytes`].
    #[serde(with = "b64")]
    pub signature: Signature,
}

impl SignedValue {
    /// Unpacked Veilid ValueData message, including its segment table.
    pub fn raw_blob(&self) -> Result<Vec<u8>, Error> {
        if let Some(blob) = &self.blob {
            let decoded = Self::from_blob(blob.clone(), self.signature)?;
            if !self.same_fields(&decoded) {
                return Err(Error::Encoding);
            }
            return Ok(blob.clone());
        }
        if self.seq > MAX_SEQ {
            return Err(Error::SeqExhausted);
        }
        if self.data.len() > crate::MAX_SUBKEY_SIZE {
            return Err(Error::ValueTooLarge);
        }
        let mut message = capnp::message::Builder::new_default();
        let mut builder = message.init_root::<crate::veilid_capnp::value_data::Builder>();
        builder.set_seq(self.seq);
        builder.set_data(&self.data);
        let mut writer = builder.reborrow().init_writer();
        writer.set_kind(u32::from_be_bytes(CRYPTO_KIND_VLD0));
        writer.set_value(&self.writer);
        if let Some(nonce) = self.nonce {
            builder.reborrow().init_nonce().set_value(&nonce);
        }
        // Match Veilid's helper exactly: only multi-segment builders are canonicalized.
        if message.len() != 1 {
            let root = message
                .get_root_as_reader::<capnp::any_pointer::Reader>()
                .expect("generated builder owns its root");
            let size = root.target_size().map_err(|_| Error::Encoding)?.word_count + 1;
            let mut canonical = capnp::message::Builder::new(
                capnp::message::HeapAllocator::new().first_segment_words(size as u32),
            );
            canonical
                .set_root_canonical(root)
                .expect("generated ValueData contains only valid data pointers");
            Ok(capnp::serialize::write_message_to_words(&canonical))
        } else {
            Ok(capnp::serialize::write_message_to_words(&message))
        }
    }

    /// Decode an upstream blob without rewriting the bytes its signature covers.
    /// This checks shape and limits; call `validate` before accepting the value.
    pub fn from_blob(blob: Vec<u8>, signature: Signature) -> Result<Self, Error> {
        if blob.len() > crate::MAX_SUBKEY_SIZE + 1024 {
            return Err(Error::ValueTooLarge);
        }
        let mut slice = blob.as_slice();
        let mut options = capnp::message::ReaderOptions::new();
        options.traversal_limit_in_words(Some(8192));
        options.nesting_limit(8);
        let message = capnp::serialize::read_message_from_flat_slice(&mut slice, options)
            .map_err(|_| Error::Encoding)?;
        if !slice.is_empty() {
            return Err(Error::Encoding);
        }
        let reader = message
            .get_root::<crate::veilid_capnp::value_data::Reader>()
            .map_err(|_| Error::Encoding)?;
        let seq = reader.get_seq();
        if seq > MAX_SEQ {
            return Err(Error::SeqExhausted);
        }
        let data = reader.get_data().map_err(|_| Error::Encoding)?;
        if data.len() > crate::MAX_SUBKEY_SIZE {
            return Err(Error::ValueTooLarge);
        }
        let writer = reader.get_writer().map_err(|_| Error::Encoding)?;
        if writer.get_kind() != u32::from_be_bytes(CRYPTO_KIND_VLD0) {
            return Err(Error::Encoding);
        }
        let writer = writer
            .get_value()
            .map_err(|_| Error::Encoding)?
            .try_into()
            .map_err(|_| Error::Encoding)?;
        let nonce = if reader.has_nonce() {
            Some(
                reader
                    .get_nonce()
                    .map_err(|_| Error::Encoding)?
                    .get_value()
                    .map_err(|_| Error::Encoding)?
                    .try_into()
                    .map_err(|_| Error::Encoding)?,
            )
        } else {
            None
        };
        Ok(Self {
            seq,
            data: data.to_vec(),
            writer,
            nonce,
            signature,
            blob: Some(blob),
        })
    }

    /// Compare Veilid value data, ignoring the signature and serialization bookkeeping.
    pub fn same_value(&self, other: &Self) -> bool {
        self.same_fields(other)
            && self
                .raw_blob()
                .ok()
                .zip(other.raw_blob().ok())
                .is_some_and(|(a, b)| a == b)
    }

    fn same_fields(&self, other: &Self) -> bool {
        self.seq == other.seq
            && self.data == other.data
            && self.writer == other.writer
            && self.nonce == other.nonce
    }

    /// Exact upstream signature input. Unencrypted values retain the legacy encoding.
    pub fn signed_bytes(&self, owner: &PublicKey, subkey: u32) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        if self.nonce.is_some() {
            let blob = self.raw_blob()?;
            out.extend_from_slice(&(blob.len() as u32).to_le_bytes());
            out.extend_from_slice(&blob);
            out.extend_from_slice(&CRYPTO_KIND_VLD0);
            out.extend_from_slice(&32u32.to_le_bytes());
            out.extend_from_slice(owner);
            out.extend_from_slice(&subkey.to_le_bytes());
        } else {
            out.extend_from_slice(owner);
            out.extend_from_slice(&subkey.to_le_bytes());
            out.extend_from_slice(&self.seq.to_le_bytes());
            out.extend_from_slice(&self.data);
        }
        Ok(out)
    }

    /// Sign an unencrypted value using Veilid's owner-bound legacy encoding.
    pub fn sign(
        owner: &PublicKey,
        subkey: u32,
        seq: u32,
        data: Vec<u8>,
        writer: &impl Signer,
    ) -> Result<Self, Error> {
        Self::sign_with_nonce(owner, subkey, seq, data, None, writer)
    }

    /// Sign ciphertext and a separate nonce, or a legacy plaintext value.
    pub fn sign_with_nonce(
        owner: &PublicKey,
        subkey: u32,
        seq: u32,
        data: Vec<u8>,
        nonce: Option<[u8; 24]>,
        writer: &impl Signer,
    ) -> Result<Self, Error> {
        if seq > MAX_SEQ {
            return Err(Error::SeqExhausted);
        }
        if data.len() > crate::MAX_SUBKEY_SIZE {
            return Err(Error::ValueTooLarge);
        }
        let mut value = Self {
            seq,
            data,
            nonce,
            writer: writer.public_key(),
            signature: [0; 64],
            blob: None,
        };
        value.signature = writer.sign(&value.signed_bytes(owner, subkey)?)?;
        Ok(value)
    }

    /// Validate schema, sequence, raw bytes and signature before use or forwarding.
    pub fn validate(
        &self,
        key: &RecordKey,
        owner: &PublicKey,
        schema: &Schema,
        subkey: u32,
        verifier: &impl Verifier,
    ) -> Result<(), Error> {
        if RecordKey::derive(owner, &schema.compile()) != *key {
            return Err(Error::WrongRecord);
        }
        if self.seq > MAX_SEQ {
            return Err(Error::SeqExhausted);
        }
        schema.check_write(owner, subkey, &self.writer, self.data.len())?;
        if self.blob.is_some() {
            self.raw_blob()?;
        }
        if !verifier.verify(
            &self.writer,
            &self.signed_bytes(owner, subkey)?,
            &self.signature,
        ) {
            return Err(Error::BadSignature);
        }
        Ok(())
    }
}

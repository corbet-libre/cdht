//! Signed records: descriptor, record key, subkey values.
//!
//! Semantics follow Veilid's DHT records: the owner signs the compiled schema (the
//! descriptor); the record key is BLAKE3(`VLD0` ‖ owner ‖ schema), exactly as Veilid
//! derives its opaque record key; each subkey holds a value with a sequence number,
//! signed by its writer. A higher sequence number replaces a lower one.
//!
//! The value signature covers our own byte layout ([`SignedValue::signed_bytes`]), not
//! Veilid's Cap'n Proto blob: the Veilid filling writes through `veilid-core`, which signs
//! with the delegated writer key itself. Keys, schema, subkeys and sequence numbers are
//! identical, so moving a record between fillings needs no data migration.

use crate::crypto::{CRYPTO_KIND_VLD0, PublicKey, Signature, Signer, Verifier};
use crate::{Error, Schema, b64};
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
        descriptor.check_members(schema)?;
        Ok(descriptor)
    }

    fn check_members(&self, schema: &Schema) -> Result<(), Error> {
        if schema.members().iter().any(|m| m.writer == self.owner) {
            return Err(Error::InvalidSchema);
        }
        Ok(())
    }

    /// The record key this descriptor defines.
    pub fn key(&self) -> RecordKey {
        RecordKey::derive(&self.owner, &self.schema)
    }

    /// Verify the owner's signature and parse the schema.
    pub fn validate(&self, verifier: &impl Verifier) -> Result<Schema, Error> {
        if !verifier.verify(&self.owner, &self.schema, &self.signature) {
            return Err(Error::BadSignature);
        }
        let schema = Schema::parse(&self.schema)?;
        self.check_members(&schema)?;
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
    /// The writer's public key.
    #[serde(with = "b64")]
    pub writer: PublicKey,
    /// The writer's signature over [`SignedValue::signed_bytes`].
    #[serde(with = "b64")]
    pub signature: Signature,
}

impl SignedValue {
    /// The exact bytes a writer signs: domain, record, subkey, sequence, writer, data.
    pub fn signed_bytes(
        key: &RecordKey,
        subkey: u32,
        seq: u32,
        writer: &PublicKey,
        data: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + 32 + 4 + 4 + 32 + 4 + data.len());
        out.extend_from_slice(b"cdht.value.v1\0");
        out.extend_from_slice(&key.0);
        out.extend_from_slice(&subkey.to_le_bytes());
        out.extend_from_slice(&seq.to_le_bytes());
        out.extend_from_slice(writer);
        out.extend_from_slice(&u32::try_from(data.len()).unwrap_or(u32::MAX).to_le_bytes());
        out.extend_from_slice(data);
        out
    }

    /// Sign `data` for `subkey` of `key` at `seq`.
    pub fn sign(
        key: &RecordKey,
        subkey: u32,
        seq: u32,
        data: Vec<u8>,
        writer: &impl Signer,
    ) -> Result<Self, Error> {
        if seq > MAX_SEQ {
            return Err(Error::SeqExhausted);
        }
        let public = writer.public_key();
        let signature = writer.sign(&Self::signed_bytes(key, subkey, seq, &public, &data))?;
        Ok(Self {
            seq,
            data,
            writer: public,
            signature,
        })
    }

    /// Check the value against the record's schema and the writer's signature.
    pub fn validate(
        &self,
        key: &RecordKey,
        owner: &PublicKey,
        schema: &Schema,
        subkey: u32,
        verifier: &impl Verifier,
    ) -> Result<(), Error> {
        if self.seq > MAX_SEQ {
            return Err(Error::SeqExhausted);
        }
        schema.check_write(owner, subkey, &self.writer, self.data.len())?;
        let bytes = Self::signed_bytes(key, subkey, self.seq, &self.writer, &self.data);
        if !verifier.verify(&self.writer, &bytes, &self.signature) {
            return Err(Error::BadSignature);
        }
        Ok(())
    }
}

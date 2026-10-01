//! `cdht`: signed replicated records with Veilid DHT semantics.
//!
//! - A record's **owner** signs its **schema**; the schema lists **writers** with their own
//!   **subkey** slots ([`Schema`], Veilid's SMPL schema, byte-identical). The record key is
//!   derived from owner and schema exactly as Veilid derives it.
//! - Every subkey value carries a **sequence number** and its writer's **signature**, and is
//!   checked against the owner-signed writer set on every hop ([`SignedValue`]).
//!   Authorisation is part of the data structure.
//! - [`Dht`]: open / get / set / **watch**, an **offline write queue**, optional
//!   per-record **encryption**. Application formats belong to the data-owning libraries.
//! - Fillings behind the [`Backend`] port: [`LocalBackend`] (one in-memory node) and
//!   [`NetworkBackend`] (replication over the caller's [`Network`] port). Tor and
//!   Veilid transport adapters plug in through `cmsh`'s DHT capability.
//!
//! `cdht` holds no secret keys (signing goes through the [`Signer`] port), contains no
//! network code and no policy: `cvlt` decides which records exist and who writes them.

#[cfg(test)]
extern crate self as cdht;
#[cfg(test)]
#[path = "../tests/common/mod.rs"]
mod test_crypto;

#[rustfmt::skip]
#[allow(missing_docs, dead_code, clippy::all)]
mod veilid_capnp;

mod backend;
mod client;
pub mod crypto;
mod error;
mod network;
mod record;
pub mod rpc;
mod schema;

pub use backend::{
    Backend, Capacity, Change, LocalBackend, MAX_WATCH_MS, PUBLIC_WATCH_LIMIT, SetOutcome, WatchId,
};
pub use client::{ClientState, Dht, FlushReport, QueuedWrite, WriteOutcome};
pub use crypto::{EncryptionKey, RecordCipher, Signer, Verifier};
pub use error::Error;
pub use network::{
    GET_VALUE_COUNT, MAX_FANOUT_NODES, Network, NetworkBackend, NodeId, ReadReport, SET_VALUE_COUNT,
};
pub use record::{Descriptor, MAX_SEQ, RecordKey, SignedValue};
pub use schema::{
    MAX_RECORD_DATA_SIZE, MAX_SUBKEY_COUNT, MAX_SUBKEY_SIZE, MAX_WRITER_COUNT, Member, Schema,
};

/// Serde helper: bytes as base64url without padding.
pub(crate) mod b64 {
    use data_encoding::BASE64URL_NOPAD;
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub(crate) fn serialize<S: Serializer, T: AsRef<[u8]>>(
        value: &T,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&BASE64URL_NOPAD.encode(value.as_ref()))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>, T: TryFrom<Vec<u8>>>(
        deserializer: D,
    ) -> Result<T, D::Error> {
        let text = String::deserialize(deserializer)?;
        let bytes = BASE64URL_NOPAD
            .decode(text.as_bytes())
            .map_err(D::Error::custom)?;
        T::try_from(bytes).map_err(|_| D::Error::custom("wrong length"))
    }
}

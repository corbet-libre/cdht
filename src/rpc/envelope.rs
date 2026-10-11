// SPDX-License-Identifier: MPL-2.0
// Portions of Veilid, Copyright Veilid contributors.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. https://mozilla.org/MPL/2.0/
// Upstream dd8e2cdd72b5bf817172ac31c20872b168c5c8fc:
// crypto/envelope/mod.rs and veilid_api/serialize_helpers/compression.rs.
//! Original VLD0 ENV0 node authentication, independent of an inner watcher signer.
//! No network key or relay rewrite is supported by this Tor-only direct adapter.
use crate::{Error, Signer, Verifier, crypto::PublicKey};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

const HEADER: usize = 0x6a;
const SIGNATURE: usize = 64;
const MINIMUM: usize = HEADER + SIGNATURE;
/// Original upstream ENV0 packet bound, including header and signature.
pub const MAX_ENVELOPE_BYTES: usize = 65_507;
/// Maximum original uncompressed body before envelope overhead.
pub const MAX_BODY_BYTES: usize = MAX_ENVELOPE_BYTES - MINIMUM;

/// Scoped node-purpose cipher owned by Keys. Implementations use maintained VLD0
/// DH + XChaCha20 with the requested peer and fresh envelope nonce. Neither node
/// secret nor computed DH secret may leave the key owner. This is distinct from
/// the DHT's original record read-secret cipher.
pub trait EnvelopeCipher {
    /// Public coordinate of the node whose secret is held by this cipher.
    fn node_id(&self) -> PublicKey;
    /// Apply original VLD0 crypt_no_auth using compute_dh(peer, this node secret).
    /// Reject invalid/non-contributory peer keys and oversized input.
    fn crypt(
        &self,
        peer: &PublicKey,
        nonce: &[u8; 24],
        input: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error>;
}
/// Bounded normal envelope timestamp acceptance, in Unix microseconds. Runtime
/// supplies actual wall time and its configured bounds, never a caller's request.
#[derive(Clone, Copy)]
pub struct TimeWindow {
    /// Maximum age at receipt. Zero allows only the current timestamp or future.
    pub behind_us: u64,
    /// Maximum future timestamp skew. Zero disallows future timestamps.
    pub ahead_us: u64,
}
/// Default number of authenticated envelope nonces remembered at once.
pub const DEFAULT_REPLAY_CAPACITY: usize = 65_536;

/// Bounded in-memory memory of accepted envelope nonces. An entry lives exactly
/// as long as its envelope could still pass the time window, so a replay inside
/// the window is refused and nothing is kept longer. Nothing is persisted. When
/// the cache is full of live entries it refuses new envelopes (fail closed)
/// instead of evicting one, because eviction would reopen a replay.
pub struct ReplayCache {
    capacity: usize,
    seen: BTreeMap<(PublicKey, [u8; 24]), u64>,
    by_expiry: BTreeSet<(u64, PublicKey, [u8; 24])>,
}

impl ReplayCache {
    /// Cache holding at most `capacity` live nonces.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            seen: BTreeMap::new(),
            by_expiry: BTreeSet::new(),
        }
    }

    /// Number of nonces currently remembered.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether no nonce is remembered.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    fn admit(
        &mut self,
        sender: PublicKey,
        nonce: [u8; 24],
        expires_us: u64,
        now_us: u64,
    ) -> Result<(), Error> {
        while let Some(&(expiry, node, seen_nonce)) = self.by_expiry.first() {
            if expiry >= now_us {
                break;
            }
            self.by_expiry.remove(&(expiry, node, seen_nonce));
            self.seen.remove(&(node, seen_nonce));
        }
        if self.seen.contains_key(&(sender, nonce)) {
            return Err(Error::Replay);
        }
        if self.seen.len() >= self.capacity {
            return Err(Error::Unavailable);
        }
        self.seen.insert((sender, nonce), expires_us);
        self.by_expiry.insert((expires_us, sender, nonce));
        Ok(())
    }
}

/// An original envelope whose node signature, destination and timestamp have been
/// authenticated. Inner record/watcher signatures still require separate checks.
pub struct Envelope {
    bytes: Vec<u8>,
    sender: PublicKey,
    recipient: PublicKey,
    nonce: [u8; 24],
    timestamp_us: u64,
}
/// An inner original SignedOperation decrypted from the authenticated outer
/// envelope. Construction binds the transport node to these exact operation bytes;
/// its watcher signer may be different. No unverified constructor is exposed.
pub struct AuthenticatedOperation {
    sender: PublicKey,
    operation: super::SignedOperation,
}
impl AuthenticatedOperation {
    /// Actual node authenticated by the original outer ENV0 signature.
    pub fn sender(&self) -> &PublicKey {
        &self.sender
    }
    /// Original operation with its independently verified inner signature.
    pub fn operation(&self) -> &super::SignedOperation {
        &self.operation
    }
    /// Authenticate the original self-advertisement against the outer node,
    /// independently of any record watcher signing the inner operation.
    pub fn sender_peer(
        &self,
        verifier: &impl Verifier,
    ) -> Result<super::peers::VerifiedExtensionPeer, Error> {
        self.operation.sender_peer_as(&self.sender, verifier)
    }
}
impl Envelope {
    /// Seal the original packed SignedOperation body, with a fresh random nonce.
    /// Compression and encryption precede the original node signature transcript.
    pub fn seal(
        body: &[u8],
        destination: &PublicKey,
        timestamp_us: u64,
        signer: &impl Signer,
        cipher: &impl EnvelopeCipher,
    ) -> Result<Vec<u8>, Error> {
        let sender = signer.public_key();
        if sender == *destination || cipher.node_id() != sender {
            return Err(Error::BadSignature);
        }
        if body.len() > MAX_BODY_BYTES {
            return Err(Error::ValueTooLarge);
        }
        let compressed = Zeroizing::new(lz4_flex::block::compress_prepend_size(body));
        let size = compressed.len() + MINIMUM;
        if size > MAX_ENVELOPE_BYTES {
            return Err(Error::ValueTooLarge);
        }
        let mut nonce = [0; 24];
        getrandom::fill(&mut nonce).map_err(|_| Error::Signer)?;
        let encrypted = cipher.crypt(destination, &nonce, &compressed)?;
        if encrypted.len() != compressed.len() {
            return Err(Error::Encoding);
        }
        let mut out = vec![0; size];
        out[..4].copy_from_slice(b"ENV0");
        out[4..8].copy_from_slice(b"VLD0");
        out[8..10].copy_from_slice(&(size as u16).to_le_bytes());
        out[10..18].copy_from_slice(&timestamp_us.to_le_bytes());
        out[18..42].copy_from_slice(&nonce);
        out[42..74].copy_from_slice(&sender);
        out[74..106].copy_from_slice(destination);
        let end = size - SIGNATURE;
        out[HEADER..end].copy_from_slice(&encrypted);
        let signature = signer.sign(&out[..end])?;
        out[end..].copy_from_slice(&signature);
        Ok(out)
    }
    /// Like [`Envelope::verify`], and additionally refuse an envelope whose
    /// sender and nonce were already accepted inside the time window. The nonce
    /// is remembered only after the node signature verified, so unauthenticated
    /// traffic cannot fill the cache.
    pub fn verify_once(
        bytes: Vec<u8>,
        destination: &PublicKey,
        now_us: u64,
        window: TimeWindow,
        verifier: &impl Verifier,
        cache: &mut ReplayCache,
    ) -> Result<Self, Error> {
        let envelope = Self::verify(bytes, destination, now_us, window, verifier)?;
        cache.admit(
            envelope.sender,
            envelope.nonce,
            envelope.timestamp_us.saturating_add(window.behind_us),
            now_us,
        )?;
        Ok(envelope)
    }
    /// Authenticate original bytes before decrypting or allocating decompressed
    /// content. A valid inner watcher signature cannot substitute for this node.
    pub fn verify(
        bytes: Vec<u8>,
        destination: &PublicKey,
        now_us: u64,
        window: TimeWindow,
        verifier: &impl Verifier,
    ) -> Result<Self, Error> {
        if !(MINIMUM..=MAX_ENVELOPE_BYTES).contains(&bytes.len())
            || &bytes[..4] != b"ENV0"
            || &bytes[4..8] != b"VLD0"
            || usize::from(u16::from_le_bytes(bytes[8..10].try_into().unwrap())) != bytes.len()
        {
            return Err(Error::Encoding);
        }
        let sender: PublicKey = bytes[42..74].try_into().unwrap();
        let recipient: PublicKey = bytes[74..106].try_into().unwrap();
        if sender == recipient || &recipient != destination {
            return Err(Error::BadSignature);
        }
        let timestamp_us = u64::from_le_bytes(bytes[10..18].try_into().unwrap());
        if now_us.saturating_sub(timestamp_us) > window.behind_us
            || timestamp_us.saturating_sub(now_us) > window.ahead_us
        {
            return Err(Error::Unavailable);
        }
        let end = bytes.len() - SIGNATURE;
        if !verifier.verify(&sender, &bytes[..end], &bytes[end..].try_into().unwrap()) {
            return Err(Error::BadSignature);
        }
        Ok(Self {
            nonce: bytes[18..42].try_into().unwrap(),
            bytes,
            sender,
            recipient,
            timestamp_us,
        })
    }
    /// Node identity authenticated by the outer envelope, distinct from watcher.
    pub fn sender(&self) -> &PublicKey {
        &self.sender
    }
    /// Authenticated original publication timestamp, in Unix microseconds.
    pub fn timestamp_us(&self) -> u64 {
        self.timestamp_us
    }
    /// Retained original packet, useful for forwarding without changing signatures.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Decrypt and verify the inner original signature while retaining its actual
    /// authenticated transport origin. Invoke synchronously inside scoped Keys.
    pub fn open_operation(
        &self,
        cipher: &impl EnvelopeCipher,
        verifier: &impl Verifier,
    ) -> Result<AuthenticatedOperation, Error> {
        let body = self.open(cipher)?;
        let operation =
            super::SignedOperation::verify_sender(body.to_vec(), &self.recipient, verifier)?;
        Ok(AuthenticatedOperation {
            sender: self.sender,
            operation,
        })
    }
    /// Decrypt through the retained node owner. LZ4's declared expansion is checked
    /// BEFORE allocation, using the original upstream decompression bound.
    pub fn open(&self, cipher: &impl EnvelopeCipher) -> Result<Zeroizing<Vec<u8>>, Error> {
        if cipher.node_id() != self.recipient {
            return Err(Error::BadSignature);
        }
        let body = cipher.crypt(
            &self.sender,
            &self.nonce,
            &self.bytes[HEADER..self.bytes.len() - SIGNATURE],
        )?;
        if body.len() != self.bytes.len() - MINIMUM {
            return Err(Error::Encoding);
        }
        let (size, compressed) =
            lz4_flex::block::uncompressed_size(&body).map_err(|_| Error::Encoding)?;
        if size > MAX_ENVELOPE_BYTES {
            return Err(Error::ValueTooLarge);
        }
        lz4_flex::block::decompress(compressed, size)
            .map(Zeroizing::new)
            .map_err(|_| Error::Encoding)
    }
}

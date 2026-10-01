// SPDX-License-Identifier: MPL-2.0
// Portions of Veilid, Copyright Veilid contributors.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Upstream: veilid/veilid, dd8e2cdd72b5bf817172ac31c20872b168c5c8fc.
//! VLD0 signing ports and record encryption.
//! Port of veilid-core/src/storage_manager/record_encryption.rs and
//! crypto/crypto_system/vld0/mod.rs. DHT encryption uses XChaCha20 without an
//! authentication tag; the record's signature authenticates ciphertext and nonce.

use crate::{Error, RecordKey};
use chacha20::{
    XChaCha20,
    cipher::{KeyIvInit, StreamCipher},
};
use data_encoding::BASE64URL_NOPAD;
use zeroize::Zeroizing;

/// A raw VLD0 public key (Ed25519).
pub type PublicKey = [u8; 32];
/// A raw VLD0 signature (Ed25519ph, context `VLD0_SIGN`).
pub type Signature = [u8; 64];

/// The only cryptosystem `cdht` records use today.
pub const CRYPTO_KIND_VLD0: [u8; 4] = *b"VLD0";

/// Makes signatures with one key. Implemented by the key owner (the vault); `cdht`
/// never sees the secret.
pub trait Signer {
    /// The public key signatures verify under.
    fn public_key(&self) -> PublicKey;
    /// Sign `data` (VLD0 semantics).
    fn sign(&self, data: &[u8]) -> Result<Signature, Error>;
}

/// Checks signatures. Must be strict (reject non-canonical signatures and weak keys).
pub trait Verifier {
    /// Whether `signature` is a valid signature by `public_key` over `data`.
    fn verify(&self, public_key: &PublicKey, data: &[u8], signature: &Signature) -> bool;
}

/// A scoped VLD0 record cipher supplied by the key owner. Implementations must
/// retain custody of the key; this port exposes only the cipher operation.
/// Records supplies fresh encryption nonces and verifies signatures before opening.
pub trait RecordCipher {
    /// Apply upstream XChaCha20 without an authentication tag. The original record
    /// signature authenticates the nonce and ciphertext before decryption.
    fn crypt(&self, nonce: &[u8; 24], input: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error>;
}

impl<F> RecordCipher for F
where
    F: Fn(&[u8; 24], &[u8]) -> Result<Zeroizing<Vec<u8>>, Error>,
{
    fn crypt(&self, nonce: &[u8; 24], input: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        self(nonce, input)
    }
}

/// An independent Veilid read capability for interoperability. Wiped on drop;
/// never sent to storage nodes. Device production code instead lends a scoped
/// [`RecordCipher`] from its key owner, without exporting the owner's secret.
#[derive(Clone)]
pub struct EncryptionKey(Zeroizing<[u8; 32]>);

impl EncryptionKey {
    /// Wrap a VLD0 shared secret supplied by the key owner.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Apply Veilid's symmetric record cipher. The caller must supply a fresh nonce
    /// for every encryption and verify the signed value before decryption.
    pub fn crypt(&self, nonce: &[u8; 24], input: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        let mut out = Zeroizing::new(input.to_vec());
        XChaCha20::new((&*self.0).into(), nonce.into())
            .try_apply_keystream(&mut out)
            .map_err(|_| Error::Crypto)?;
        Ok(out)
    }

    /// Veilid's full record-key encoding, including the secret read capability.
    /// Treat the returned string as a secret; never log or send it to DHT nodes.
    pub fn record_key(&self, opaque: &RecordKey) -> Zeroizing<String> {
        Zeroizing::new(format!("{}:{}", opaque, BASE64URL_NOPAD.encode(&*self.0)))
    }

    /// Decode a full VLD0 record key, separating its public locator and read secret.
    pub fn parse_record_key(text: &str) -> Result<(RecordKey, Option<Self>), Error> {
        let parts: Vec<_> = text.split(':').collect();
        match parts.as_slice() {
            ["VLD0", _] => Ok((text.parse()?, None)),
            ["VLD0", opaque, secret] => {
                let bytes = Zeroizing::new(
                    BASE64URL_NOPAD
                        .decode(secret.as_bytes())
                        .map_err(|_| Error::Encoding)?,
                );
                let secret: [u8; 32] = bytes.as_slice().try_into().map_err(|_| Error::Encoding)?;
                Ok((
                    format!("VLD0:{opaque}").parse()?,
                    Some(Self::from_bytes(secret)),
                ))
            }
            _ => Err(Error::Encoding),
        }
    }
}

impl std::fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EncryptionKey([redacted])")
    }
}

impl RecordCipher for EncryptionKey {
    fn crypt(&self, nonce: &[u8; 24], input: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.crypt(nonce, input)
    }
}

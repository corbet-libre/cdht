//! Crypto ports and record encryption.
//!
//! `cdht` signs and verifies through two small ports, so it never holds a secret key and
//! does not depend on a particular key store: in the vault, `cvlt` adapts `ckmg`'s key
//! ring (VLD0: Ed25519ph with context `VLD0_SIGN`); tests use a local double. Keys are raw
//! 32-byte VLD0 public keys, signatures raw 64-byte VLD0 signatures.
//!
//! Record data can be encrypted with a per-record key (XChaCha20-Poly1305), as Veilid
//! does for encrypted DHT records. The key travels with the record key out of band, never
//! inside the record.

use crate::Error;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
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

const NONCE_LENGTH: usize = 24;
const AAD_LABEL: &[u8] = b"cdht.value-data.v1\0";

/// A per-record symmetric key. Wiped on drop.
#[derive(Clone)]
pub struct EncryptionKey(Zeroizing<[u8; 32]>);

impl EncryptionKey {
    /// Wrap 32 secret bytes (in the vault: a member-scope purpose secret from `ckmg`).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    fn cipher(&self) -> Result<XChaCha20Poly1305, Error> {
        XChaCha20Poly1305::new_from_slice(self.0.as_slice()).map_err(|_| Error::Crypto)
    }

    /// Encrypt one subkey's data, bound to the record and subkey.
    pub(crate) fn seal(
        &self,
        record: &[u8; 32],
        subkey: u32,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut nonce = [0u8; NONCE_LENGTH];
        getrandom::fill(&mut nonce).map_err(|_| Error::Randomness)?;
        let ciphertext = self
            .cipher()?
            .encrypt(
                &XNonce::try_from(&nonce[..]).map_err(|_| Error::Crypto)?,
                Payload {
                    msg: plaintext,
                    aad: &aad(record, subkey),
                },
            )
            .map_err(|_| Error::Crypto)?;
        let mut out = Vec::with_capacity(NONCE_LENGTH + ciphertext.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt one subkey's data.
    pub(crate) fn open(
        &self,
        record: &[u8; 32],
        subkey: u32,
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        if sealed.len() < NONCE_LENGTH {
            return Err(Error::Decrypt);
        }
        let (nonce, ciphertext) = sealed.split_at(NONCE_LENGTH);
        self.cipher()?
            .decrypt(
                &XNonce::try_from(nonce).map_err(|_| Error::Decrypt)?,
                Payload {
                    msg: ciphertext,
                    aad: &aad(record, subkey),
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| Error::Decrypt)
    }
}

impl std::fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EncryptionKey([redacted])")
    }
}

fn aad(record: &[u8; 32], subkey: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(AAD_LABEL.len() + 36);
    out.extend_from_slice(AAD_LABEL);
    out.extend_from_slice(record);
    out.extend_from_slice(&subkey.to_le_bytes());
    out
}

//! Test doubles for the crypto ports with Veilid VLD0 semantics (Ed25519ph, context
//! `VLD0_SIGN`). In the vault, `cvlt` adapts `ckmg` instead.
#![allow(dead_code)]

use cdht::crypto::{PublicKey, Signature};
use cdht::{Error, Signer, Verifier};
use ed25519_dalek::{Digest, Sha512, SigningKey, VerifyingKey};

pub struct TestKey(SigningKey);

pub fn key(seed: u8) -> TestKey {
    TestKey(SigningKey::from_bytes(&[seed; 32]))
}

fn prehash(data: &[u8]) -> Sha512 {
    let mut digest = Sha512::new();
    digest.update(data);
    digest
}

impl Signer for TestKey {
    fn public_key(&self) -> PublicKey {
        self.0.verifying_key().to_bytes()
    }
    fn sign(&self, data: &[u8]) -> Result<Signature, Error> {
        self.0
            .sign_prehashed(prehash(data), Some(&b"VLD0_SIGN"[..]))
            .map(|s| s.to_bytes())
            .map_err(|_| Error::Signer)
    }
}

#[derive(Clone, Copy)]
pub struct TestVerifier;

impl Verifier for TestVerifier {
    fn verify(&self, public_key: &PublicKey, data: &[u8], signature: &Signature) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(public_key) else {
            return false;
        };
        !key.is_weak()
            && key
                .verify_prehashed_strict(
                    prehash(data),
                    Some(&b"VLD0_SIGN"[..]),
                    &ed25519_dalek::Signature::from_bytes(signature),
                )
                .is_ok()
    }
}

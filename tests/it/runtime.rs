//! A real signing/encrypting local engine qualifies the runtime facade itself.
//! Native network and storage qualification belongs to Mesh/cvln's actual core.
use crate::common::{TestKey, TestVerifier, key};
use cdht::{
    Backend as RawBackend, Descriptor, Dht, EncryptionKey, Error, LocalBackend, RecordKey, Schema,
    SetOutcome, SignedValue, Signer,
    runtime::{Backend, Changes, Identity, Publication, Record, Value},
};
use futures_executor::block_on;

struct Engine {
    storage: LocalBackend<TestVerifier>,
    identity: Identity,
    writer: TestKey,
    cipher: EncryptionKey,
}
impl Backend for Engine {
    fn identity(&self) -> Identity {
        self.identity.clone()
    }
    async fn get(&self, subkey: u32, _: bool) -> Result<Option<Value>, Error> {
        self.storage
            .get(&self.identity.key, subkey)
            .await?
            .map(|signed| {
                signed.validate(
                    &self.identity.key,
                    &self.identity.owner,
                    &self.identity.schema,
                    subkey,
                    &TestVerifier,
                )?;
                Ok(Value {
                    seq: signed.seq,
                    writer: signed.writer,
                    data: self
                        .cipher
                        .crypt(&signed.nonce.ok_or(Error::Decrypt)?, &signed.data)?,
                })
            })
            .transpose()
    }
    async fn republish(&self, subkey: u32, seq: u32, data: &[u8]) -> Result<Publication, Error> {
        let mut nonce = [0; 24];
        getrandom::fill(&mut nonce).map_err(|_| Error::Unavailable)?;
        let encrypted = self.cipher.crypt(&nonce, data)?;
        let signed = SignedValue::sign_with_nonce(
            &self.identity.owner,
            subkey,
            seq,
            encrypted.to_vec(),
            Some(nonce),
            &self.writer,
        )?;
        match self
            .storage
            .set(&self.identity.key, subkey, &signed)
            .await?
        {
            SetOutcome::Accepted => Ok(Publication::Queued),
            SetOutcome::Newer(_) => Ok(Publication::Conflict(
                self.get(subkey, false).await?.ok_or(Error::Unavailable)?,
            )),
        }
    }
    async fn flush(&self) -> Result<bool, Error> {
        // This local test engine makes no network replication claim.
        Ok(false)
    }
    async fn watch(&self) -> Result<bool, Error> {
        Err(Error::Unavailable)
    }
    async fn cancel_watch(&self) -> Result<bool, Error> {
        Err(Error::Unavailable)
    }
    fn changes(&self) -> Result<Changes, Error> {
        Err(Error::Unavailable)
    }
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn original_tor_signature_is_verified_before_scoped_plaintext_republication() {
    block_on(async {
        let writer = key(51);
        let cipher = EncryptionKey::from_bytes([72; 32]);
        let schema = Schema::new(1, vec![]).unwrap();
        let source = LocalBackend::new(TestVerifier);
        let mut tor = Dht::new(source.clone(), TestVerifier);
        let locator = tor.create(&schema, &writer).await.unwrap();
        tor.set(&locator, 0, b"original content", &writer, Some(&cipher))
            .await
            .unwrap();
        let original = tor.get_signed(&locator, 0).await.unwrap().unwrap();
        let identity = Identity {
            key: locator,
            owner: writer.public_key(),
            schema: schema.clone(),
            writer: Some(writer.public_key()),
        };
        let destination = LocalBackend::new(TestVerifier);
        destination
            .create(&Descriptor::create(&schema, &writer).unwrap())
            .await
            .unwrap();
        let record = Record::new(Engine {
            storage: destination.clone(),
            identity: identity.clone(),
            writer,
            cipher,
        })
        .unwrap();
        assert!(record.identity().key == locator);
        assert!(record.get(0, false).await.unwrap().is_none());
        let prepared = {
            let scoped_cipher = EncryptionKey::from_bytes([72; 32]);
            record
                .prepare_republish(0, &original, &TestVerifier, Some(&scoped_cipher))
                .unwrap()
        }; // Borrowed scoped capability is released BEFORE network await.
        assert_eq!(&*prepared.data, b"original content");
        assert_eq!(format!("{prepared:?}"), "Value([redacted])");
        assert!(matches!(
            record.republish(0, &prepared).await.unwrap(),
            Publication::Queued
        ));
        assert!(!record.flush().await.unwrap());
        let reopened = record.get(0, true).await.unwrap().unwrap();
        assert_eq!(reopened.seq, original.seq);
        assert_eq!(reopened.writer, original.writer);
        assert_eq!(&*reopened.data, b"original content");
        let encoded = destination.get(&locator, 0).await.unwrap().unwrap();
        assert_ne!(encoded.nonce, original.nonce);
        assert_ne!(encoded.signature, original.signature);
        // Reopen through the independently validating original Records client.
        let mut reader = Dht::new(destination, TestVerifier);
        reader.open(&locator).await.unwrap();
        assert_eq!(
            &*reader
                .get(&locator, 0, Some(&EncryptionKey::from_bytes([72; 32])))
                .await
                .unwrap()
                .unwrap(),
            b"original content"
        );
        let mut tampered = original.clone();
        tampered.signature[0] ^= 1;
        assert!(
            record
                .prepare_republish(
                    0,
                    &tampered,
                    &TestVerifier,
                    Some(&EncryptionKey::from_bytes([72; 32]))
                )
                .is_err()
        );
        assert!(matches!(
            record.prepare_republish(0, &original, &TestVerifier, None),
            Err(Error::Decrypt)
        ));
        assert!(matches!(
            record.get(1, false).await,
            Err(Error::SubkeyOutOfRange)
        ));
        assert!(matches!(
            record.republish(1, &prepared).await,
            Err(Error::SubkeyOutOfRange)
        ));
        let mut bad = Value {
            seq: prepared.seq,
            writer: [0; 32],
            data: vec![1].into(),
        };
        assert!(matches!(
            record.republish(0, &bad).await,
            Err(Error::WrongWriter)
        ));
        bad.writer = prepared.writer;
        bad.seq = u32::MAX;
        assert!(matches!(
            record.republish(0, &bad).await,
            Err(Error::SeqExhausted)
        ));
        bad.seq = prepared.seq;
        bad.data = vec![0; cdht::MAX_SUBKEY_SIZE + 1].into();
        assert!(matches!(
            record.republish(0, &bad).await,
            Err(Error::ValueTooLarge)
        ));
        bad.data = b"conflicting content".to_vec().into();
        assert!(matches!(
            record.republish(0, &bad).await.unwrap(),
            Publication::Conflict(_)
        ));
        assert!(record.watch().await.is_err());
        assert!(record.cancel_watch().await.is_err());
        assert!(record.changes().is_err());
        let mut engine = record.into_backend();
        engine.identity.writer = None;
        let readonly = Record::new(engine).unwrap();
        assert!(matches!(
            readonly.republish(0, &prepared).await,
            Err(Error::WrongWriter)
        ));
        assert!(matches!(
            readonly.prepare_republish(
                0,
                &original,
                &TestVerifier,
                Some(&EncryptionKey::from_bytes([72; 32]))
            ),
            Err(Error::WrongWriter)
        ));
        let mut engine = readonly.into_backend();
        engine.identity.key = RecordKey::derive(&[0; 32], &schema.compile());
        assert!(matches!(Record::new(engine), Err(Error::WrongRecord)));
    });
}

//! A backend acknowledgment is untrusted and must never discard pending work.
use crate::common::{TestVerifier, key};
use cdht::{
    Backend, Change, ClientState, Descriptor, Dht, Error, LocalBackend, RecordKey, Schema,
    SetOutcome, SignedValue, WatchId,
};
use futures_executor::block_on;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct Faulty {
    inner: LocalBackend<TestVerifier>,
    reply: Arc<Mutex<Option<SignedValue>>>,
    hang: Arc<std::sync::atomic::AtomicBool>,
    corrupt_reply: Arc<std::sync::atomic::AtomicU8>,
}
impl Faulty {
    fn receive(&self, stage: u8) -> Result<(), Error> {
        if self
            .corrupt_reply
            .load(std::sync::atomic::Ordering::Relaxed)
            == stage
        {
            // The operation ran against the actual store, then its transport
            // reply was corrupted. Use the real bounded record decoder.
            let _ = cdht::rpc::DescriptorBytes::from_bytes(vec![0xff; 8])?;
        }
        Ok(())
    }
}
impl Backend for Faulty {
    async fn create(&self, d: &Descriptor) -> Result<(), Error> {
        self.inner.create(d).await?;
        self.receive(1)
    }
    async fn descriptor(&self, k: &RecordKey) -> Result<Option<Descriptor>, Error> {
        let result = self.inner.descriptor(k).await?;
        self.receive(2)?;
        Ok(result)
    }
    async fn get(&self, k: &RecordKey, s: u32) -> Result<Option<SignedValue>, Error> {
        let result = self.inner.get(k, s).await?;
        self.receive(3)?;
        Ok(result)
    }
    async fn set(&self, k: &RecordKey, s: u32, v: &SignedValue) -> Result<SetOutcome, Error> {
        if self.hang.load(std::sync::atomic::Ordering::Relaxed) {
            std::future::pending::<()>().await;
        }
        if let Some(value) = self.reply.lock().unwrap().clone() {
            return Ok(SetOutcome::Newer(value));
        }
        let result = self.inner.set(k, s, v).await?;
        self.receive(4)?;
        Ok(result)
    }
    async fn watch(&self, k: &RecordKey) -> Result<WatchId, Error> {
        self.inner.watch(k).await
    }
    async fn cancel_watch(&self, w: WatchId) -> Result<(), Error> {
        self.inner.cancel_watch(w).await
    }
    async fn changes(&self, w: WatchId) -> Result<Vec<Change>, Error> {
        self.inner.changes(w).await
    }
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn forged_flush_reply_keeps_the_queue_and_cache() {
    block_on(async {
        let backend = Faulty {
            inner: LocalBackend::new(TestVerifier),
            reply: Arc::new(Mutex::new(None)),
            hang: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            corrupt_reply: Arc::new(std::sync::atomic::AtomicU8::new(0)),
        };
        let owner = key(1);
        let mut client = Dht::new(backend.clone(), TestVerifier);
        let record = client
            .create(&Schema::dflt(1).unwrap(), &owner)
            .await
            .unwrap();
        backend.inner.set_online(false);
        client
            .set(&record, 0, b"keep me", &owner, None)
            .await
            .unwrap();
        let pending = client.state().queue()[0].value.clone();
        let mut forged = pending.clone();
        forged.seq = 999;
        *backend.reply.lock().unwrap() = Some(forged);
        backend.inner.set_online(true);
        assert_eq!(client.flush().await.unwrap_err(), Error::BadSignature);
        assert_eq!(client.state().queue()[0].value, pending);
        *backend.reply.lock().unwrap() = None;
        assert_eq!(client.flush().await.unwrap().written, 1);
        assert_eq!(
            client
                .get(&record, 0, None)
                .await
                .unwrap()
                .unwrap()
                .as_slice(),
            b"keep me"
        );
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn resume_preserves_original_pending_bytes_beside_a_newer_authenticated_cache() {
    use cdht::Signer;
    block_on(async {
        let backend = LocalBackend::new(TestVerifier);
        let owner = key(1);
        let mut client = Dht::new(backend.clone(), TestVerifier);
        let record = client
            .create(&Schema::dflt(1).unwrap(), &owner)
            .await
            .unwrap();
        backend.set_online(false);
        client.set(&record, 0, b"old", &owner, None).await.unwrap();
        let old_queue = serde_json::to_value(client.state()).unwrap()["queue"].clone();
        client
            .set(&record, 0, b"latest", &owner, None)
            .await
            .unwrap();
        let mut state = serde_json::to_value(client.state()).unwrap();
        state["queue"] = old_queue;
        let state: ClientState = serde_json::from_value(state).unwrap();
        let mut resumed = Dht::with_state(backend.clone(), TestVerifier, state);
        assert_eq!(resumed.state().queue()[0].value.seq, 0);
        assert_eq!(resumed.state().queue()[0].value.data, b"old");
        backend.set_online(true);
        let latest =
            SignedValue::sign(&owner.public_key(), 0, 1, b"latest".to_vec(), &owner).unwrap();
        backend.set(&record, 0, &latest).await.unwrap();
        let report = resumed.flush().await.unwrap();
        assert_eq!(report.written, 0);
        assert_eq!(report.stale, vec![(record, 0)]);
        assert_eq!(report.remaining, 0);
        assert_eq!(resumed.get_signed(&record, 0).await.unwrap(), Some(latest));
        assert_eq!(
            backend.get(&record, 0).await.unwrap().unwrap().data,
            b"latest"
        );
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn ciphertext_nonce_owner_and_subkey_tampering_are_rejected() {
    use cdht::{EncryptionKey, Signer};
    let owner = key(1);
    let schema = Schema::dflt(2).unwrap();
    let record = Descriptor::create(&schema, &owner).unwrap().key();
    let data = EncryptionKey::from_bytes([42; 32])
        .crypt(&[3; 24], b"message")
        .unwrap()
        .to_vec();
    let value =
        SignedValue::sign_with_nonce(&owner.public_key(), 0, 0, data, Some([3; 24]), &owner)
            .unwrap();
    let mut altered = value.clone();
    altered.nonce = Some([4; 24]);
    assert_eq!(
        altered
            .validate(&record, &owner.public_key(), &schema, 0, &TestVerifier)
            .unwrap_err(),
        Error::BadSignature
    );
    let mut altered = value.clone();
    altered.data[0] ^= 1;
    assert_eq!(
        altered
            .validate(&record, &owner.public_key(), &schema, 0, &TestVerifier)
            .unwrap_err(),
        Error::BadSignature
    );
    assert_eq!(
        value
            .validate(&record, &owner.public_key(), &schema, 1, &TestVerifier)
            .unwrap_err(),
        Error::BadSignature
    );
    let other = key(2);
    let other_record = Descriptor::create(&schema, &other).unwrap().key();
    assert!(
        value
            .validate(
                &other_record,
                &other.public_key(),
                &schema,
                0,
                &TestVerifier
            )
            .is_err()
    );
    assert!(SignedValue::from_blob(vec![255; 64], value.signature).is_err());
    let mut trailing = value.raw_blob().unwrap();
    trailing.extend_from_slice(&[0; 8]);
    assert_eq!(
        SignedValue::from_blob(trailing, value.signature).unwrap_err(),
        Error::Encoding
    );
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn cancellation_after_dispatch_keeps_a_signed_retry() {
    use std::{
        future::Future,
        task::{Context, Poll, Waker},
    };
    block_on(async {
        let backend = Faulty {
            inner: LocalBackend::new(TestVerifier),
            reply: Arc::new(Mutex::new(None)),
            hang: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            corrupt_reply: Arc::new(std::sync::atomic::AtomicU8::new(0)),
        };
        let owner = key(1);
        let mut client = Dht::new(backend.clone(), TestVerifier);
        let record = client
            .create(&Schema::dflt(1).unwrap(), &owner)
            .await
            .unwrap();
        {
            let mut write = Box::pin(client.set(&record, 0, b"pending", &owner, None));
            assert!(matches!(
                write.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                Poll::Pending
            ));
        }
        assert_eq!(client.state().queue().len(), 1);
        backend
            .hang
            .store(false, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(client.flush().await.unwrap().written, 1);
        assert_eq!(
            backend.inner.get(&record, 0).await.unwrap().unwrap().data,
            b"pending"
        );
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn malformed_backend_replies_never_acknowledge_or_discard_signed_intent() {
    use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
    block_on(async {
        let backend = Faulty {
            inner: LocalBackend::new(TestVerifier),
            reply: Arc::new(Mutex::new(None)),
            hang: Arc::new(AtomicBool::new(false)),
            corrupt_reply: Arc::new(AtomicU8::new(0)),
        };
        let owner = key(60);
        let schema = Schema::dflt(1).unwrap();
        let locator = Descriptor::create(&schema, &owner).unwrap().key();
        let mut client = Dht::new(backend.clone(), TestVerifier);
        backend.corrupt_reply.store(1, Ordering::Relaxed);
        assert_eq!(
            client.create(&schema, &owner).await.unwrap_err(),
            Error::Encoding
        );
        assert_eq!(client.schema(&locator).unwrap_err(), Error::NotOpen);
        assert!(backend.inner.descriptor(&locator).await.unwrap().is_some());
        backend.corrupt_reply.store(2, Ordering::Relaxed);
        assert_eq!(client.open(&locator).await.unwrap_err(), Error::Encoding);
        backend.corrupt_reply.store(1, Ordering::Relaxed);
        assert_eq!(client.open(&locator).await.unwrap_err(), Error::Encoding);
        backend.corrupt_reply.store(0, Ordering::Relaxed);
        client.open(&locator).await.unwrap();
        client
            .set(&locator, 0, b"original", &owner, None)
            .await
            .unwrap();
        let before = serde_json::to_vec(client.state()).unwrap();
        backend.corrupt_reply.store(3, Ordering::Relaxed);
        assert_eq!(
            client.get_signed(&locator, 0).await.unwrap_err(),
            Error::Encoding
        );
        assert_eq!(serde_json::to_vec(client.state()).unwrap(), before);
        backend.corrupt_reply.store(4, Ordering::Relaxed);
        assert_eq!(
            client
                .set(&locator, 0, b"pending", &owner, None)
                .await
                .unwrap_err(),
            Error::Encoding
        );
        let pending = client.state().queue()[0].value.clone();
        assert_eq!(
            backend.inner.get(&locator, 0).await.unwrap(),
            Some(pending.clone())
        );
        backend.corrupt_reply.store(1, Ordering::Relaxed);
        assert_eq!(client.flush().await.unwrap_err(), Error::Encoding);
        assert_eq!(client.state().queue()[0].value, pending);
        backend.corrupt_reply.store(0, Ordering::Relaxed);
        assert_eq!(client.flush().await.unwrap().written, 1);
        assert!(client.state().queue().is_empty());
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn replaying_a_genuine_older_signed_response_cannot_acknowledge_a_newer_write() {
    use std::sync::atomic::{AtomicBool, AtomicU8};
    block_on(async {
        let backend = Faulty {
            inner: LocalBackend::new(TestVerifier),
            reply: Arc::new(Mutex::new(None)),
            hang: Arc::new(AtomicBool::new(false)),
            corrupt_reply: Arc::new(AtomicU8::new(0)),
        };
        let owner = key(61);
        let mut client = Dht::new(backend.clone(), TestVerifier);
        let locator = client
            .create(&Schema::dflt(1).unwrap(), &owner)
            .await
            .unwrap();
        client
            .set(&locator, 0, b"past", &owner, None)
            .await
            .unwrap();
        let past = backend.inner.get(&locator, 0).await.unwrap().unwrap();
        backend.inner.set_online(false);
        client
            .set(&locator, 0, b"future", &owner, None)
            .await
            .unwrap();
        let pending = client.state().queue()[0].value.clone();
        *backend.reply.lock().unwrap() = Some(past);
        backend.inner.set_online(true);
        assert_eq!(client.flush().await.unwrap_err(), Error::Conflict);
        assert_eq!(client.state().queue()[0].value, pending);
        *backend.reply.lock().unwrap() = None;
        assert_eq!(client.flush().await.unwrap().written, 1);
        assert_eq!(backend.inner.get(&locator, 0).await.unwrap(), Some(pending));
    });
}

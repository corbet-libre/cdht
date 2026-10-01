//! A backend acknowledgment is untrusted and must never discard pending work.
mod common;
use cdht::{
    Backend, Change, ClientState, Descriptor, Dht, Error, LocalBackend, RecordKey, Schema,
    SetOutcome, SignedValue, WatchId,
};
use common::{TestVerifier, key};
use futures_executor::block_on;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct Faulty {
    inner: LocalBackend<TestVerifier>,
    reply: Arc<Mutex<Option<SignedValue>>>,
    hang: Arc<std::sync::atomic::AtomicBool>,
}
impl Backend for Faulty {
    async fn create(&self, d: &Descriptor) -> Result<(), Error> {
        self.inner.create(d).await
    }
    async fn descriptor(&self, k: &RecordKey) -> Result<Option<Descriptor>, Error> {
        self.inner.descriptor(k).await
    }
    async fn get(&self, k: &RecordKey, s: u32) -> Result<Option<SignedValue>, Error> {
        self.inner.get(k, s).await
    }
    async fn set(&self, k: &RecordKey, s: u32, v: &SignedValue) -> Result<SetOutcome, Error> {
        if self.hang.load(std::sync::atomic::Ordering::Relaxed) {
            std::future::pending::<()>().await;
        }
        if let Some(value) = self.reply.lock().unwrap().clone() {
            return Ok(SetOutcome::Newer(value));
        }
        self.inner.set(k, s, v).await
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
fn resume_coalesces_old_signed_queue_entries_to_the_newest_cached_value() {
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
        assert_eq!(resumed.state().queue()[0].value.seq, 1);
        backend.set_online(true);
        resumed.flush().await.unwrap();
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

//! Original signed values, validating LocalBackend and original ClientState.
//! Persistence faults model lost transport outcomes, not accepted authority or
//! distributed Veilid/Tor replication. No signing capability reaches staging.
mod common;

use cdht::{
    Backend, Change, ClientState, Descriptor, Dht, EncryptionKey, Error, LocalBackend,
    QueuedPublication, RecordCipher, RecordKey, Schema, SetOutcome, SignedValue, Signer, WatchId,
    rpc::{DescriptorBytes, ValueBytes},
};
use common::{TestVerifier, key};
use futures::FutureExt;
use futures_executor::block_on;
use std::sync::{Arc, Mutex};

const PLAINTEXT: &[u8] = b"fixed original genesis evidence fixture";

#[derive(Clone)]
struct TransportFaults {
    inner: LocalBackend<TestVerifier>,
    mode: Arc<Mutex<u8>>,
    writes: Arc<Mutex<usize>>,
}
impl TransportFaults {
    fn new() -> Self {
        Self {
            inner: LocalBackend::new(TestVerifier),
            mode: Arc::new(Mutex::new(0)),
            writes: Arc::new(Mutex::new(0)),
        }
    }
}
impl Backend for TransportFaults {
    async fn create(&self, descriptor: &Descriptor) -> Result<(), Error> {
        self.inner.create(descriptor).await
    }
    async fn descriptor(&self, record: &RecordKey) -> Result<Option<Descriptor>, Error> {
        self.inner.descriptor(record).await
    }
    async fn get(&self, record: &RecordKey, subkey: u32) -> Result<Option<SignedValue>, Error> {
        self.inner.get(record, subkey).await
    }
    async fn set(
        &self,
        record: &RecordKey,
        subkey: u32,
        value: &SignedValue,
    ) -> Result<SetOutcome, Error> {
        *self.writes.lock().unwrap() += 1;
        let outcome = self.inner.set(record, subkey, value).await?;
        let mode = *self.mode.lock().unwrap();
        match mode {
            1 => Err(Error::Unavailable),
            2 => futures::future::pending().await,
            _ => Ok(outcome),
        }
    }
    async fn watch(&self, record: &RecordKey) -> Result<WatchId, Error> {
        self.inner.watch(record).await
    }
    async fn cancel_watch(&self, watch: WatchId) -> Result<(), Error> {
        self.inner.cancel_watch(watch).await
    }
    async fn changes(&self, watch: WatchId) -> Result<Vec<Change>, Error> {
        self.inner.changes(watch).await
    }
}
fn signed(seq: u32, data: &[u8], nonce: u8) -> (Descriptor, SignedValue) {
    let owner = key(91);
    let descriptor = Descriptor::create(&Schema::dflt(1).unwrap(), &owner).unwrap();
    let nonce = [nonce; 24];
    let ciphertext = EncryptionKey::from_bytes([51; 32])
        .crypt(&nonce, data)
        .unwrap();
    let value = SignedValue::sign_with_nonce(
        &descriptor.owner,
        0,
        seq,
        ciphertext.to_vec(),
        Some(nonce),
        &owner,
    )
    .unwrap();
    // Accept input through the original RPC decoders, including the retained
    // original ValueData blob, with no private signing key in the returned pair.
    (
        DescriptorBytes::encode(&descriptor)
            .unwrap()
            .decode()
            .unwrap(),
        ValueBytes::encode(&value).unwrap().decode().unwrap(),
    )
}
fn exact_bytes(descriptor: &Descriptor, value: &SignedValue) -> (Vec<u8>, Vec<u8>) {
    (
        DescriptorBytes::encode(descriptor)
            .unwrap()
            .as_bytes()
            .to_vec(),
        ValueBytes::encode(value).unwrap().as_bytes().to_vec(),
    )
}
fn snapshot<B: Backend>(client: &Dht<B, TestVerifier>) -> Vec<u8> {
    serde_json::to_vec(client.state()).unwrap()
}
macro_rules! shared {
    ($name:ident,$body:block) => {
        #[cfg_attr(not(target_arch = "wasm32"), test)]
        #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
        fn $name() { block_on(async $body); }
    };
}

shared!(
    original_genesis_rpc_bytes_survive_staging_serde_reopen_offline_and_real_flush,
    {
        let backend = TransportFaults::new();
        backend.inner.set_online(false);
        let (descriptor, value) = signed(0, PLAINTEXT, 52);
        let expected = exact_bytes(&descriptor, &value);
        let mut client = Dht::new(backend.clone(), TestVerifier);
        assert!(matches!(
            client.queue_original(&descriptor, 0, &value).unwrap(),
            QueuedPublication::Queued
        ));
        assert_eq!(*backend.writes.lock().unwrap(), 0);
        assert_eq!(client.state().queue()[0].value, value);
        let stored = snapshot(&client);
        drop(client);
        let state: ClientState = serde_json::from_slice(&stored).unwrap();
        let mut reopened = Dht::with_state(backend.clone(), TestVerifier, state);
        assert_eq!(snapshot(&reopened), stored);
        assert_eq!(
            exact_bytes(&descriptor, &reopened.state().queue()[0].value),
            expected
        );
        assert_eq!(reopened.flush().await.unwrap().remaining, 1);
        assert_eq!(snapshot(&reopened), stored);
        backend.inner.set_online(true);
        let report = reopened.flush().await.unwrap();
        assert_eq!(report.written, 1);
        assert_eq!(report.remaining, 0);
        assert!(report.stale.is_empty());
        let received_descriptor = backend
            .inner
            .descriptor(&descriptor.key())
            .await
            .unwrap()
            .unwrap();
        let received = backend
            .inner
            .get(&descriptor.key(), 0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(exact_bytes(&received_descriptor, &received), expected);
        let mut reader = Dht::new(backend.clone(), TestVerifier);
        reader.open(&descriptor.key()).await.unwrap();
        assert_eq!(
            reader
                .get_signed_fresh(&descriptor.key(), 0)
                .await
                .unwrap()
                .unwrap(),
            value
        );
        assert_eq!(
            reader
                .open_value(
                    &descriptor.key(),
                    0,
                    &received,
                    Some(&EncryptionKey::from_bytes([51; 32]))
                )
                .unwrap()
                .as_slice(),
            PLAINTEXT
        );
    }
);

shared!(
    lost_reply_and_cancelled_flush_retain_only_the_original_signed_obligation,
    {
        for mode in [1, 2] {
            let backend = TransportFaults::new();
            let (descriptor, value) = signed(0, PLAINTEXT, 53);
            let expected = exact_bytes(&descriptor, &value);
            let mut client = Dht::new(backend.clone(), TestVerifier);
            client.queue_original(&descriptor, 0, &value).unwrap();
            let staged = snapshot(&client);
            *backend.mode.lock().unwrap() = mode;
            if mode == 1 {
                assert_eq!(client.flush().await.unwrap().remaining, 1);
            } else {
                assert!(client.flush().now_or_never().is_none());
            }
            assert_eq!(snapshot(&client), staged);
            let received = backend
                .inner
                .get(&descriptor.key(), 0)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(exact_bytes(&descriptor, &received), expected);
            drop(client);
            let state: ClientState = serde_json::from_slice(&staged).unwrap();
            let mut reopened = Dht::with_state(backend.clone(), TestVerifier, state);
            *backend.mode.lock().unwrap() = 0;
            let report = reopened.flush().await.unwrap();
            assert_eq!(report.written, 1);
            assert_eq!(report.remaining, 0);
            assert_eq!(*backend.writes.lock().unwrap(), 2);
            assert_eq!(
                exact_bytes(
                    &descriptor,
                    &backend
                        .inner
                        .get(&descriptor.key(), 0)
                        .await
                        .unwrap()
                        .unwrap()
                ),
                expected
            );
        }
    }
);

shared!(
    generation_ciphertext_nonce_and_signature_conflicts_never_replace_staged_bytes,
    {
        let backend = LocalBackend::new(TestVerifier);
        let (descriptor, original) = signed(7, PLAINTEXT, 54);
        let mut client = Dht::new(backend, TestVerifier);
        client.queue_original(&descriptor, 0, &original).unwrap();
        let staged = snapshot(&client);
        let owner = key(91);
        let mut alternative_signature = original.clone();
        alternative_signature.signature =
            owner.alternative_signature(&original.signed_bytes(&descriptor.owner, 0).unwrap());
        alternative_signature
            .validate(
                &descriptor.key(),
                &descriptor.owner,
                &Schema::dflt(1).unwrap(),
                0,
                &TestVerifier,
            )
            .unwrap();
        let candidates = [
            signed(6, PLAINTEXT, 54).1,
            signed(7, b"different", 54).1,
            signed(7, PLAINTEXT, 55).1,
            alternative_signature,
        ];
        for candidate in candidates {
            let QueuedPublication::Conflict(conflict) =
                client.queue_original(&descriptor, 0, &candidate).unwrap()
            else {
                panic!("conflicting original value was staged")
            };
            assert_eq!(conflict, original);
            assert_eq!(snapshot(&client), staged);
        }
        assert!(matches!(
            client.queue_original(&descriptor, 0, &original).unwrap(),
            QueuedPublication::Queued
        ));
        assert_eq!(snapshot(&client), staged);
        let mut different_descriptor = descriptor.clone();
        different_descriptor.signature = owner.alternative_signature(&descriptor.schema);
        different_descriptor.validate(&TestVerifier).unwrap();
        assert_eq!(
            client
                .queue_original(&different_descriptor, 0, &original)
                .unwrap_err(),
            Error::Conflict
        );
        assert_eq!(snapshot(&client), staged);
        let higher = signed(8, b"next admitted generation", 56).1;
        let QueuedPublication::Conflict(conflict) =
            client.queue_original(&descriptor, 0, &higher).unwrap()
        else {
            panic!("original pending obligation was superseded")
        };
        assert_eq!(conflict, original);
        assert_eq!(snapshot(&client), staged);
        assert_eq!(client.flush().await.unwrap().written, 1);
        assert!(client.state().queue().is_empty());
        assert!(matches!(
            client.queue_original(&descriptor, 0, &higher).unwrap(),
            QueuedPublication::Queued
        ));
        assert_eq!(client.state().queue().len(), 1);
        assert_eq!(client.state().queue()[0].value, higher);
    }
);

shared!(
    fresh_equal_observation_and_pending_original_are_independent_staging_fences,
    {
        let backend = LocalBackend::new(TestVerifier);
        let (descriptor, pending) = signed(7, b"pending original", 57);
        let winner = signed(7, b"authenticated remote winner", 58).1;
        backend.create(&descriptor).await.unwrap();
        backend.set(&descriptor.key(), 0, &winner).await.unwrap();
        let mut client = Dht::new(backend, TestVerifier);
        client.queue_original(&descriptor, 0, &pending).unwrap();
        assert_eq!(
            client
                .get_signed_fresh(&descriptor.key(), 0)
                .await
                .unwrap()
                .unwrap(),
            winner
        );
        assert_eq!(client.state().queue()[0].value, pending);
        let staged = snapshot(&client);
        let QueuedPublication::Conflict(conflict) =
            client.queue_original(&descriptor, 0, &pending).unwrap()
        else {
            panic!("fresh winner ignored")
        };
        assert_eq!(conflict, winner);
        assert_eq!(snapshot(&client), staged);
        let QueuedPublication::Conflict(conflict) =
            client.queue_original(&descriptor, 0, &winner).unwrap()
        else {
            panic!("pending original ignored")
        };
        assert_eq!(conflict, pending);
        assert_eq!(snapshot(&client), staged);
        let state: ClientState = serde_json::from_slice(&staged).unwrap();
        let mut reopened = Dht::with_state(LocalBackend::new(TestVerifier), TestVerifier, state);
        assert_eq!(snapshot(&reopened), staged);
        assert!(matches!(
            reopened.queue_original(&descriptor, 0, &winner).unwrap(),
            QueuedPublication::Conflict(_)
        ));
        assert_eq!(snapshot(&reopened), staged);
        let newer = signed(8, b"newer authenticated remote observation", 60).1;
        client
            .backend()
            .set(&descriptor.key(), 0, &newer)
            .await
            .unwrap();
        assert_eq!(
            client
                .get_signed_fresh(&descriptor.key(), 0)
                .await
                .unwrap()
                .unwrap(),
            newer
        );
        assert_eq!(client.state().queue()[0].value, pending);
        let before_stale = snapshot(&client);
        let QueuedPublication::Conflict(conflict) =
            client.queue_original(&descriptor, 0, &pending).unwrap()
        else {
            panic!("cached higher generation ignored")
        };
        assert_eq!(conflict, newer);
        assert_eq!(snapshot(&client), before_stale);
        let state: ClientState = serde_json::from_slice(&before_stale).unwrap();
        let mut higher_cache_reopen =
            Dht::with_state(client.backend().clone(), TestVerifier, state);
        assert_eq!(snapshot(&higher_cache_reopen), before_stale);
        assert_eq!(
            exact_bytes(&descriptor, &higher_cache_reopen.state().queue()[0].value),
            exact_bytes(&descriptor, &pending)
        );
        let report = higher_cache_reopen.flush().await.unwrap();
        assert_eq!(report.written, 0);
        assert_eq!(report.stale, vec![(descriptor.key(), 0)]);
        assert_eq!(report.remaining, 0);
        assert_eq!(
            higher_cache_reopen
                .get_signed_fresh(&descriptor.key(), 0)
                .await
                .unwrap(),
            Some(newer)
        );
    }
);

shared!(
    identical_original_staging_keeps_multiple_slots_and_blob_bookkeeping_exact,
    {
        let owner = key(95);
        let descriptor = Descriptor::create(&Schema::dflt(3).unwrap(), &owner).unwrap();
        let mut client = Dht::new(LocalBackend::new(TestVerifier), TestVerifier);
        let mut originals = Vec::new();
        for subkey in [2, 0, 1] {
            let value = SignedValue::sign_with_nonce(
                &descriptor.owner,
                subkey,
                0,
                vec![subkey as u8],
                Some([61; 24]),
                &owner,
            )
            .unwrap();
            client.queue_original(&descriptor, subkey, &value).unwrap();
            originals.push(value);
        }
        let staged = snapshot(&client);
        assert_eq!(
            client
                .state()
                .queue()
                .iter()
                .map(|q| q.subkey)
                .collect::<Vec<_>>(),
            vec![2, 0, 1]
        );
        let from_blob = ValueBytes::encode(&originals[1]).unwrap().decode().unwrap();
        assert_ne!(from_blob, originals[1]);
        assert!(from_blob.same_value(&originals[1]));
        assert_eq!(from_blob.signature, originals[1].signature);
        assert!(matches!(
            client.queue_original(&descriptor, 0, &from_blob).unwrap(),
            QueuedPublication::Queued
        ));
        assert_eq!(snapshot(&client), staged);
        assert!(matches!(
            client
                .queue_original(&descriptor, 0, &originals[1])
                .unwrap(),
            QueuedPublication::Queued
        ));
        assert_eq!(snapshot(&client), staged);
    }
);

shared!(
    invalid_signed_inputs_refuse_before_any_original_state_mutation,
    {
        let (descriptor, value) = signed(0, PLAINTEXT, 59);
        for invalid in 0..7 {
            let mut client = Dht::new(LocalBackend::new(TestVerifier), TestVerifier);
            let empty = snapshot(&client);
            let mut supplied_descriptor = descriptor.clone();
            let mut supplied_value = value.clone();
            let mut subkey = 0;
            match invalid {
                0 => supplied_descriptor.signature[0] ^= 1,
                1 => supplied_descriptor.schema.push(1),
                2 => supplied_value.signature[0] ^= 1,
                3 => supplied_value.writer = key(92).public_key(),
                4 => subkey = 1,
                5 => supplied_value.seq = cdht::MAX_SEQ + 1,
                6 => supplied_value.data = vec![0; cdht::MAX_SUBKEY_SIZE + 1],
                _ => unreachable!(),
            }
            assert!(
                client
                    .queue_original(&supplied_descriptor, subkey, &supplied_value)
                    .is_err()
            );
            assert_eq!(snapshot(&client), empty);
        }
        // A valid SMPL member signature still cannot move between schema slots.
        let owner = key(93);
        let member = key(94);
        let schema = Schema::new(
            1,
            vec![cdht::Member {
                writer: member.public_key(),
                subkeys: 1,
            }],
        )
        .unwrap();
        let descriptor = Descriptor::create(&schema, &owner).unwrap();
        let member_value =
            SignedValue::sign(&descriptor.owner, 1, 0, b"member".to_vec(), &member).unwrap();
        let mut client = Dht::new(LocalBackend::new(TestVerifier), TestVerifier);
        let empty = snapshot(&client);
        assert_eq!(
            client
                .queue_original(&descriptor, 0, &member_value)
                .unwrap_err(),
            Error::WrongWriter
        );
        assert_eq!(snapshot(&client), empty);
        assert!(matches!(
            client
                .queue_original(&descriptor, 1, &member_value)
                .unwrap(),
            QueuedPublication::Queued
        ));
    }
);

shared!(
    original_observation_keeps_its_floor_and_never_replaces_the_pending_publication,
    {
        let backend = TransportFaults::new();
        backend.inner.set_online(false);
        let (descriptor, pending) = signed(0, PLAINTEXT, 62);
        let mut client = Dht::new(backend.clone(), TestVerifier);
        client.queue_original(&descriptor, 0, &pending).unwrap();
        let original_queue = client.state().queue().to_vec();
        let conflict = signed(0, b"equal conflicting observation", 63).1;
        client
            .observe_original(&descriptor.key(), 0, &conflict)
            .unwrap();
        assert_eq!(client.state().queue(), original_queue);
        assert_eq!(*backend.writes.lock().unwrap(), 0);
        assert_eq!(
            client.get_signed(&descriptor.key(), 0).await.unwrap(),
            Some(conflict)
        );
        let higher = signed(1, b"higher authenticated observation", 64).1;
        client
            .observe_original(&descriptor.key(), 0, &higher)
            .unwrap();
        let stored = snapshot(&client);
        assert_eq!(client.state().queue(), original_queue);
        assert_eq!(
            client.observe_original(&descriptor.key(), 0, &pending),
            Err(Error::Conflict)
        );
        assert_eq!(snapshot(&client), stored);
        for case in 0..3 {
            let mut invalid = higher.clone();
            let subkey = if case == 2 { 1 } else { 0 };
            if case == 0 {
                invalid.signature[0] ^= 1;
            }
            if case == 1 {
                invalid.writer = key(92).public_key();
            }
            assert!(
                client
                    .observe_original(&descriptor.key(), subkey, &invalid)
                    .is_err()
            );
            assert_eq!(snapshot(&client), stored);
        }
        drop(client);
        let restored: ClientState = serde_json::from_slice(&stored).unwrap();
        let mut reopened = Dht::with_state(backend.clone(), TestVerifier, restored);
        assert_eq!(snapshot(&reopened), stored);
        let QueuedPublication::Conflict(observed) =
            reopened.queue_original(&descriptor, 0, &pending).unwrap()
        else {
            panic!("retained signed observation lost its floor")
        };
        assert_eq!(observed, higher);
        assert_eq!(reopened.state().queue(), original_queue);
        assert_eq!(*backend.writes.lock().unwrap(), 0);
    }
);

fn two_original_outputs() -> (Descriptor, [SignedValue; 2]) {
    let owner = key(93);
    let descriptor = Descriptor::create(&Schema::dflt(2).unwrap(), &owner).unwrap();
    let values = [0, 1].map(|subkey| {
        let nonce = [101 + subkey as u8; 24];
        let packed = EncryptionKey::from_bytes([55; 32])
            .crypt(&nonce, &[subkey as u8, 7, 8])
            .unwrap();
        SignedValue::sign_with_nonce(
            &descriptor.owner,
            subkey,
            2,
            packed.to_vec(),
            Some(nonce),
            &owner,
        )
        .unwrap()
    });
    (descriptor, values)
}

shared!(one_output_flush_returns_before_the_next_original_write, {
    let backend = TransportFaults::new();
    let (descriptor, values) = two_original_outputs();
    let mut client = Dht::new(backend.clone(), TestVerifier);
    for (subkey, value) in values.iter().enumerate() {
        client
            .queue_original(&descriptor, subkey as u32, value)
            .unwrap();
    }
    let report = client.flush_one().await.unwrap();
    assert_eq!((report.written, report.remaining), (1, 1));
    assert!(report.stale.is_empty());
    assert_eq!(*backend.writes.lock().unwrap(), 1);
    assert_eq!(
        backend.inner.get(&descriptor.key(), 0).await.unwrap(),
        Some(values[0].clone())
    );
    assert!(
        backend
            .inner
            .get(&descriptor.key(), 1)
            .await
            .unwrap()
            .is_none()
    );
    let state: ClientState = serde_json::from_slice(&snapshot(&client)).unwrap();
    let mut reopened = Dht::with_state(backend.clone(), TestVerifier, state.clone());
    assert_eq!(reopened.state(), &state);
    let report = reopened.flush_one().await.unwrap();
    assert_eq!((report.written, report.remaining), (1, 0));
    assert_eq!(*backend.writes.lock().unwrap(), 2);
    assert_eq!(
        backend.inner.get(&descriptor.key(), 1).await.unwrap(),
        Some(values[1].clone())
    );
});

shared!(
    one_output_flush_retains_real_newer_floor_before_attempting_next_subkey,
    {
        let backend = TransportFaults::new();
        let (descriptor, values) = two_original_outputs();
        let newer = SignedValue::sign_with_nonce(
            &descriptor.owner,
            0,
            3,
            b"newer authenticated ciphertext".to_vec(),
            Some([104; 24]),
            &key(93),
        )
        .unwrap();
        backend.inner.create(&descriptor).await.unwrap();
        backend
            .inner
            .set(&descriptor.key(), 0, &newer)
            .await
            .unwrap();
        let mut client = Dht::new(backend.clone(), TestVerifier);
        for (subkey, value) in values.iter().enumerate() {
            client
                .queue_original(&descriptor, subkey as u32, value)
                .unwrap();
        }
        let report = client.flush_one().await.unwrap();
        assert_eq!((report.written, report.remaining), (0, 1));
        assert_eq!(report.stale, vec![(descriptor.key(), 0)]);
        assert_eq!(*backend.writes.lock().unwrap(), 1);
        assert!(
            backend
                .inner
                .get(&descriptor.key(), 1)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            client.observed_value(&descriptor.key(), 0).unwrap(),
            Some(&newer)
        );
        assert_eq!(
            client.observed_value(&descriptor.key(), 1).unwrap(),
            Some(&values[1])
        );
        assert!(matches!(
            client.observed_value(&descriptor.key(), 2),
            Err(Error::SubkeyOutOfRange)
        ));
        let state: ClientState = serde_json::from_slice(&snapshot(&client)).unwrap();
        let mut reopened = Dht::with_state(backend, TestVerifier, state.clone());
        assert_eq!(reopened.state(), &state);
        assert!(
            matches!(reopened.queue_original(&descriptor, 0, &values[0]).unwrap(), QueuedPublication::Conflict(value) if value == newer)
        );
        assert_eq!(reopened.state().queue().len(), 1);
    }
);

shared!(
    one_output_flush_unknown_and_cancelled_reply_keeps_exact_original_tail,
    {
        for mode in [1, 2] {
            let backend = TransportFaults::new();
            let (descriptor, values) = two_original_outputs();
            let mut client = Dht::new(backend.clone(), TestVerifier);
            for (subkey, value) in values.iter().enumerate() {
                client
                    .queue_original(&descriptor, subkey as u32, value)
                    .unwrap();
            }
            let before = snapshot(&client);
            *backend.mode.lock().unwrap() = mode;
            if mode == 1 {
                assert_eq!(client.flush_one().await.unwrap().remaining, 2);
            } else {
                assert!(client.flush_one().now_or_never().is_none());
            }
            assert_eq!(*backend.writes.lock().unwrap(), 1);
            assert_eq!(snapshot(&client), before);
            assert!(
                backend
                    .inner
                    .get(&descriptor.key(), 1)
                    .await
                    .unwrap()
                    .is_none()
            );
            *backend.mode.lock().unwrap() = 0;
            let state: ClientState = serde_json::from_slice(&before).unwrap();
            let mut reopened = Dht::with_state(backend.clone(), TestVerifier, state);
            assert_eq!(reopened.flush_one().await.unwrap().remaining, 1);
            assert_eq!(*backend.writes.lock().unwrap(), 2);
            assert!(
                backend
                    .inner
                    .get(&descriptor.key(), 1)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }
);

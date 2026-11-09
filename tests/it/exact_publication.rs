//! Exact semantic generations and fresh observations through original Records.
//! LocalBackend acceptance proves this owner path, not distributed replication.

use crate::common::{TestKey, TestVerifier, key};
use cdht::{
    Backend, Change, ClientState, Descriptor, Dht, EncryptionKey, Error, LocalBackend, Member,
    QueuedPublication, RecordKey, Schema, SetOutcome, SignedValue, Signer, WatchId,
};
use futures_executor::block_on;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
enum ReadFault {
    #[default]
    None,
    Missing,
    UnknownRecord,
    Replay(SignedValue),
    CorruptSignature,
}

/// All writes and successful values come from the actual validating backend.
/// Only the read reply can be withheld, replayed, or corrupted after retrieval.
#[derive(Clone)]
struct ReadFaults {
    inner: LocalBackend<TestVerifier>,
    fault: Arc<Mutex<ReadFault>>,
}
impl ReadFaults {
    fn new() -> Self {
        Self {
            inner: LocalBackend::new(TestVerifier),
            fault: Arc::new(Mutex::new(ReadFault::None)),
        }
    }
    fn set_fault(&self, fault: ReadFault) {
        *self.fault.lock().unwrap() = fault;
    }
}
impl Backend for ReadFaults {
    async fn create(&self, descriptor: &Descriptor) -> Result<(), Error> {
        self.inner.create(descriptor).await
    }
    async fn descriptor(&self, record: &RecordKey) -> Result<Option<Descriptor>, Error> {
        self.inner.descriptor(record).await
    }
    async fn get(&self, record: &RecordKey, subkey: u32) -> Result<Option<SignedValue>, Error> {
        let original = self.inner.get(record, subkey).await?;
        match self.fault.lock().unwrap().clone() {
            ReadFault::None => Ok(original),
            ReadFault::Missing => Ok(None),
            ReadFault::UnknownRecord => Err(Error::UnknownRecord),
            ReadFault::Replay(value) => Ok(Some(value)),
            ReadFault::CorruptSignature => Ok(original.map(|mut value| {
                value.signature[0] ^= 1;
                value
            })),
        }
    }
    async fn set(
        &self,
        record: &RecordKey,
        subkey: u32,
        value: &SignedValue,
    ) -> Result<SetOutcome, Error> {
        self.inner.set(record, subkey, value).await
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

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn encrypted_parts_keep_generation_seven_through_serialized_queue_reopen_and_flush() {
    block_on(async {
        let backend = LocalBackend::new(TestVerifier);
        backend.set_online(false);
        let mut client = Dht::new(backend.clone(), TestVerifier);
        let schema = Schema::dflt(3).unwrap();
        let parts: [&[u8]; 3] = [b"generation seven manifest", b"first part", b"second part"];
        let record = {
            let owner: TestKey = key(71);
            let encryption = EncryptionKey::from_bytes([19; 32]);
            let record = client.queue_create(&schema, &owner).unwrap();
            for (subkey, part) in parts.iter().enumerate() {
                assert!(matches!(
                    client
                        .queue_republish(&record, subkey as u32, 7, part, &owner, Some(&encryption))
                        .unwrap(),
                    QueuedPublication::Queued
                ));
            }
            record
        };
        let original = client.state().queue().to_vec();
        assert_eq!(original.len(), parts.len());
        for (write, plaintext) in original.iter().zip(parts) {
            assert_eq!(write.value.seq, 7);
            assert!(write.value.nonce.is_some());
            assert_ne!(write.value.data, plaintext);
        }
        let state_bytes = serde_json::to_vec(client.state()).unwrap();
        drop(client);
        let restored: ClientState = serde_json::from_slice(&state_bytes).unwrap();
        let mut reopened = Dht::with_state(backend.clone(), TestVerifier, restored);
        assert_eq!(reopened.state().queue(), original);
        let offline = reopened.flush().await.unwrap();
        assert_eq!(offline.written, 0);
        assert_eq!(offline.remaining, parts.len());
        assert_eq!(reopened.state().queue(), original);

        backend.set_online(true);
        let flushed = reopened.flush().await.unwrap();
        assert_eq!(flushed.written, parts.len());
        assert!(flushed.stale.is_empty());
        assert_eq!(flushed.remaining, 0);
        assert!(reopened.state().queue().is_empty());

        // A separate reader has no restored cache, signer, or shared Dht state.
        let mut reader = Dht::new(backend.clone(), TestVerifier);
        assert_eq!(reader.open(&record).await.unwrap(), schema);
        let encryption = EncryptionKey::from_bytes([19; 32]);
        for (subkey, part) in parts.iter().enumerate() {
            let received = reader
                .get_signed_fresh(&record, subkey as u32)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(received, original[subkey].value);
            assert_eq!(received.seq, 7);
            assert_eq!(
                reader
                    .open_value(&record, subkey as u32, &received, Some(&encryption))
                    .unwrap()
                    .as_slice(),
                *part
            );
        }
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn exact_idempotence_retains_signed_bytes_and_conflicts_do_not_mutate_the_queue() {
    let backend = LocalBackend::new(TestVerifier);
    let owner = key(72);
    let encryption = EncryptionKey::from_bytes([20; 32]);
    let mut client = Dht::new(backend, TestVerifier);
    let record = client
        .queue_create(&Schema::dflt(1).unwrap(), &owner)
        .unwrap();
    assert!(matches!(
        client
            .queue_republish(&record, 0, 7, b"seven", &owner, Some(&encryption))
            .unwrap(),
        QueuedPublication::Queued
    ));
    let original = client.state().queue()[0].value.clone();
    assert!(matches!(
        client
            .queue_republish(&record, 0, 7, b"seven", &owner, Some(&encryption))
            .unwrap(),
        QueuedPublication::Queued
    ));
    assert_eq!(
        client.state().queue()[0].value.raw_blob().unwrap(),
        original.raw_blob().unwrap()
    );
    assert_eq!(
        client.state().queue()[0].value.signature,
        original.signature
    );
    for (seq, data) in [(7, b"different".as_slice()), (6, b"seven".as_slice())] {
        let before = client.state().clone();
        let outcome = client
            .queue_republish(&record, 0, seq, data, &owner, Some(&encryption))
            .unwrap();
        let QueuedPublication::Conflict(current) = outcome else {
            panic!("expected original signed conflict");
        };
        assert_eq!(current, original);
        assert_eq!(client.state(), &before);
    }
    assert!(matches!(
        client
            .queue_republish(&record, 0, 9, b"nine", &owner, Some(&encryption))
            .unwrap(),
        QueuedPublication::Queued
    ));
    let before = client.state().clone();
    let newest = before.queue()[0].value.clone();
    let QueuedPublication::Conflict(current) = client
        .queue_republish(&record, 0, 7, b"seven", &owner, Some(&encryption))
        .unwrap()
    else {
        panic!("newer authenticated generation must win");
    };
    assert_eq!(current, newest);
    assert_eq!(client.state(), &before);
    assert_eq!(current.seq, 9);
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn exact_publication_checks_writer_sequence_subkey_and_payload_before_mutation() {
    let owner = key(73);
    let member = key(74);
    let outsider = key(75);
    let schema = Schema::new(
        1,
        vec![Member {
            writer: member.public_key(),
            subkeys: 1,
        }],
    )
    .unwrap();
    let mut client = Dht::new(LocalBackend::new(TestVerifier), TestVerifier);
    let record = client.queue_create(&schema, &owner).unwrap();
    assert!(matches!(
        client
            .queue_republish(&record, 1, 7, b"member part", &member, None)
            .unwrap(),
        QueuedPublication::Queued
    ));
    let before = client.state().clone();
    for wrong in [&owner, &outsider] {
        assert_eq!(
            client
                .queue_republish(&record, 1, 6, b"member part", wrong, None)
                .unwrap_err(),
            Error::WrongWriter
        );
        assert_eq!(client.state(), &before);
    }
    assert_eq!(
        client
            .queue_republish(&record, 0, cdht::MAX_SEQ + 1, b"too late", &owner, None)
            .unwrap_err(),
        Error::SeqExhausted
    );
    assert_eq!(client.state(), &before);
    assert_eq!(
        client
            .queue_republish(&record, 2, 7, b"outside schema", &owner, None)
            .unwrap_err(),
        Error::SubkeyOutOfRange
    );
    assert_eq!(client.state(), &before);
    assert_eq!(
        client
            .queue_republish(
                &record,
                0,
                7,
                &vec![0; cdht::MAX_SUBKEY_SIZE + 1],
                &owner,
                None
            )
            .unwrap_err(),
        Error::ValueTooLarge
    );
    assert_eq!(client.state(), &before);
    assert!(matches!(
        client
            .queue_republish(&record, 0, cdht::MAX_SEQ, b"last generation", &owner, None)
            .unwrap(),
        QueuedPublication::Queued
    ));
    assert_eq!(
        client.state().queue().last().unwrap().value.seq,
        cdht::MAX_SEQ
    );
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn fresh_reads_refuse_cached_values_on_network_loss_or_withheld_prior_value() {
    block_on(async {
        let backend = ReadFaults::new();
        let owner = key(76);
        let mut writer = Dht::new(backend.clone(), TestVerifier);
        let record = writer
            .queue_create(&Schema::dflt(2).unwrap(), &owner)
            .unwrap();
        writer
            .queue_republish(&record, 0, 7, b"known value", &owner, None)
            .unwrap();
        assert_eq!(writer.flush().await.unwrap().written, 1);
        let mut reader = Dht::new(backend.clone(), TestVerifier);
        reader.open(&record).await.unwrap();
        assert!(reader.get_signed_fresh(&record, 1).await.unwrap().is_none());
        let observed = reader.get_signed_fresh(&record, 0).await.unwrap().unwrap();
        let before = reader.state().clone();

        backend.inner.set_online(false);
        for subkey in [0, 1] {
            assert_eq!(
                reader.get_signed_fresh(&record, subkey).await.unwrap_err(),
                Error::Unavailable
            );
        }
        // The ordinary offline API really can read the cached value; the fresh
        // API's refusal is not merely an accidentally empty fixture cache.
        assert_eq!(
            reader.get_signed(&record, 0).await.unwrap().unwrap(),
            observed
        );
        assert_eq!(reader.state(), &before);
        backend.inner.set_online(true);
        for fault in [ReadFault::Missing, ReadFault::UnknownRecord] {
            backend.set_fault(fault);
            assert_eq!(
                reader.get_signed_fresh(&record, 0).await.unwrap_err(),
                Error::Unavailable
            );
            assert_eq!(reader.state(), &before);
        }
        backend.set_fault(ReadFault::None);
        assert_eq!(
            reader.get_signed_fresh(&record, 0).await.unwrap().unwrap(),
            observed
        );
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn fresh_reads_refuse_original_lower_generations_and_corrupted_signatures() {
    block_on(async {
        let backend = ReadFaults::new();
        let owner = key(77);
        let mut writer = Dht::new(backend.clone(), TestVerifier);
        let record = writer
            .queue_create(&Schema::dflt(1).unwrap(), &owner)
            .unwrap();
        writer
            .queue_republish(&record, 0, 6, b"older", &owner, None)
            .unwrap();
        assert_eq!(writer.flush().await.unwrap().written, 1);
        let older = backend.inner.get(&record, 0).await.unwrap().unwrap();
        writer
            .queue_republish(&record, 0, 7, b"current", &owner, None)
            .unwrap();
        assert_eq!(writer.flush().await.unwrap().written, 1);
        let mut reader = Dht::new(backend.clone(), TestVerifier);
        reader.open(&record).await.unwrap();
        let current = reader.get_signed_fresh(&record, 0).await.unwrap().unwrap();
        assert_eq!(current.seq, 7);
        let before = reader.state().clone();
        backend.set_fault(ReadFault::Replay(older));
        assert_eq!(
            reader.get_signed_fresh(&record, 0).await.unwrap_err(),
            Error::Conflict
        );
        assert_eq!(reader.state(), &before);
        backend.set_fault(ReadFault::CorruptSignature);
        assert_eq!(
            reader.get_signed_fresh(&record, 0).await.unwrap_err(),
            Error::BadSignature
        );
        assert_eq!(reader.state(), &before);
        backend.set_fault(ReadFault::None);
        assert_eq!(
            reader.get_signed_fresh(&record, 0).await.unwrap().unwrap(),
            current
        );
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn equal_generation_fresh_observation_retains_pending_work_and_fences_republication() {
    block_on(async {
        let backend = LocalBackend::new(TestVerifier);
        let owner = key(78);
        let encryption = EncryptionKey::from_bytes([21; 32]);
        let schema = Schema::dflt(1).unwrap();
        let mut remote_writer = Dht::new(backend.clone(), TestVerifier);
        let record = remote_writer.queue_create(&schema, &owner).unwrap();
        remote_writer
            .queue_republish(&record, 0, 7, b"remote B", &owner, Some(&encryption))
            .unwrap();
        assert_eq!(remote_writer.flush().await.unwrap().written, 1);
        let remote = backend.get(&record, 0).await.unwrap().unwrap();

        let mut local = Dht::new(backend, TestVerifier);
        assert_eq!(local.queue_create(&schema, &owner).unwrap(), record);
        local
            .queue_republish(&record, 0, 7, b"pending A", &owner, Some(&encryption))
            .unwrap();
        let original_queue = local.state().queue().to_vec();
        assert_ne!(original_queue[0].value, remote);

        let observed = local.get_signed_fresh(&record, 0).await.unwrap().unwrap();
        assert_eq!(observed, remote);
        assert_eq!(local.state().queue(), original_queue);
        assert_eq!(
            local
                .open_value(&record, 0, &observed, Some(&encryption))
                .unwrap()
                .as_slice(),
            b"remote B"
        );
        let before_retry = local.state().clone();
        let QueuedPublication::Conflict(conflict) = local
            .queue_republish(&record, 0, 7, b"pending A", &owner, Some(&encryption))
            .unwrap()
        else {
            panic!("authenticated equal-generation remote value must fence the retry");
        };
        assert_eq!(conflict, remote);
        assert_eq!(local.state(), &before_retry);
        assert_eq!(local.state().queue(), original_queue);

        let serialized = serde_json::to_vec(local.state()).unwrap();
        let backend = local.backend().clone();
        drop(local);
        let state: ClientState = serde_json::from_slice(&serialized).unwrap();
        let mut reopened = Dht::with_state(backend, TestVerifier, state);
        assert_eq!(reopened.state(), &before_retry);
        assert_eq!(reopened.state().queue(), original_queue);
        assert_eq!(
            reopened.state().queue()[0].value.raw_blob().unwrap(),
            original_queue[0].value.raw_blob().unwrap()
        );
        assert_eq!(
            reopened.state().queue()[0].value.signature,
            original_queue[0].value.signature
        );
        // No network read occurs before this retry. The restored authenticated
        // observation B must still fence A, while A's original obligation stays.
        let QueuedPublication::Conflict(conflict) = reopened
            .queue_republish(&record, 0, 7, b"pending A", &owner, Some(&encryption))
            .unwrap()
        else {
            panic!("restoring the pending queue must retain the observed conflict");
        };
        assert_eq!(conflict, remote);
        assert_eq!(reopened.state(), &before_retry);
        let report = reopened.flush().await.unwrap();
        assert_eq!(report.written, 0);
        assert_eq!(report.stale, vec![(record, 0)]);
        assert_eq!(report.remaining, 0);
        assert!(reopened.state().queue().is_empty());
        assert_eq!(
            reopened
                .get_signed_fresh(&record, 0)
                .await
                .unwrap()
                .unwrap(),
            remote
        );
        // Empty after an authenticated stale result is not publication of A.
        // The enclosing runtime must reconcile its expected publication content.
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn equal_generation_identical_plaintext_reuses_the_fresh_remote_ciphertext() {
    block_on(async {
        let backend = LocalBackend::new(TestVerifier);
        let owner = key(79);
        let encryption = EncryptionKey::from_bytes([22; 32]);
        let schema = Schema::dflt(1).unwrap();
        let mut remote_writer = Dht::new(backend.clone(), TestVerifier);
        let record = remote_writer.queue_create(&schema, &owner).unwrap();
        remote_writer
            .queue_republish(&record, 0, 7, b"identical", &owner, Some(&encryption))
            .unwrap();
        assert_eq!(remote_writer.flush().await.unwrap().written, 1);
        let remote = backend.get(&record, 0).await.unwrap().unwrap();

        let mut local = Dht::new(backend, TestVerifier);
        local.queue_create(&schema, &owner).unwrap();
        local
            .queue_republish(&record, 0, 7, b"identical", &owner, Some(&encryption))
            .unwrap();
        let originally_queued = local.state().queue()[0].value.clone();
        assert_ne!(originally_queued.nonce, remote.nonce);
        assert_eq!(
            local.get_signed_fresh(&record, 0).await.unwrap().unwrap(),
            remote
        );
        assert_eq!(local.state().queue()[0].value, originally_queued);
        let before_reopen = local.state().clone();
        let serialized = serde_json::to_vec(&before_reopen).unwrap();
        let backend = local.backend().clone();
        drop(local);
        let state: ClientState = serde_json::from_slice(&serialized).unwrap();
        let mut local = Dht::with_state(backend, TestVerifier, state);
        assert_eq!(local.state(), &before_reopen);
        assert_eq!(local.state().queue()[0].value, originally_queued);
        // Preparation can now establish plaintext idempotence with the retained
        // observation, reusing its original nonce/signature without renumbering.
        assert!(matches!(
            local
                .queue_republish(&record, 0, 7, b"identical", &owner, Some(&encryption))
                .unwrap(),
            QueuedPublication::Queued
        ));
        assert_eq!(local.state().queue()[0].value, remote);
        assert_eq!(local.state().queue()[0].value.seq, 7);
        let report = local.flush().await.unwrap();
        assert_eq!(report.written, 1);
        assert!(report.stale.is_empty());
        assert_eq!(report.remaining, 0);
        assert_eq!(
            local.get_signed_fresh(&record, 0).await.unwrap().unwrap(),
            remote
        );
    });
}

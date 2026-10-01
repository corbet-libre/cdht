//! Independent node stores exercise real fanout, signatures, capacity and churn.
mod common;
#[path = "common/network.rs"]
mod simulation;
use cdht::{
    Backend, Capacity, Dht, Error, LocalBackend, MAX_WATCH_MS, NetworkBackend, Schema, SignedValue,
    Signer, WriteOutcome,
};
use common::{TestVerifier, key};
use futures_executor::block_on;
use simulation::SimNetwork;

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn five_closest_copies_three_read_agreement_and_partial_evidence() {
    block_on(async {
        let network = SimNetwork::new(50, Capacity::NATIVE);
        let owner = key(1);
        let mut dht = Dht::new(
            NetworkBackend::new(network.clone(), TestVerifier),
            TestVerifier,
        );
        let record = dht.create(&Schema::dflt(1).unwrap(), &owner).await.unwrap();
        assert_eq!(
            dht.set(&record, 0, b"hello", &owner, None).await.unwrap(),
            WriteOutcome::Written { seq: 0 }
        );
        let holders: Vec<_> = (0..50)
            .filter(|i| network.store(*i).usage().0 > 0)
            .collect();
        assert_eq!(holders.len(), 5);
        let mut distances: Vec<_> = (0..50)
            .map(|i| {
                let mut distance = network.id(i);
                for (d, k) in distance.iter_mut().zip(record.0) {
                    *d ^= k;
                }
                (distance, i)
            })
            .collect();
        distances.sort();
        assert!(distances[..5].iter().all(|(_, i)| holders.contains(i)));
        let report = dht.backend().read(&record, 0).await.unwrap();
        assert!(report.has_consensus());
        assert_eq!(report.agreement, 3);
        for i in &holders[..4] {
            network.online(*i, false);
        }
        let report = dht.backend().read(&record, 0).await.unwrap();
        assert!(!report.has_consensus());
        assert_eq!(report.agreement, 1);
        assert_eq!(report.value.unwrap().data, b"hello");
        network.online(holders[4], false);
        let report = dht.backend().read(&record, 0).await.unwrap();
        assert!(report.value.is_none());
        assert_eq!(report.agreement, 0);
        for i in 0..50 {
            network.online(i, false);
        }
        assert_eq!(
            dht.backend().read(&record, 0).await.unwrap_err(),
            Error::Unavailable
        );
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn owner_rehydrates_after_all_remote_copies_are_lost_without_resigning() {
    block_on(async {
        let network = SimNetwork::new(30, Capacity::NATIVE);
        let owner = key(1);
        let mut dht = Dht::new(
            NetworkBackend::new(network.clone(), TestVerifier),
            TestVerifier,
        );
        let record = dht.create(&Schema::dflt(1).unwrap(), &owner).await.unwrap();
        dht.set(&record, 0, b"recover", &owner, None).await.unwrap();
        let before = dht.get_signed(&record, 0).await.unwrap().unwrap();
        let state = dht.state().clone();
        for i in 0..30 {
            network.replace(i);
        }
        let mut restored = Dht::with_state(
            NetworkBackend::new(network.clone(), TestVerifier),
            TestVerifier,
            state,
        );
        restored.open(&record).await.unwrap();
        let after = restored.backend().read(&record, 0).await.unwrap();
        assert!(after.has_consensus());
        assert_eq!(before, after.value.unwrap());
        assert_eq!(
            (0..30).filter(|i| network.store(*i).usage().0 > 0).count(),
            5
        );
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn rehydration_requires_an_answer_and_does_not_treat_silence_as_absence() {
    block_on(async {
        let network = SimNetwork::new(20, Capacity::NATIVE);
        let owner = key(1);
        let mut client = Dht::new(
            NetworkBackend::new(network.clone(), TestVerifier),
            TestVerifier,
        );
        let record = client
            .create(&Schema::dflt(1).unwrap(), &owner)
            .await
            .unwrap();
        client
            .set(&record, 0, b"retained", &owner, None)
            .await
            .unwrap();
        let original = client.get_signed(&record, 0).await.unwrap().unwrap();
        let state = client.state().clone();
        for i in 0..20 {
            network.replace(i);
        }
        // Discovery and writes still work, but no node answers the inspection.
        network.silence_reads(true);
        let mut client = Dht::with_state(
            NetworkBackend::new(network.clone(), TestVerifier),
            TestVerifier,
            state,
        );
        client.open(&record).await.unwrap();
        assert!(client.state().queue().is_empty());
        assert_eq!(client.flush().await.unwrap().written, 0);
        assert!((0..20).all(|i| network.store(i).usage().0 == 0));
        network.silence_reads(false);
        client.open(&record).await.unwrap();
        assert!(client.state().queue().is_empty());
        assert_eq!(
            client.backend().read(&record, 0).await.unwrap().value,
            Some(original)
        );
        assert_eq!(
            (0..20).filter(|i| network.store(*i).usage().0 > 0).count(),
            5
        );
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn small_population_queues_until_five_nodes_are_available() {
    block_on(async {
        let network = SimNetwork::new(8, Capacity::NATIVE);
        for i in 3..8 {
            network.online(i, false);
        }
        let owner = key(1);
        let mut dht = Dht::new(
            NetworkBackend::new(network.clone(), TestVerifier),
            TestVerifier,
        );
        let record = dht.create(&Schema::dflt(1).unwrap(), &owner).await.unwrap();
        assert_eq!(
            dht.set(&record, 0, b"pending", &owner, None).await.unwrap(),
            WriteOutcome::Queued { seq: 0 }
        );
        assert_eq!(dht.flush().await.unwrap().remaining, 1);
        for i in 3..8 {
            network.online(i, true);
        }
        assert_eq!(dht.flush().await.unwrap().written, 1);
        assert!(
            dht.backend()
                .read(&record, 0)
                .await
                .unwrap()
                .has_consensus()
        );
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn capacity_uses_lru_and_no_record_ttl() {
    block_on(async {
        let node = LocalBackend::with_capacity(
            TestVerifier,
            Capacity {
                records: 2,
                bytes: 10_000,
            },
        );
        let mut dht = Dht::new(node.clone(), TestVerifier);
        let a = dht
            .create(&Schema::dflt(1).unwrap(), &key(1))
            .await
            .unwrap();
        let b = dht
            .create(&Schema::dflt(1).unwrap(), &key(2))
            .await
            .unwrap();
        node.descriptor(&a).await.unwrap();
        let c = dht
            .create(&Schema::dflt(1).unwrap(), &key(3))
            .await
            .unwrap();
        assert!(node.descriptor(&b).await.unwrap().is_none());
        assert!(node.descriptor(&a).await.unwrap().is_some());
        assert!(node.descriptor(&c).await.unwrap().is_some());
        node.advance_to(365 * 24 * 60 * 60 * 1000);
        assert!(node.descriptor(&a).await.unwrap().is_some());
        assert_eq!(node.usage().2, 1);
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn watch_leases_counts_quotas_and_loss_are_observable() {
    block_on(async {
        let node = LocalBackend::new(TestVerifier);
        let owner = key(1);
        let mut dht = Dht::new(node.clone(), TestVerifier);
        let record = dht.create(&Schema::dflt(1).unwrap(), &owner).await.unwrap();
        let watch = node.watch_for(&record, MAX_WATCH_MS, 1).unwrap();
        dht.set(&record, 0, b"one", &owner, None).await.unwrap();
        assert_eq!(node.changes(watch).await.unwrap().len(), 1);
        assert_eq!(node.changes(watch).await.unwrap_err(), Error::UnknownWatch);
        let watch = node.watch(&record).await.unwrap();
        node.advance_to(MAX_WATCH_MS - 1);
        node.renew_watch(watch, MAX_WATCH_MS).unwrap();
        node.advance_to(MAX_WATCH_MS + 1);
        assert!(node.changes(watch).await.unwrap().is_empty());
        node.advance_to(2 * MAX_WATCH_MS);
        assert_eq!(node.changes(watch).await.unwrap_err(), Error::UnknownWatch);
        for _ in 0..32 {
            node.watch(&record).await.unwrap();
        }
        assert_eq!(node.watch(&record).await.unwrap_err(), Error::Unavailable);
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn max_sequence_and_unchanged_plaintext_follow_upstream() {
    block_on(async {
        let node = LocalBackend::new(TestVerifier);
        let owner = key(1);
        let mut dht = Dht::new(node.clone(), TestVerifier);
        let record = dht.create(&Schema::dflt(1).unwrap(), &owner).await.unwrap();
        assert!(dht.get(&record, 0, None).await.unwrap().is_none());
        dht.set(&record, 0, b"same", &owner, None).await.unwrap();
        assert_eq!(
            dht.set(&record, 0, b"same", &owner, None).await.unwrap(),
            WriteOutcome::Written { seq: 0 }
        );
        let value = SignedValue::sign(
            &owner.public_key(),
            0,
            cdht::MAX_SEQ,
            b"final".to_vec(),
            &owner,
        )
        .unwrap();
        node.set(&record, 0, &value).await.unwrap();
        dht.get(&record, 0, None).await.unwrap();
        assert_eq!(
            dht.set(&record, 0, b"changed", &owner, None)
                .await
                .unwrap_err(),
            Error::SeqExhausted
        );
        assert_eq!(
            dht.set(&record, 0, b"final", &owner, None).await.unwrap(),
            WriteOutcome::Written { seq: cdht::MAX_SEQ }
        );
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn byte_capacity_evicts_records_and_rejects_a_single_oversized_record() {
    block_on(async {
        let node = LocalBackend::with_capacity(
            TestVerifier,
            Capacity {
                records: 100,
                bytes: 500,
            },
        );
        let mut dht = Dht::new(node.clone(), TestVerifier);
        let a = key(1);
        let b = key(2);
        let first = dht.create(&Schema::dflt(1).unwrap(), &a).await.unwrap();
        dht.set(&first, 0, &[1; 150], &a, None).await.unwrap();
        let second = dht.create(&Schema::dflt(1).unwrap(), &b).await.unwrap();
        dht.set(&second, 0, &[2; 150], &b, None).await.unwrap();
        assert!(node.descriptor(&first).await.unwrap().is_none());
        assert!(node.usage().1 <= 500);
        assert!(matches!(
            dht.set(&second, 0, &[3; 501], &b, None).await.unwrap(),
            WriteOutcome::Queued { .. }
        ));
        assert_eq!(
            node.get(&second, 0).await.unwrap().unwrap().data,
            vec![2; 150]
        );
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn unchanged_encrypted_write_reuses_sequence_and_reports_success() {
    block_on(async {
        let node = LocalBackend::new(TestVerifier);
        let owner = key(1);
        let secret = cdht::EncryptionKey::from_bytes([42; 32]);
        let mut dht = Dht::new(node.clone(), TestVerifier);
        let record = dht.create(&Schema::dflt(1).unwrap(), &owner).await.unwrap();
        dht.set(&record, 0, b"same", &owner, Some(&secret))
            .await
            .unwrap();
        let original = node.get(&record, 0).await.unwrap().unwrap();
        assert_eq!(
            dht.set(&record, 0, b"same", &owner, Some(&secret))
                .await
                .unwrap(),
            WriteOutcome::Written { seq: 0 }
        );
        assert_eq!(node.get(&record, 0).await.unwrap().unwrap(), original);
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn fresh_device_restores_sealed_state_and_offline_messages_without_the_old_device() {
    block_on(async {
        use cdht::{Descriptor, EncryptionKey, Member};
        let network = SimNetwork::new(20, Capacity::NATIVE);
        // Credential/key ports supply the same purpose signer and read capability
        // after synced-passkey unlock; this leaf does not implement WebAuthn/PRF.
        let owner = key(1);
        let sender = key(2);
        let secret = EncryptionKey::from_bytes([42; 32]);
        let schema = Schema::new(
            1,
            vec![Member {
                writer: sender.public_key(),
                subkeys: 1,
            }],
        )
        .unwrap();
        let mut old_device = Dht::new(
            NetworkBackend::new(network.for_node(0), TestVerifier),
            TestVerifier,
        );
        let record = old_device.create(&schema, &owner).await.unwrap();
        old_device
            .set(
                &record,
                0,
                b"committed contacts and history",
                &owner,
                Some(&secret),
            )
            .await
            .unwrap();
        let full_key = secret.record_key(&record);
        drop(old_device);
        network.online(0, false);

        let mut writer = Dht::new(
            NetworkBackend::new(network.for_node(2), TestVerifier),
            TestVerifier,
        );
        writer.open(&record).await.unwrap();
        writer
            .set(
                &record,
                1,
                b"message while recipient is away",
                &sender,
                Some(&secret),
            )
            .await
            .unwrap();
        let (restored_locator, restored_secret) =
            EncryptionKey::parse_record_key(&full_key).unwrap();
        let mut fresh = Dht::new(
            NetworkBackend::new(network.for_node(19), TestVerifier),
            TestVerifier,
        );
        fresh.open(&restored_locator).await.unwrap();
        assert_eq!(
            fresh
                .get(
                    &record,
                    0,
                    restored_secret
                        .as_ref()
                        .map(|cipher| cipher as &dyn cdht::RecordCipher)
                )
                .await
                .unwrap()
                .unwrap()
                .as_slice(),
            b"committed contacts and history"
        );
        assert_eq!(
            fresh
                .get(
                    &record,
                    1,
                    restored_secret
                        .as_ref()
                        .map(|cipher| cipher as &dyn cdht::RecordCipher)
                )
                .await
                .unwrap()
                .unwrap()
                .as_slice(),
            b"message while recipient is away"
        );
        assert_eq!(
            Descriptor::create(&schema, &key(1)).unwrap().key(),
            restored_locator
        );

        for i in 0..20 {
            network.replace(i);
        }
        let mut empty = Dht::new(NetworkBackend::new(network, TestVerifier), TestVerifier);
        assert_eq!(empty.open(&record).await.unwrap_err(), Error::UnknownRecord);
        // Missing replicas do not authorize creating a different identity or locator.
        assert_eq!(Descriptor::create(&schema, &key(1)).unwrap().key(), record);
    });
}

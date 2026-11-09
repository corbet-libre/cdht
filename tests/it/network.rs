//! Independent node stores exercise real fanout, signatures, capacity and churn.
#[path = "../common/network.rs"]
mod simulation;
use crate::common::{TestVerifier, key};
use cdht::{
    Backend, Capacity, Dht, Error, LocalBackend, MAX_WATCH_MS, NetworkBackend, Schema, SignedValue,
    Signer, WriteOutcome,
};
use futures_executor::block_on;
use simulation::SimNetwork;

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn record_responses_extend_the_same_fanout_without_counting_hints_as_holders() {
    block_on(async {
        let network = SimNetwork::new(5, Capacity::NATIVE);
        network.discover_progressively();
        let owner = key(59);
        let mut writer = Dht::new(
            NetworkBackend::new(network.clone(), TestVerifier),
            TestVerifier,
        );
        let key = writer
            .create(&Schema::dflt(1).unwrap(), &owner)
            .await
            .unwrap();
        assert_eq!(
            writer.set(&key, 0, b"dynamic", &owner, None).await.unwrap(),
            WriteOutcome::Written { seq: 0 }
        );
        assert!((0..5).all(|index| network.store(index).usage().0 == 1));
        network.discover_progressively();
        let reader = NetworkBackend::new(network.clone(), TestVerifier);
        assert!(reader.descriptor(&key).await.unwrap().is_some());
        let report = reader.read(&key, 0).await.unwrap();
        assert!(report.has_consensus());
        assert_eq!((report.agreement, report.contacted), (3, 3));
        assert_eq!(report.value.unwrap().data, b"dynamic");
        // Discovery alone does not supply the missing fifth stored copy.
        network.online(4, false);
        network.discover_progressively();
        assert_eq!(
            writer.set(&key, 0, b"pending", &owner, None).await.unwrap(),
            WriteOutcome::Queued { seq: 1 }
        );
    });
}

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
        // after owner-authorized root recovery; this fixture does not prove the
        // separate PRF-wrapped common-root lookup or implement WebAuthn.
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

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn network_watches_keep_holder_identity_cancel_and_surface_lease_loss() {
    block_on(async {
        let network = SimNetwork::new(8, Capacity::NATIVE);
        let owner = key(31);
        let mut client = Dht::new(
            NetworkBackend::new(network.clone(), TestVerifier),
            TestVerifier,
        );
        let record = client
            .create(&Schema::dflt(2).unwrap(), &owner)
            .await
            .unwrap();
        client
            .set(&record, 0, b"first", &owner, None)
            .await
            .unwrap();
        let watch = client.backend().watch(&record).await.unwrap();
        assert!(client.backend().changes(watch).await.unwrap().is_empty());
        client
            .set(&record, 0, b"second", &owner, None)
            .await
            .unwrap();
        client
            .set(&record, 0, b"third", &owner, None)
            .await
            .unwrap();
        let changes = client.backend().changes(watch).await.unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].key, record);
        assert_eq!(changes[0].subkey, 0);
        assert_eq!(changes[0].seq, 2);
        client.backend().cancel_watch(watch).await.unwrap();
        client.backend().cancel_watch(watch).await.unwrap();
        assert_eq!(
            client.backend().changes(watch).await.unwrap_err(),
            Error::UnknownWatch
        );
        let watch = client.backend().watch(&record).await.unwrap();
        network.advance_to(MAX_WATCH_MS);
        assert_eq!(
            client.backend().changes(watch).await.unwrap_err(),
            Error::UnknownWatch
        );
        client.backend().cancel_watch(watch).await.unwrap();
        // Every holder uses the real store's quota, so the fanout must exhaust
        // its actual failed candidates rather than claim a subscription.
        for i in 0..8 {
            if network
                .store(i)
                .descriptor(&record)
                .await
                .unwrap()
                .is_some()
            {
                for _ in 0..32 {
                    network.store(i).watch(&record).await.unwrap();
                }
            }
        }
        assert_eq!(
            client.backend().watch(&record).await.unwrap_err(),
            Error::Unavailable
        );
        assert_eq!(client.backend().network().evictions(), 0);
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn cached_owner_rehydration_retains_newer_signed_network_data() {
    block_on(async {
        let network = SimNetwork::new(5, Capacity::NATIVE);
        let owner = key(32);
        let mut client = Dht::new(
            NetworkBackend::new(network.clone(), TestVerifier),
            TestVerifier,
        );
        let record = client
            .create(&Schema::dflt(1).unwrap(), &owner)
            .await
            .unwrap();
        client.set(&record, 0, b"old", &owner, None).await.unwrap();
        let old = client.get_signed(&record, 0).await.unwrap().unwrap();
        assert!(matches!(
            client.backend().rehydrate(&record, 0, &old).await.unwrap(),
            cdht::SetOutcome::Accepted
        ));
        assert!(matches!(
            client.backend().rehydrate(&record, 0, &old).await.unwrap(),
            cdht::SetOutcome::Accepted
        ));
        let newer =
            SignedValue::sign(&owner.public_key(), 0, 1, b"newer".to_vec(), &owner).unwrap();
        for i in 0..5 {
            network.store(i).set(&record, 0, &newer).await.unwrap();
        }
        network.advance_to(300_000);
        assert!(
            matches!(client.backend().rehydrate(&record, 0, &old).await.unwrap(), cdht::SetOutcome::Newer(value) if value == newer)
        );
        let mut restored = Dht::new(
            NetworkBackend::new(network.clone(), TestVerifier),
            TestVerifier,
        );
        restored.open(&record).await.unwrap();
        assert_eq!(restored.get_signed(&record, 0).await.unwrap(), Some(newer));
        assert_eq!(
            restored.backend().read(&record, 1).await.unwrap_err(),
            Error::SubkeyOutOfRange
        );
        let missing = cdht::Descriptor::create(&Schema::dflt(1).unwrap(), &key(33))
            .unwrap()
            .key();
        assert!(
            restored
                .backend()
                .descriptor(&missing)
                .await
                .unwrap()
                .is_none()
        );
        let empty = NetworkBackend::new(SimNetwork::new(0, Capacity::NATIVE), TestVerifier);
        assert_eq!(
            empty.descriptor(&missing).await.unwrap_err(),
            Error::Unavailable
        );
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn divergent_real_holders_converge_without_resigning_the_newest_ciphertext() {
    block_on(async {
        let network = SimNetwork::new(5, Capacity::NATIVE);
        let backend = NetworkBackend::new(network.clone(), TestVerifier);
        let owner = key(47);
        let descriptor = cdht::Descriptor::create(&Schema::dflt(1).unwrap(), &owner).unwrap();
        let record = descriptor.key();
        backend.create(&descriptor).await.unwrap();
        let secret = cdht::EncryptionKey::from_bytes([48; 32]);
        let mut values = Vec::new();
        for seq in 0..2 {
            let nonce = [seq as u8; 24];
            values.push(
                SignedValue::sign_with_nonce(
                    &owner.public_key(),
                    0,
                    seq,
                    secret
                        .crypt(&nonce, b"retained ciphertext")
                        .unwrap()
                        .to_vec(),
                    Some(nonce),
                    &owner,
                )
                .unwrap(),
            );
        }
        for i in 0..5 {
            let store = network.store(i);
            store.create(&descriptor).await.unwrap();
            store.set(&record, 0, &values[0]).await.unwrap();
        }
        let mut order: Vec<_> = (0..5).collect();
        order.sort_by_key(|i| {
            let mut distance = network.id(*i);
            for (part, coordinate) in distance.iter_mut().zip(record.0) {
                *part ^= coordinate;
            }
            distance
        });
        let nearest = order[1];
        network
            .store(nearest)
            .set(&record, 0, &values[1])
            .await
            .unwrap();
        let observed = backend.read(&record, 0).await.unwrap();
        assert_eq!(observed.value, Some(values[1].clone()));
        assert_eq!(observed.agreement, 1);
        assert!(!observed.has_consensus());
        assert_eq!(observed.contacted, 5);
        // Real storage refuses the stale write. Fanout must preserve the actual
        // returned higher value, not manufacture a replacement signature/nonce.
        assert!(matches!(
            backend.set(&record, 0, &values[0]).await.unwrap(),
            cdht::SetOutcome::Newer(value) if value == values[1]
        ));
        for i in 0..5 {
            assert_eq!(
                network.store(i).get(&record, 0).await.unwrap(),
                Some(values[1].clone())
            );
        }
        assert!(backend.read(&record, 0).await.unwrap().has_consensus());
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn concurrent_equal_sequence_holders_never_manufacture_a_winner() {
    block_on(async {
        let network = SimNetwork::new(5, Capacity::NATIVE);
        let owner = key(50);
        let descriptor = cdht::Descriptor::create(&Schema::dflt(1).unwrap(), &owner).unwrap();
        let record = descriptor.key();
        let backend = NetworkBackend::new(network.clone(), TestVerifier);
        backend.create(&descriptor).await.unwrap();
        let mut order: Vec<_> = (0..5).collect();
        order.sort_by_key(|i| {
            let mut distance = network.id(*i);
            for (part, coordinate) in distance.iter_mut().zip(record.0) {
                *part ^= coordinate;
            }
            distance
        });
        let left = SignedValue::sign(&descriptor.owner, 0, 0, b"left".to_vec(), &owner).unwrap();
        let right = SignedValue::sign(&descriptor.owner, 0, 0, b"right".to_vec(), &owner).unwrap();
        for i in 0..5 {
            network.store(i).create(&descriptor).await.unwrap();
        }
        network
            .store(order[0])
            .set(&record, 0, &left)
            .await
            .unwrap();
        network
            .store(order[1])
            .set(&record, 0, &right)
            .await
            .unwrap();
        assert_eq!(
            backend.set(&record, 0, &left).await.unwrap_err(),
            Error::Unavailable
        );
        assert_eq!(
            network.store(order[0]).get(&record, 0).await.unwrap(),
            Some(left)
        );
        assert_eq!(
            network.store(order[1]).get(&record, 0).await.unwrap(),
            Some(right)
        );
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn discovered_but_offline_stores_do_not_acknowledge_writes_or_absence() {
    block_on(async {
        let network = SimNetwork::new(5, Capacity::NATIVE);
        let owner = key(51);
        let descriptor = cdht::Descriptor::create(&Schema::dflt(1).unwrap(), &owner).unwrap();
        let record = descriptor.key();
        let backend = NetworkBackend::new(network.clone(), TestVerifier);
        backend.create(&descriptor).await.unwrap();
        let value = SignedValue::sign(&descriptor.owner, 0, 0, vec![], &owner).unwrap();
        for i in 0..5 {
            network.store(i).set_online(false);
        }
        let fresh = NetworkBackend::new(network.clone(), TestVerifier);
        assert_eq!(
            fresh.descriptor(&record).await.unwrap_err(),
            Error::Unavailable
        );
        assert_eq!(
            backend.set(&record, 0, &value).await.unwrap_err(),
            Error::Unavailable
        );
        // One genuinely reachable empty store establishes an answered inspection,
        // but cannot satisfy the five-holder write target during rehydration.
        network.store(0).set_online(true);
        assert!(!backend.read(&record, 0).await.unwrap().has_consensus());
        assert_eq!(
            backend.rehydrate(&record, 0, &value).await.unwrap_err(),
            Error::Unavailable
        );
        assert_eq!(network.store(0).get(&record, 0).await.unwrap(), Some(value));
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn corrupted_transport_replies_cannot_replace_real_records_or_authorize_hints() {
    block_on(async {
        let network = SimNetwork::new(5, Capacity::NATIVE);
        let owner = key(52);
        let descriptor = cdht::Descriptor::create(&Schema::dflt(1).unwrap(), &owner).unwrap();
        let record = descriptor.key();
        let backend = NetworkBackend::new(network.clone(), TestVerifier);
        backend.create(&descriptor).await.unwrap();
        let old = SignedValue::sign(&descriptor.owner, 0, 0, b"old".to_vec(), &owner).unwrap();
        let current =
            SignedValue::sign(&descriptor.owner, 0, 1, b"current".to_vec(), &owner).unwrap();
        for i in 0..5 {
            network.store(i).create(&descriptor).await.unwrap();
            network.store(i).set(&record, 0, &current).await.unwrap();
        }
        network.corrupt_record_replies(true, true);
        let fresh = NetworkBackend::new(network.clone(), TestVerifier);
        assert_eq!(
            fresh.descriptor(&record).await.unwrap_err(),
            Error::Unavailable
        );
        assert_eq!(
            backend.read(&record, 0).await.unwrap_err(),
            Error::Unavailable
        );
        assert_eq!(
            backend.set(&record, 0, &old).await.unwrap_err(),
            Error::Unavailable
        );
        for i in 0..5 {
            assert_eq!(
                network.store(i).get(&record, 0).await.unwrap(),
                Some(current.clone())
            );
        }
        network.corrupt_record_replies(false, false);
        assert_eq!(
            fresh.descriptor(&record).await.unwrap(),
            Some(descriptor.clone())
        );
        for mode in 1..=4 {
            let watch = backend.watch(&record).await.unwrap();
            let value = SignedValue::sign(
                &descriptor.owner,
                0,
                1 + u32::from(mode),
                vec![mode],
                &owner,
            )
            .unwrap();
            backend.set(&record, 0, &value).await.unwrap();
            network.corrupt_change_replies(mode);
            assert_eq!(backend.changes(watch).await.unwrap_err(), Error::Encoding);
            backend.cancel_watch(watch).await.unwrap();
        }
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn a_higher_local_sequence_is_not_skipped_by_an_older_successful_inspection() {
    block_on(async {
        let network = SimNetwork::new(5, Capacity::NATIVE);
        let owner = key(53);
        let descriptor = cdht::Descriptor::create(&Schema::dflt(1).unwrap(), &owner).unwrap();
        let record = descriptor.key();
        let backend = NetworkBackend::new(network.clone(), TestVerifier);
        backend.create(&descriptor).await.unwrap();
        let old = SignedValue::sign(&descriptor.owner, 0, 0, vec![0], &owner).unwrap();
        backend.set(&record, 0, &old).await.unwrap();
        backend.rehydrate(&record, 0, &old).await.unwrap();
        let new = SignedValue::sign(&descriptor.owner, 0, 1, vec![1], &owner).unwrap();
        backend.rehydrate(&record, 0, &new).await.unwrap();
        for i in 0..5 {
            assert_eq!(
                network.store(i).get(&record, 0).await.unwrap(),
                Some(new.clone())
            );
        }
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn storage_refuses_impossible_capacity_and_empty_watch_requests() {
    block_on(async {
        let descriptor = cdht::Descriptor::create(&Schema::dflt(1).unwrap(), &key(34)).unwrap();
        for capacity in [
            Capacity {
                records: 0,
                bytes: 1024,
            },
            Capacity {
                records: 1,
                bytes: 95,
            },
        ] {
            let store = LocalBackend::with_capacity(TestVerifier, capacity);
            assert_eq!(
                store.create(&descriptor).await.unwrap_err(),
                Error::Unavailable
            );
            assert_eq!(store.usage().0, 0);
        }
        let store = LocalBackend::new(TestVerifier);
        let record = descriptor.key();
        assert_eq!(
            store.watch_for(&record, 1, 1).unwrap_err(),
            Error::UnknownRecord
        );
        store.create(&descriptor).await.unwrap();
        assert_eq!(
            store.watch_for(&record, 0, 1).unwrap_err(),
            Error::Unavailable
        );
        assert_eq!(
            store.watch_for(&record, 1, 0).unwrap_err(),
            Error::Unavailable
        );
        let watch = store.watch_for(&record, 1, 1).unwrap();
        assert_eq!(
            store.renew_watch(watch, 0).unwrap_err(),
            Error::UnknownWatch
        );
        assert_eq!(
            store.get(&record, 1).await.unwrap_err(),
            Error::SubkeyOutOfRange
        );
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn refused_first_value_keeps_descriptor_and_watch_notifications_separate() {
    block_on(async {
        let store = LocalBackend::with_capacity(
            TestVerifier,
            Capacity {
                records: 2,
                bytes: 600,
            },
        );
        let owner = key(35);
        let other = key(36);
        let mut client = Dht::new(store.clone(), TestVerifier);
        let first = client
            .create(&Schema::dflt(1).unwrap(), &owner)
            .await
            .unwrap();
        let second = client
            .create(&Schema::dflt(1).unwrap(), &other)
            .await
            .unwrap();
        let first_watch = store.watch(&first).await.unwrap();
        let second_watch = store.watch(&second).await.unwrap();
        let oversized = SignedValue::sign(&owner.public_key(), 0, 0, vec![9; 600], &owner).unwrap();
        assert_eq!(
            store.set(&first, 0, &oversized).await.unwrap_err(),
            Error::Unavailable
        );
        assert!(store.get(&first, 0).await.unwrap().is_none());
        assert!(store.descriptor(&first).await.unwrap().is_some());
        assert!(store.changes(first_watch).await.unwrap().is_empty());
        assert!(store.changes(second_watch).await.unwrap().is_empty());
        client.set(&first, 0, b"fits", &owner, None).await.unwrap();
        assert_eq!(store.changes(first_watch).await.unwrap().len(), 1);
        assert!(store.changes(second_watch).await.unwrap().is_empty());
        store.cancel_watch(first_watch).await.unwrap();
        assert_eq!(
            store.renew_watch(first_watch, 1).unwrap_err(),
            Error::UnknownWatch
        );
        assert!(store.get(&second, 0).await.unwrap().is_none());
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn replayed_record_bytes_only_acknowledge_the_exact_current_proposal() {
    block_on(async {
        let network = SimNetwork::new(5, Capacity::NATIVE);
        let backend = NetworkBackend::new(network.clone(), TestVerifier);
        let owner = key(62);
        let descriptor = cdht::Descriptor::create(&Schema::dflt(1).unwrap(), &owner).unwrap();
        let record = descriptor.key();
        backend.create(&descriptor).await.unwrap();
        let old = SignedValue::sign(&descriptor.owner, 0, 0, vec![0], &owner).unwrap();
        backend.set(&record, 0, &old).await.unwrap();
        network.replay_set_value(&network.store(0).get(&record, 0).await.unwrap().unwrap());
        let current = SignedValue::sign(&descriptor.owner, 0, 1, vec![1], &owner).unwrap();
        assert_eq!(
            backend.set(&record, 0, &current).await.unwrap_err(),
            Error::Unavailable
        );
        // Every actual store applied the write, but old signed data was not an ACK.
        for i in 0..5 {
            assert_eq!(
                network.store(i).get(&record, 0).await.unwrap(),
                Some(current.clone())
            );
        }
        network.replay_set_value(&network.store(0).get(&record, 0).await.unwrap().unwrap());
        assert!(matches!(
            backend.set(&record, 0, &current).await.unwrap(),
            cdht::SetOutcome::Accepted
        ));
    });
}

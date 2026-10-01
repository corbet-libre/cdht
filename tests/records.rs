//! Schemas, descriptors, signed values and the client over the local filling.

mod common;

use cdht::{
    Backend, ClientState, Descriptor, Dht, EncryptionKey, Error, LocalBackend, Member, RecordKey,
    Schema, SetOutcome, SignedValue, Signer, WriteOutcome,
};
use common::{TestKey, TestVerifier, key};
use futures_executor::block_on;

type Client = Dht<LocalBackend<TestVerifier>, TestVerifier>;

fn network() -> LocalBackend<TestVerifier> {
    LocalBackend::new(TestVerifier)
}

fn client(backend: &LocalBackend<TestVerifier>) -> Client {
    Dht::new(backend.clone(), TestVerifier)
}

/// Owner subkeys 0..2, device A 2..4, device B 4..6.
fn two_device_schema(a: &TestKey, b: &TestKey) -> Schema {
    Schema::new(
        2,
        vec![
            Member {
                writer: a.public_key(),
                subkeys: 2,
            },
            Member {
                writer: b.public_key(),
                subkeys: 2,
            },
        ],
    )
    .unwrap()
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn schema_compiles_to_veilid_smpl_bytes() {
    let a = key(1);
    let schema = Schema::new(
        3,
        vec![Member {
            writer: a.public_key(),
            subkeys: 5,
        }],
    )
    .unwrap();
    let mut expected = b"SMPL".to_vec();
    expected.extend_from_slice(&3u16.to_le_bytes());
    expected.extend_from_slice(&a.public_key());
    expected.extend_from_slice(&5u16.to_le_bytes());
    assert_eq!(schema.compile(), expected);
    assert_eq!(Schema::parse(&expected).unwrap(), schema);
    assert_eq!(schema.subkey_count(), 8);
    assert_eq!(schema.max_value_len(), cdht::MAX_SUBKEY_SIZE);
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn schema_validation_and_writer_ranges() {
    let (owner, a, b) = (key(1), key(2), key(3));
    assert_eq!(Schema::new(0, vec![]).unwrap_err(), Error::InvalidSchema);
    let member = |k: &TestKey, n| Member {
        writer: k.public_key(),
        subkeys: n,
    };
    assert!(Schema::new(1, vec![member(&a, 0)]).is_ok());
    assert!(Schema::new(1, vec![member(&a, 1), member(&a, 1)]).is_ok());
    assert_eq!(
        Schema::new(1, vec![member(&a, 1024)]).unwrap_err(),
        Error::InvalidSchema
    );
    assert!(Schema::parse(b"SMPL\x01").is_err());
    assert!(Schema::parse(b"DFLT\x01\x00").is_ok());

    let schema = two_device_schema(&a, &b);
    let o = owner.public_key();
    assert_eq!(schema.writer_of(&o, 0), Some(o));
    assert_eq!(schema.writer_of(&o, 2), Some(a.public_key()));
    assert_eq!(schema.writer_of(&o, 5), Some(b.public_key()));
    assert_eq!(schema.writer_of(&o, 6), None);
    assert_eq!(schema.subkeys_of(&o, &a.public_key()), vec![2, 3]);
    assert_eq!(schema.subkeys_of(&o, &o), vec![0, 1]);
    assert!(schema.subkeys_of(&o, &key(9).public_key()).is_empty());
    assert_eq!(
        schema.check_write(&o, 2, &b.public_key(), 1).unwrap_err(),
        Error::WrongWriter
    );
    assert_eq!(
        schema.check_write(&o, 9, &o, 1).unwrap_err(),
        Error::SubkeyOutOfRange
    );
    assert_eq!(
        schema
            .check_write(&o, 0, &o, cdht::MAX_SUBKEY_SIZE + 1)
            .unwrap_err(),
        Error::ValueTooLarge
    );
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn descriptors_and_record_keys_follow_veilid() {
    let (owner, a, b) = (key(1), key(2), key(3));
    let schema = two_device_schema(&a, &b);
    let descriptor = Descriptor::create(&schema, &owner).unwrap();
    assert_eq!(descriptor.validate(&TestVerifier).unwrap(), schema);

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"VLD0");
    hasher.update(&owner.public_key());
    hasher.update(&schema.compile());
    assert_eq!(descriptor.key(), RecordKey(*hasher.finalize().as_bytes()));

    let text = descriptor.key().to_string();
    assert!(text.starts_with("VLD0:"));
    assert_eq!(text.parse::<RecordKey>().unwrap(), descriptor.key());

    let mut forged = descriptor.clone();
    forged.schema = Schema::new(5, vec![]).unwrap().compile();
    assert_eq!(
        forged.validate(&TestVerifier).unwrap_err(),
        Error::BadSignature
    );
    assert_eq!(
        descriptor
            .validate_for(&forged.key(), &TestVerifier)
            .unwrap_err(),
        Error::WrongRecord
    );

    // Veilid permits the owner to appear in member slots too.
    let self_member = Schema::new(
        1,
        vec![Member {
            writer: owner.public_key(),
            subkeys: 1,
        }],
    )
    .unwrap();
    assert!(Descriptor::create(&self_member, &owner).is_ok());

    let json = serde_json::to_string(&descriptor).unwrap();
    assert_eq!(
        serde_json::from_str::<Descriptor>(&json).unwrap(),
        descriptor
    );
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn writes_are_checked_against_the_owner_signed_writer_set() {
    block_on(async {
        let (owner, a, b) = (key(1), key(2), key(3));
        let backend = network();
        let mut dht = client(&backend);
        let record = dht
            .create(&two_device_schema(&a, &b), &owner)
            .await
            .unwrap();
        // No application header is reserved or synthesized.
        assert!(dht.get(&record, 0, None).await.unwrap().is_none());

        assert_eq!(
            dht.set(&record, 1, b"owner data", &owner, None)
                .await
                .unwrap(),
            WriteOutcome::Written { seq: 0 }
        );
        assert_eq!(
            dht.set(&record, 2, b"from a", &a, None).await.unwrap(),
            WriteOutcome::Written { seq: 0 }
        );
        assert_eq!(
            dht.set(&record, 4, b"b in a's slot?", &a, None)
                .await
                .unwrap_err(),
            Error::WrongWriter
        );
        assert_eq!(
            dht.get(&record, 2, None).await.unwrap().unwrap().as_slice(),
            b"from a"
        );

        // A node never trusts the writer: forged and misplaced values are refused.
        let forged = SignedValue::sign(&owner.public_key(), 4, 0, b"forged".to_vec(), &a).unwrap();
        assert_eq!(
            backend.set(&record, 4, &forged).await.unwrap_err(),
            Error::WrongWriter
        );
        let mut tampered = SignedValue::sign(&owner.public_key(), 2, 1, b"x".to_vec(), &a).unwrap();
        tampered.data = b"y".to_vec();
        assert_eq!(
            backend.set(&record, 2, &tampered).await.unwrap_err(),
            Error::BadSignature
        );
        // Replaying an older value returns the newer one.
        let old = SignedValue::sign(&owner.public_key(), 2, 0, b"older".to_vec(), &a).unwrap();
        match backend.set(&record, 2, &old).await.unwrap() {
            SetOutcome::Newer(current) => assert_eq!(current.data, b"from a"),
            SetOutcome::Accepted => panic!("stale write accepted"),
        }
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn sequence_numbers_and_stale_writes() {
    block_on(async {
        let (owner, a, b) = (key(1), key(2), key(3));
        let backend = network();
        let mut first = client(&backend);
        let record = first
            .create(&two_device_schema(&a, &b), &owner)
            .await
            .unwrap();
        assert_eq!(
            first.set(&record, 1, b"v0", &owner, None).await.unwrap(),
            WriteOutcome::Written { seq: 0 }
        );
        assert_eq!(
            first.set(&record, 1, b"v1", &owner, None).await.unwrap(),
            WriteOutcome::Written { seq: 1 }
        );

        // A second client that has not read the subkey yet starts at seq 0: stale.
        let mut second = client(&backend);
        second.open(&record).await.unwrap();
        assert_eq!(
            second
                .set(&record, 1, b"other", &owner, None)
                .await
                .unwrap(),
            WriteOutcome::Stale { current_seq: 1 }
        );
        // It learned the current value; the next write goes through.
        assert_eq!(
            second.set(&record, 1, b"v2", &owner, None).await.unwrap(),
            WriteOutcome::Written { seq: 2 }
        );
        assert_eq!(
            first
                .get(&record, 1, None)
                .await
                .unwrap()
                .unwrap()
                .as_slice(),
            b"v2"
        );
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn offline_writes_are_queued_and_flushed() {
    block_on(async {
        let (owner, a, b) = (key(1), key(2), key(3));
        let backend = network();
        let mut device_a = client(&backend);
        let record = device_a
            .create(&two_device_schema(&a, &b), &owner)
            .await
            .unwrap();

        backend.set_online(false);
        assert_eq!(
            device_a
                .set(&record, 2, b"draft 1", &a, None)
                .await
                .unwrap(),
            WriteOutcome::Queued { seq: 0 }
        );
        assert_eq!(
            device_a
                .set(&record, 2, b"draft 2", &a, None)
                .await
                .unwrap(),
            WriteOutcome::Queued { seq: 1 }
        );
        // The newer queued write superseded the older one; reads see it locally.
        assert_eq!(device_a.state().queue().len(), 1);
        assert_eq!(
            device_a
                .get(&record, 2, None)
                .await
                .unwrap()
                .unwrap()
                .as_slice(),
            b"draft 2"
        );
        // Opening a cached record works offline.
        device_a.open(&record).await.unwrap();

        // Still offline: flushing keeps everything.
        let report = device_a.flush().await.unwrap();
        assert_eq!((report.written, report.remaining), (0, 1));

        backend.set_online(true);
        let report = device_a.flush().await.unwrap();
        assert_eq!((report.written, report.remaining), (1, 0));
        assert!(report.stale.is_empty());

        let mut device_b = client(&backend);
        device_b.open(&record).await.unwrap();
        assert_eq!(
            device_b
                .get(&record, 2, None)
                .await
                .unwrap()
                .unwrap()
                .as_slice(),
            b"draft 2"
        );
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn flush_reports_stale_queued_writes() {
    block_on(async {
        let (owner, a, b) = (key(1), key(2), key(3));
        let backend = network();
        let mut offline = client(&backend);
        let record = offline
            .create(&two_device_schema(&a, &b), &owner)
            .await
            .unwrap();
        let mut online = client(&backend);
        online.open(&record).await.unwrap();

        // `offline` loses the network and queues; meanwhile `online` writes twice.
        let offline_backend = LocalBackend::new(TestVerifier);
        let mut isolated = Dht::with_state(
            offline_backend.clone(),
            TestVerifier,
            offline.state().clone(),
        );
        offline_backend.set_online(false);
        assert_eq!(
            isolated
                .set(&record, 1, b"offline", &owner, None)
                .await
                .unwrap(),
            WriteOutcome::Queued { seq: 0 }
        );
        online
            .set(&record, 1, b"online 1", &owner, None)
            .await
            .unwrap();
        online
            .set(&record, 1, b"online 2", &owner, None)
            .await
            .unwrap();

        // Back on the shared network: the queued write is stale.
        let mut rejoined = Dht::with_state(backend.clone(), TestVerifier, isolated.state().clone());
        let report = rejoined.flush().await.unwrap();
        assert_eq!(report.written, 0);
        assert_eq!(report.stale, vec![(record, 1)]);
        assert_eq!(
            rejoined
                .get(&record, 1, None)
                .await
                .unwrap()
                .unwrap()
                .as_slice(),
            b"online 2"
        );
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn watchers_see_changes() {
    block_on(async {
        let (owner, a, b) = (key(1), key(2), key(3));
        let backend = network();
        let mut writer = client(&backend);
        let record = writer
            .create(&two_device_schema(&a, &b), &owner)
            .await
            .unwrap();
        let mut watcher = client(&backend);
        watcher.open(&record).await.unwrap();
        let watch = watcher.watch(&record).await.unwrap();
        assert!(watcher.changes(watch).await.unwrap().is_empty());

        writer.set(&record, 4, b"hello", &b, None).await.unwrap();
        let changes = watcher.changes(watch).await.unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!((changes[0].subkey, changes[0].seq), (4, 0));
        assert!(watcher.changes(watch).await.unwrap().is_empty());

        watcher.cancel_watch(watch).await.unwrap();
        writer.set(&record, 4, b"again", &b, None).await.unwrap();
        assert_eq!(
            watcher.changes(watch).await.unwrap_err(),
            Error::UnknownWatch
        );
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn encrypted_records_hide_data_from_the_backend() {
    block_on(async {
        let (owner, a, b) = (key(1), key(2), key(3));
        let secret = EncryptionKey::from_bytes([42; 32]);
        let backend = network();
        let mut dht = client(&backend);
        let record = dht
            .create(&two_device_schema(&a, &b), &owner)
            .await
            .unwrap();
        dht.set(&record, 2, b"private note", &a, Some(&secret))
            .await
            .unwrap();

        let stored = backend.get(&record, 2).await.unwrap().unwrap();
        assert!(!stored.data.windows(12).any(|w| w == b"private note"));
        assert_eq!(
            dht.get(&record, 2, Some(&secret))
                .await
                .unwrap()
                .unwrap()
                .as_slice(),
            b"private note"
        );
        let wrong = EncryptionKey::from_bytes([7; 32]);
        // Veilid's record cipher has no key confirmation: a wrong key yields garbage.
        assert_ne!(
            dht.get(&record, 2, Some(&wrong))
                .await
                .unwrap()
                .unwrap()
                .as_slice(),
            b"private note"
        );
        assert_eq!(dht.get(&record, 2, None).await.unwrap_err(), Error::Decrypt);
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn client_state_persists_and_is_revalidated() {
    block_on(async {
        let (owner, a, b) = (key(1), key(2), key(3));
        let backend = network();
        let mut dht = client(&backend);
        let record = dht
            .create(&two_device_schema(&a, &b), &owner)
            .await
            .unwrap();
        dht.set(&record, 2, b"kept", &a, None).await.unwrap();
        dht.set(&record, 0, b"owner data", &owner, None)
            .await
            .unwrap();

        let json = serde_json::to_string(dht.state()).unwrap();
        let state: ClientState = serde_json::from_str(&json).unwrap();
        backend.set_online(false);
        let mut resumed = Dht::with_state(backend.clone(), TestVerifier, state);
        assert_eq!(
            resumed
                .get(&record, 2, None)
                .await
                .unwrap()
                .unwrap()
                .as_slice(),
            b"kept"
        );
        assert!(resumed.get(&record, 0, None).await.unwrap().is_some());

        // Tampered persisted values are dropped on resume.
        let b64 = |bytes: &[u8]| data_encoding::BASE64URL_NOPAD.encode(bytes);
        let tampered = json.replace(&b64(b"kept"), &b64(b"evil"));
        assert_ne!(tampered, json);
        let state: ClientState = serde_json::from_str(&tampered).unwrap();
        let mut resumed = Dht::with_state(backend.clone(), TestVerifier, state);
        assert_eq!(
            resumed.get(&record, 2, None).await.unwrap_err(),
            Error::Unavailable
        );
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn scoped_signer_can_end_before_any_network_io() {
    block_on(async {
        let backend = LocalBackend::new(TestVerifier);
        backend.set_online(false);
        let mut writer = Dht::new(backend.clone(), TestVerifier);
        let encryption = EncryptionKey::from_bytes([19; 32]);
        let record = {
            let owner = key(71);
            let record = writer
                .queue_create(&Schema::dflt(1).unwrap(), &owner)
                .unwrap();
            assert_eq!(
                writer
                    .queue_set(&record, 0, b"scoped data", &owner, Some(&encryption))
                    .unwrap(),
                0
            );
            record
        };
        {
            let owner = key(71);
            let before = writer.state().queue()[0].value.raw_blob().unwrap();
            writer
                .queue_set(&record, 0, b"scoped data", &owner, Some(&encryption))
                .unwrap();
            assert_eq!(writer.state().queue()[0].value.raw_blob().unwrap(), before);
        }
        let staged = writer.state().clone();
        let original = staged.queue()[0].value.raw_blob().unwrap();
        let signature = staged.queue()[0].value.signature;
        assert_eq!(writer.flush().await.unwrap().remaining, 1);
        backend.set_online(true);
        let mut restored = Dht::with_state(backend.clone(), TestVerifier, staged);
        assert_eq!(restored.flush().await.unwrap().written, 1);
        let stored = backend.get(&record, 0).await.unwrap().unwrap();
        assert_eq!(stored.raw_blob().unwrap(), original);
        assert_eq!(stored.signature, signature);
        assert_eq!(
            restored
                .get(&record, 0, Some(&encryption))
                .await
                .unwrap()
                .unwrap()
                .as_slice(),
            b"scoped data"
        );
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn scoped_cipher_opens_only_authenticated_values() {
    block_on(async {
        let backend = network();
        let mut writer = client(&backend);
        let owner = key(72);
        let encryption = EncryptionKey::from_bytes([23; 32]);
        let record = writer
            .queue_create(&Schema::dflt(1).unwrap(), &owner)
            .unwrap();
        {
            let crypt = |nonce: &[u8; 24], bytes: &[u8]| encryption.crypt(nonce, bytes);
            writer
                .queue_set(&record, 0, b"original", &owner, Some(&crypt))
                .unwrap();
        }
        assert_eq!(writer.flush().await.unwrap().written, 1);
        let mut reader = client(&backend);
        reader.open(&record).await.unwrap();
        let value = reader.get_signed(&record, 0).await.unwrap().unwrap();
        let calls = std::cell::Cell::new(0);
        let crypt = |nonce: &[u8; 24], bytes: &[u8]| {
            calls.set(calls.get() + 1);
            encryption.crypt(nonce, bytes)
        };
        assert_eq!(
            reader
                .open_value(&record, 0, &value, Some(&crypt))
                .unwrap()
                .as_slice(),
            b"original"
        );
        assert_eq!(calls.get(), 1);
        let mut invalid = value.clone();
        invalid.signature[0] ^= 1;
        assert_eq!(
            reader.open_value(&record, 0, &invalid, Some(&crypt)),
            Err(Error::BadSignature)
        );
        let mut invalid_nonce = value.clone();
        invalid_nonce.nonce.as_mut().unwrap()[0] ^= 1;
        assert!(
            reader
                .open_value(&record, 0, &invalid_nonce, Some(&crypt))
                .is_err()
        );
        assert!(reader.open_value(&record, 1, &value, Some(&crypt)).is_err());
        assert_eq!(calls.get(), 1);
        let refused = |_nonce: &[u8; 24], _bytes: &[u8]| Err(Error::Crypto);
        assert_eq!(
            reader.open_value(&record, 0, &value, Some(&refused)),
            Err(Error::Crypto)
        );
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn independent_read_capabilities_refuse_malformed_keys_and_redact_debug() {
    let owner = key(42);
    let record = Descriptor::create(&Schema::dflt(1).unwrap(), &owner)
        .unwrap()
        .key();
    let secret = EncryptionKey::from_bytes([57; 32]);
    let capability = secret.record_key(&record);
    let (parsed, decoded) = EncryptionKey::parse_record_key(&capability).unwrap();
    assert_eq!(parsed, record);
    let nonce = [23; 24];
    let plaintext = b"private record";
    assert_eq!(
        decoded.unwrap().crypt(&nonce, plaintext).unwrap(),
        secret.crypt(&nonce, plaintext).unwrap()
    );
    assert!(
        EncryptionKey::parse_record_key(&record.to_string())
            .unwrap()
            .1
            .is_none()
    );
    for malformed in [
        "",
        "VLD1:AAAA",
        "VLD0:",
        "VLD0:!",
        "VLD0:AAAA:!",
        "VLD0:AAAA:AAAA",
        "VLD0:a:b:c",
    ] {
        assert_eq!(
            EncryptionKey::parse_record_key(malformed).unwrap_err(),
            Error::Encoding
        );
    }
    assert_eq!(format!("{secret:?}"), "EncryptionKey([redacted])");
    assert!(!format!("{secret:?}").contains(capability.as_str()));
    assert!(format!("{record:?}").contains(&record.to_string()));
    assert!("VLD0:!".parse::<RecordKey>().is_err());
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn schemas_and_signed_values_refuse_out_of_bounds_external_structures() {
    let owner = key(43);
    let schema = Schema::dflt(1).unwrap();
    assert!(schema.members().is_empty());
    let record = Descriptor::create(&schema, &owner).unwrap().key();
    let member = Member {
        writer: owner.public_key(),
        subkeys: 1,
    };
    assert_eq!(
        Schema::new(1, vec![member; 257]).unwrap_err(),
        Error::InvalidSchema
    );
    let writers: Vec<_> = (0..256u16)
        .map(|i| {
            let mut writer = [0; 32];
            writer[..2].copy_from_slice(&i.to_le_bytes());
            Member { writer, subkeys: 1 }
        })
        .collect();
    assert_eq!(Schema::new(1, writers).unwrap_err(), Error::InvalidSchema);
    for malformed in [
        vec![],
        vec![0; 6 + 257 * 34],
        b"NONE\x01\0".to_vec(),
        b"SMPL\x01\0x".to_vec(),
    ] {
        assert_eq!(Schema::parse(&malformed).unwrap_err(), Error::InvalidSchema);
    }
    assert_eq!(
        SignedValue::sign(&owner.public_key(), 0, u32::MAX, vec![], &owner).unwrap_err(),
        Error::SeqExhausted
    );
    assert_eq!(
        SignedValue::sign(
            &owner.public_key(),
            0,
            0,
            vec![0; cdht::MAX_SUBKEY_SIZE + 1],
            &owner
        )
        .unwrap_err(),
        Error::ValueTooLarge
    );
    let value = SignedValue::sign(&owner.public_key(), 0, 0, vec![1], &owner).unwrap();
    let other_writer = key(59);
    let independently_signed =
        SignedValue::sign(&other_writer.public_key(), 0, 0, vec![1], &other_writer).unwrap();
    assert!(!value.same_value(&independently_signed));
    let mut altered = value.clone();
    altered.seq = u32::MAX;
    assert_eq!(altered.raw_blob().unwrap_err(), Error::SeqExhausted);
    assert_eq!(
        altered
            .validate(&record, &owner.public_key(), &schema, 0, &TestVerifier)
            .unwrap_err(),
        Error::SeqExhausted
    );
    altered = value.clone();
    altered.data.resize(cdht::MAX_SUBKEY_SIZE + 1, 0);
    assert_eq!(altered.raw_blob().unwrap_err(), Error::ValueTooLarge);
    assert_eq!(
        value
            .validate(
                &RecordKey([0; 32]),
                &owner.public_key(),
                &schema,
                0,
                &TestVerifier
            )
            .unwrap_err(),
        Error::WrongRecord
    );
    let mut original = SignedValue::from_blob(value.raw_blob().unwrap(), value.signature).unwrap();
    original
        .validate(&record, &owner.public_key(), &schema, 0, &TestVerifier)
        .unwrap();
    original.data[0] ^= 1;
    assert_eq!(original.raw_blob().unwrap_err(), Error::Encoding);
    assert!(!original.same_value(&value));
    assert!(!original.same_value(&original.clone()));
    assert_eq!(
        SignedValue::from_blob(vec![0; cdht::MAX_SUBKEY_SIZE + 1025], [0; 64]).unwrap_err(),
        Error::ValueTooLarge
    );
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn recovering_a_mixed_queue_preserves_other_records_and_subkeys() {
    block_on(async {
        let backend = network();
        let a = key(55);
        let b = key(56);
        let mut original = client(&backend);
        let ra = original
            .create(&Schema::dflt(2).unwrap(), &a)
            .await
            .unwrap();
        let rb = original
            .create(&Schema::dflt(2).unwrap(), &b)
            .await
            .unwrap();
        backend.set_online(false);
        for (record, signer) in [(&rb, &b), (&ra, &a)] {
            for subkey in 0..2 {
                assert!(matches!(
                    original
                        .set(record, subkey, &[subkey as u8], signer, None)
                        .await
                        .unwrap(),
                    WriteOutcome::Queued { seq: 0 }
                ));
            }
        }
        let state: ClientState =
            serde_json::from_slice(&serde_json::to_vec(original.state()).unwrap()).unwrap();
        let mut restored = Dht::with_state(backend.clone(), TestVerifier, state);
        assert_eq!(restored.state().queue().len(), 4);
        backend.set_online(true);
        let concurrent =
            SignedValue::sign(&b.public_key(), 0, 1, b"another device".to_vec(), &b).unwrap();
        backend.set(&rb, 0, &concurrent).await.unwrap();
        let flushed = restored.flush().await.unwrap();
        assert_eq!(flushed.written, 3);
        assert_eq!(flushed.stale, vec![(rb, 0)]);
        assert!(restored.state().queue().is_empty());
        assert_eq!(restored.get_signed(&rb, 0).await.unwrap(), Some(concurrent));
        for (record, subkey) in [(ra, 0), (ra, 1), (rb, 1)] {
            assert_eq!(
                restored
                    .get(&record, subkey, None)
                    .await
                    .unwrap()
                    .unwrap()
                    .as_slice(),
                &[subkey as u8]
            );
        }
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn record_cipher_bounds_match_the_upstream_subkey_boundary() {
    let key = EncryptionKey::from_bytes([57; 32]);
    let nonce = [58; 24];
    for length in [0, cdht::MAX_SUBKEY_SIZE] {
        let original = vec![9; length];
        let ciphertext = key.crypt(&nonce, &original).unwrap();
        assert_eq!(key.crypt(&nonce, &ciphertext).unwrap().as_slice(), original);
    }
    assert_eq!(
        key.crypt(&nonce, &vec![0; cdht::MAX_SUBKEY_SIZE + 1])
            .unwrap_err(),
        Error::ValueTooLarge
    );
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn scoped_cipher_adapter_executes_under_custody_and_unchanged_write_keeps_nonce() {
    use cdht::RecordCipher;
    block_on(async {
        let backend = LocalBackend::new(TestVerifier);
        let owner = key(44);
        let secret = EncryptionKey::from_bytes([17; 32]);
        let capability = |nonce: &[u8; 24], input: &[u8]| secret.crypt(nonce, input);
        let mut dht = Dht::new(backend.clone(), TestVerifier);
        let record = dht.create(&Schema::dflt(1).unwrap(), &owner).await.unwrap();
        dht.set(
            &record,
            0,
            b"same",
            &owner,
            Some(&capability as &dyn RecordCipher),
        )
        .await
        .unwrap();
        let original = dht.get_signed(&record, 0).await.unwrap().unwrap();
        assert_eq!(
            dht.set(&record, 0, b"same", &owner, Some(&capability))
                .await
                .unwrap(),
            WriteOutcome::Written { seq: 0 }
        );
        assert_eq!(dht.get_signed(&record, 0).await.unwrap().unwrap(), original);
        assert_eq!(
            dht.open_value(&record, 0, &original, Some(&capability))
                .unwrap()
                .as_slice(),
            b"same"
        );
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn imported_retry_snapshots_recover_only_authenticated_latest_values() {
    block_on(async {
        let owner = key(1);
        let backend = network();
        let mut original = client(&backend);
        let record = original
            .queue_create(&Schema::dflt(2).unwrap(), &owner)
            .unwrap();
        original
            .queue_set(&record, 0, b"first", &owner, None)
            .unwrap();
        let first = serde_json::to_value(original.state()).unwrap()["queue"][0].clone();
        original
            .queue_set(&record, 0, b"latest", &owner, None)
            .unwrap();
        original
            .queue_set(&record, 1, b"other subkey", &owner, None)
            .unwrap();
        let snapshot = serde_json::to_value(original.state()).unwrap();
        let locator = record.to_string();
        // A valid retry survives loss of its redundant cache. Duplicate imported
        // retries coalesce, and stale retries never roll back a newer cache.
        for remove_cache in [false, true] {
            let mut state = snapshot.clone();
            if remove_cache {
                state["values"] = serde_json::json!({});
            }
            state["queue"]
                .as_array_mut()
                .unwrap()
                .insert(0, first.clone());
            let mut resumed = Dht::with_state(
                backend.clone(),
                TestVerifier,
                serde_json::from_value(state).unwrap(),
            );
            assert_eq!(resumed.state().queue().len(), 2);
            let pending = resumed
                .state()
                .queue()
                .iter()
                .find(|q| q.subkey == 0)
                .unwrap();
            assert_eq!(pending.value.seq, 1);
            assert_eq!(pending.value.data, b"latest");
            assert_eq!(resumed.flush().await.unwrap().written, 2);
            assert_eq!(
                resumed
                    .get(&record, 0, None)
                    .await
                    .unwrap()
                    .unwrap()
                    .as_slice(),
                b"latest"
            );
            assert_eq!(
                resumed.get_signed(&record, 2).await.unwrap_err(),
                Error::SubkeyOutOfRange
            );
        }
        // A valid signature cannot authorize another locator/subkey, and a forged
        // signature in both the cache and queue cannot become a retry obligation.
        for case in 0..4 {
            let mut state = snapshot.clone();
            match case {
                0 => {
                    state["descriptors"][&locator]["signature"] =
                        serde_json::json!(data_encoding::BASE64URL_NOPAD.encode(&[0; 64]));
                }
                1 => {
                    state["queue"][0]["key"] = serde_json::json!(RecordKey([42; 32]).to_string());
                    state["values"] = serde_json::json!({});
                }
                2 => {
                    state["queue"][0]["subkey"] = serde_json::json!(2);
                    state["values"] = serde_json::json!({});
                }
                3 => {
                    state["queue"][0]["value"]["signature"] =
                        serde_json::json!(data_encoding::BASE64URL_NOPAD.encode(&[0; 64]));
                    state["values"][&locator]["0"] = state["queue"][0]["value"].clone();
                }
                _ => unreachable!(),
            }
            let resumed = Dht::with_state(
                network(),
                TestVerifier,
                serde_json::from_value(state).unwrap(),
            );
            assert!(resumed.state().queue().iter().all(|q| q.subkey == 1));
            if case == 0 {
                assert_eq!(resumed.schema(&record).unwrap_err(), Error::NotOpen);
                assert!(resumed.state().queue().is_empty());
            }
        }
        assert_eq!(original.schema(&record).unwrap().1.owner_subkeys(), 2);
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn public_record_errors_never_contain_record_data() {
    for (error, message) in [
        (Error::Encoding, "malformed data"),
        (Error::InvalidSchema, "invalid schema"),
        (Error::BadSignature, "signature did not verify"),
        (Error::WrongWriter, "writer not allowed for this subkey"),
        (Error::SubkeyOutOfRange, "subkey out of range"),
        (Error::ValueTooLarge, "value too large"),
        (Error::SeqExhausted, "sequence numbers exhausted"),
        (Error::WrongRecord, "descriptor does not match the record"),
        (Error::UnknownRecord, "unknown record"),
        (Error::NotOpen, "record not open"),
        (Error::UnknownWatch, "unknown watch"),
        (Error::Unavailable, "backend unavailable"),
        (Error::Conflict, "concurrent write won"),
        (Error::Decrypt, "decryption failed"),
        (Error::Signer, "signing failed"),
        (Error::Randomness, "randomness unavailable"),
        (Error::Crypto, "cryptographic failure"),
    ] {
        assert_eq!(error.to_string(), message);
        assert!(std::error::Error::source(&error).is_none());
    }
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn equivalent_authenticated_descriptor_retains_the_original_signature() {
    block_on(async {
        let owner = key(41);
        let descriptor = Descriptor::create(&Schema::dflt(1).unwrap(), &owner).unwrap();
        let mut alternate = descriptor.clone();
        alternate.signature = owner.alternative_signature(&alternate.schema);
        assert_ne!(descriptor.signature, alternate.signature);
        alternate.validate(&TestVerifier).unwrap();
        assert_eq!(descriptor.key(), alternate.key());
        let backend = network();
        backend.create(&descriptor).await.unwrap();
        backend.create(&alternate).await.unwrap();
        assert_eq!(
            backend.descriptor(&descriptor.key()).await.unwrap(),
            Some(descriptor)
        );
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn independent_equal_sequence_encrypted_writes_compare_plaintext_and_keep_original_bytes() {
    block_on(async {
        let backend = network();
        let owner = key(42);
        let encryption = EncryptionKey::from_bytes([43; 32]);
        let mut first = client(&backend);
        let record = first
            .create(&Schema::dflt(1).unwrap(), &owner)
            .await
            .unwrap();
        let mut second = client(&backend);
        let mut conflicting = client(&backend);
        second.open(&record).await.unwrap();
        conflicting.open(&record).await.unwrap();
        first
            .set(&record, 0, b"unchanged", &owner, Some(&encryption))
            .await
            .unwrap();
        let original = backend.get(&record, 0).await.unwrap().unwrap();
        assert_eq!(
            second
                .set(&record, 0, b"unchanged", &owner, Some(&encryption))
                .await
                .unwrap(),
            WriteOutcome::Written { seq: 0 }
        );
        assert_eq!(
            second.get_signed(&record, 0).await.unwrap(),
            Some(original.clone())
        );
        assert!(second.state().queue().is_empty());
        assert_eq!(
            conflicting
                .set(&record, 0, b"different", &owner, Some(&encryption))
                .await
                .unwrap(),
            WriteOutcome::Stale { current_seq: 0 }
        );
        assert_eq!(
            conflicting.get_signed(&record, 0).await.unwrap(),
            Some(original.clone())
        );
        assert!(conflicting.state().queue().is_empty());
        assert_eq!(backend.get(&record, 0).await.unwrap(), Some(original));
    });
}

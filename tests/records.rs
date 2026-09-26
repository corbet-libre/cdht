//! Schemas, descriptors, signed values and the client over the local filling.

mod common;

use cdht::{
    Backend, ClientState, Descriptor, Dht, EncryptionKey, Error, HEADER_SUBKEY, LocalBackend,
    Member, RecordKey, Schema, SetOutcome, SignedValue, Signer, WriteOutcome,
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

#[test]
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

#[test]
fn schema_validation_and_writer_ranges() {
    let (owner, a, b) = (key(1), key(2), key(3));
    assert_eq!(Schema::new(0, vec![]).unwrap_err(), Error::InvalidSchema);
    let member = |k: &TestKey, n| Member {
        writer: k.public_key(),
        subkeys: n,
    };
    assert_eq!(
        Schema::new(1, vec![member(&a, 0)]).unwrap_err(),
        Error::InvalidSchema
    );
    assert_eq!(
        Schema::new(1, vec![member(&a, 1), member(&a, 1)]).unwrap_err(),
        Error::InvalidSchema
    );
    assert_eq!(
        Schema::new(1, vec![member(&a, 1024)]).unwrap_err(),
        Error::InvalidSchema
    );
    assert!(Schema::parse(b"SMPL\x01").is_err());
    assert!(Schema::parse(b"DFLT\x01\x00").is_err());

    let schema = two_device_schema(&a, &b);
    let o = owner.public_key();
    assert_eq!(schema.writer_of(&o, 0), Some(o));
    assert_eq!(schema.writer_of(&o, 2), Some(a.public_key()));
    assert_eq!(schema.writer_of(&o, 5), Some(b.public_key()));
    assert_eq!(schema.writer_of(&o, 6), None);
    assert_eq!(schema.subkeys_of(&o, &a.public_key()), 2..4);
    assert_eq!(schema.subkeys_of(&o, &o), 0..2);
    assert_eq!(schema.subkeys_of(&o, &key(9).public_key()), 0..0);
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

#[test]
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

    // The owner cannot also be a member.
    let self_member = Schema::new(
        1,
        vec![Member {
            writer: owner.public_key(),
            subkeys: 1,
        }],
    )
    .unwrap();
    assert_eq!(
        Descriptor::create(&self_member, &owner).unwrap_err(),
        Error::InvalidSchema
    );

    let json = serde_json::to_string(&descriptor).unwrap();
    assert_eq!(
        serde_json::from_str::<Descriptor>(&json).unwrap(),
        descriptor
    );
}

#[test]
fn writes_are_checked_against_the_owner_signed_writer_set() {
    block_on(async {
        let (owner, a, b) = (key(1), key(2), key(3));
        let backend = network();
        let mut dht = client(&backend);
        let record = dht
            .create(&two_device_schema(&a, &b), &owner, None)
            .await
            .unwrap();
        let header = dht.header(&record, None).await.unwrap();
        assert_eq!(header.epoch, 0);
        assert_eq!(header.predecessor, None);

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
        let forged = SignedValue::sign(&record, 4, 0, b"forged".to_vec(), &a).unwrap();
        assert_eq!(
            backend.set(&record, 4, &forged).await.unwrap_err(),
            Error::WrongWriter
        );
        let mut tampered = SignedValue::sign(&record, 2, 1, b"x".to_vec(), &a).unwrap();
        tampered.data = b"y".to_vec();
        assert_eq!(
            backend.set(&record, 2, &tampered).await.unwrap_err(),
            Error::BadSignature
        );
        // Replaying an older value returns the newer one.
        let old = SignedValue::sign(&record, 2, 0, b"older".to_vec(), &a).unwrap();
        match backend.set(&record, 2, &old).await.unwrap() {
            SetOutcome::Newer(current) => assert_eq!(current.data, b"from a"),
            SetOutcome::Accepted => panic!("stale write accepted"),
        }
    });
}

#[test]
fn sequence_numbers_and_stale_writes() {
    block_on(async {
        let (owner, a, b) = (key(1), key(2), key(3));
        let backend = network();
        let mut first = client(&backend);
        let record = first
            .create(&two_device_schema(&a, &b), &owner, None)
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

#[test]
fn offline_writes_are_queued_and_flushed() {
    block_on(async {
        let (owner, a, b) = (key(1), key(2), key(3));
        let backend = network();
        let mut device_a = client(&backend);
        let record = device_a
            .create(&two_device_schema(&a, &b), &owner, None)
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

#[test]
fn flush_reports_stale_queued_writes() {
    block_on(async {
        let (owner, a, b) = (key(1), key(2), key(3));
        let backend = network();
        let mut offline = client(&backend);
        let record = offline
            .create(&two_device_schema(&a, &b), &owner, None)
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

#[test]
fn watchers_see_changes() {
    block_on(async {
        let (owner, a, b) = (key(1), key(2), key(3));
        let backend = network();
        let mut writer = client(&backend);
        let record = writer
            .create(&two_device_schema(&a, &b), &owner, None)
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

#[test]
fn encrypted_records_hide_data_from_the_backend() {
    block_on(async {
        let (owner, a, b) = (key(1), key(2), key(3));
        let secret = EncryptionKey::from_bytes([42; 32]);
        let backend = network();
        let mut dht = client(&backend);
        let record = dht
            .create(&two_device_schema(&a, &b), &owner, Some(&secret))
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
        assert_eq!(
            dht.get(&record, 2, Some(&wrong)).await.unwrap_err(),
            Error::Decrypt
        );
        // The header is encrypted too.
        assert_eq!(
            dht.header(&record, None).await.unwrap_err(),
            Error::Encoding
        );
        assert_eq!(dht.header(&record, Some(&secret)).await.unwrap().epoch, 0);
    });
}

#[test]
fn epochs_link_records_and_exclude_removed_writers() {
    block_on(async {
        let (owner, a, b) = (key(1), key(2), key(3));
        let new_owner = key(4);
        let old_secret = EncryptionKey::from_bytes([1; 32]);
        let new_secret = EncryptionKey::from_bytes([2; 32]);
        let backend = network();
        let mut dht = client(&backend);
        let old = dht
            .create(&two_device_schema(&a, &b), &owner, Some(&old_secret))
            .await
            .unwrap();

        // Remove device B: new writer set, new owner key, new encryption key.
        let only_a = Schema::new(
            2,
            vec![Member {
                writer: a.public_key(),
                subkeys: 2,
            }],
        )
        .unwrap();
        let new = dht
            .rotate(
                &old,
                &owner,
                Some(&old_secret),
                &only_a,
                &new_owner,
                Some(&new_secret),
            )
            .await
            .unwrap();
        assert_ne!(new, old);
        let old_header = dht.header(&old, Some(&old_secret)).await.unwrap();
        assert_eq!(old_header.successor, Some(new));
        let new_header = dht.header(&new, Some(&new_secret)).await.unwrap();
        assert_eq!((new_header.epoch, new_header.predecessor), (1, Some(old)));

        // B is no writer of the new epoch.
        assert_eq!(
            dht.set(&new, 4, b"b", &b, Some(&new_secret))
                .await
                .unwrap_err(),
            Error::SubkeyOutOfRange
        );
        dht.set(&new, 2, b"a", &a, Some(&new_secret)).await.unwrap();

        // A reader holding both keys follows to the newest epoch; B, knowing only the old
        // key, stops at the old record.
        let mut reader = client(&backend);
        reader.open(&old).await.unwrap();
        let keys = |k: &RecordKey| {
            if *k == old {
                Some(old_secret.clone())
            } else if *k == new {
                Some(new_secret.clone())
            } else {
                None
            }
        };
        assert_eq!(reader.latest(&old, keys).await.unwrap(), new);
        let only_old = |k: &RecordKey| (*k == old).then(|| old_secret.clone());
        assert_eq!(reader.latest(&old, only_old).await.unwrap(), old);

        // A record rotates once.
        assert_eq!(
            dht.rotate(
                &old,
                &owner,
                Some(&old_secret),
                &only_a,
                &new_owner,
                Some(&new_secret)
            )
            .await
            .unwrap_err(),
            Error::Conflict
        );
        // Only the owner rotates.
        assert_eq!(
            dht.rotate(&new, &a, Some(&new_secret), &only_a, &a, None)
                .await
                .unwrap_err(),
            Error::WrongWriter
        );
    });
}

#[test]
fn client_state_persists_and_is_revalidated() {
    block_on(async {
        let (owner, a, b) = (key(1), key(2), key(3));
        let backend = network();
        let mut dht = client(&backend);
        let record = dht
            .create(&two_device_schema(&a, &b), &owner, None)
            .await
            .unwrap();
        dht.set(&record, 2, b"kept", &a, None).await.unwrap();

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
        assert!(
            resumed
                .get(&record, HEADER_SUBKEY, None)
                .await
                .unwrap()
                .is_some()
        );

        // Tampered persisted values are dropped on resume.
        let b64 = |bytes: &[u8]| data_encoding::BASE64URL_NOPAD.encode(bytes);
        let tampered = json.replace(&b64(b"kept"), &b64(b"evil"));
        assert_ne!(tampered, json);
        let state: ClientState = serde_json::from_str(&tampered).unwrap();
        let mut resumed = Dht::with_state(backend.clone(), TestVerifier, state);
        assert!(resumed.get(&record, 2, None).await.unwrap().is_none());
    });
}

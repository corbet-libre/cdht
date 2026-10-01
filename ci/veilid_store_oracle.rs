//! CI-only internal hook, compiled inside otherwise unchanged upstream storage.
//! Original local bytes and open-time rehydration scheduling; no network success.
use super::*;

impl StorageManager {
    pub(crate) async fn cdht_import_local_original(
        &self,
        key: &OpaqueRecordKey,
        descriptor: SignedValueDescriptor,
        value: SignedValueData,
    ) {
        assert!(matches!(
            self.verify_inbound_signed_value(key, &descriptor, &value, 0)
                .await,
            NetworkResult::Value(())
        ));
        self.check_subkey_value_data(
            &descriptor.schema().unwrap(),
            descriptor.ref_owner(),
            0,
            value.value_data(),
        )
        .unwrap();
        let store = self.get_local_record_store().unwrap();
        let record = Record::<LocalRecordDetail>::new(
            Timestamp::now(),
            Arc::new(descriptor),
            LocalRecordDetail::new(SafetySelection::Safe(SafetySpec::default())),
        )
        .unwrap();
        store.new_record(key.clone(), record).await.unwrap();
        store
            .set_single_subkey(
                key,
                0,
                Arc::new(value),
                InboundWatchUpdateMode::NoUpdate,
                CommitActionFlushMode::Immediate,
            )
            .await
            .unwrap();
        assert!(!self.inner.lock().locally_created_records.contains(key));
    }

    pub(crate) async fn cdht_reopen_imported_local(
        &self,
        key: &OpaqueRecordKey,
    ) -> (SignedValueData, SignedValueDescriptor) {
        // No secret or writer capability is required to re-publish signed bytes.
        // No read secret crosses this fixture boundary, so ciphertext stays opaque.
        let locator = RecordKey::new(key.kind(), BareRecordKey::new(key.value(), None));
        let opened = self
            .open_record(
                locator,
                None,
                SafetySelection::Safe(SafetySpec::default()),
                true,
            )
            .await
            .unwrap();
        assert_eq!(opened.ref_key().opaque(), *key);
        assert!(opened.ref_owner_secret().is_none());
        {
            let inner = self.inner.lock();
            let queued = inner
                .rehydration_requests
                .get(key)
                .expect("upstream open queued rehydration");
            assert_eq!(queued.subkeys, ValueSubkeyRangeSet::full());
            assert_eq!(
                queued.consensus_count,
                self.config().internal().network.dht.set_value_count as usize
            );
        }
        let stored = self
            .get_local_record_store()
            .unwrap()
            .get_subkey(key, 0, true)
            .await
            .unwrap()
            .unwrap();
        (
            stored.opt_value.unwrap().as_ref().clone(),
            stored.opt_descriptor.unwrap().as_ref().clone(),
        )
    }
}

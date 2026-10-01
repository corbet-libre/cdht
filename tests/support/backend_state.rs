//! Actual store state survives an interrupted lock and refuses identifier exhaustion.
use super::*;
use crate::test_crypto as common;
use common::{TestVerifier, key};
use futures_executor::block_on;

#[test]
fn poisoned_lock_retains_validated_records_and_cannot_wrap_watch_identifiers() {
    block_on(async {
        let store = LocalBackend::new(TestVerifier);
        let owner = key(44);
        let descriptor = Descriptor::create(&crate::Schema::dflt(1).unwrap(), &owner).unwrap();
        store.create(&descriptor).await.unwrap();
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _lock = store.state.lock().unwrap();
                panic!("interrupted critical section");
            }))
            .is_err()
        );
        assert_eq!(
            store.descriptor(&descriptor.key()).await.unwrap(),
            Some(descriptor.clone())
        );
        let value =
            SignedValue::sign(&descriptor.owner, 0, 0, b"retained".to_vec(), &owner).unwrap();
        store.set(&descriptor.key(), 0, &value).await.unwrap();
        assert_eq!(store.get(&descriptor.key(), 0).await.unwrap(), Some(value));
        store.lock_any().next_watch = u64::MAX;
        assert_eq!(
            store.watch(&descriptor.key()).await.unwrap_err(),
            Error::Unavailable
        );
        assert!(store.lock_any().watches.is_empty());
        assert_eq!(store.lock_any().next_watch, u64::MAX);
    });
}

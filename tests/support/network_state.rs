//! Actual node stores retain their watch capacity after local bookkeeping faults.
use super::*;
use crate::test_crypto::{TestVerifier, key};
#[path = "../common/network.rs"]
mod participants;
use futures_executor::block_on;
use participants::SimNetwork;
fn poison<T>(value: &Mutex<T>) {
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = value.lock().unwrap();
            panic!("interrupted bookkeeping");
        }))
        .is_err()
    );
}
#[test]
fn exhausted_or_interrupted_local_watch_state_never_consumes_remote_capacity() {
    block_on(async {
        for fault in 0..3 {
            let transport = SimNetwork::new(1, crate::Capacity::NATIVE);
            let backend = NetworkBackend::new(transport.clone(), TestVerifier);
            let descriptor =
                Descriptor::create(&crate::Schema::dflt(1).unwrap(), &key(45)).unwrap();
            let record = descriptor.key();
            backend.create(&descriptor).await.unwrap();
            transport.store(0).create(&descriptor).await.unwrap();
            match fault {
                0 => *backend.next_watch.lock().unwrap() = u64::MAX,
                1 => poison(&backend.next_watch),
                _ => poison(&backend.watches),
            }
            assert_eq!(
                backend.watch(&record).await.unwrap_err(),
                Error::Unavailable
            );
            for _ in 0..crate::PUBLIC_WATCH_LIMIT {
                transport.store(0).watch(&record).await.unwrap();
            }
            assert_eq!(
                transport.store(0).watch(&record).await.unwrap_err(),
                Error::Unavailable
            );
        }
    });
}

#[test]
fn interruption_after_remote_acceptance_cancels_the_actual_remote_lease() {
    use std::task::{Context, Poll, Waker};

    block_on(async {
        let transport = SimNetwork::new(1, crate::Capacity::NATIVE);
        let backend = NetworkBackend::new(transport.clone(), TestVerifier);
        let descriptor = Descriptor::create(&crate::Schema::dflt(1).unwrap(), &key(46)).unwrap();
        let record = descriptor.key();
        backend.create(&descriptor).await.unwrap();
        let store = transport.store(0);
        store.create(&descriptor).await.unwrap();
        transport.pause_watch_replies(true);
        let mut request = std::pin::pin!(backend.watch(&record));
        assert!(matches!(
            request
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ));
        // The reply is pending, but the real node already owns one lease.
        for _ in 1..crate::PUBLIC_WATCH_LIMIT {
            store.watch(&record).await.unwrap();
        }
        assert_eq!(store.watch(&record).await.unwrap_err(), Error::Unavailable);
        poison(&backend.watches);
        transport.pause_watch_replies(false);
        assert_eq!(request.await.unwrap_err(), Error::Unavailable);
        // Cleanup frees precisely the accepted lease, leaving others untouched.
        store.watch(&record).await.unwrap();
        assert_eq!(store.watch(&record).await.unwrap_err(), Error::Unavailable);
    });
}

#[test]
fn interrupted_descriptor_and_inspection_state_refuse_authority() {
    block_on(async {
        let transport = SimNetwork::new(5, crate::Capacity::NATIVE);
        let descriptor = Descriptor::create(&crate::Schema::dflt(1).unwrap(), &key(49)).unwrap();
        let record = descriptor.key();
        let value =
            SignedValue::sign(&descriptor.owner, 0, 0, b"original".to_vec(), &key(49)).unwrap();
        for index in 0..5 {
            let store = transport.store(index);
            store.create(&descriptor).await.unwrap();
            store.set(&record, 0, &value).await.unwrap();
        }
        let backend = NetworkBackend::new(transport.clone(), TestVerifier);
        backend.create(&descriptor).await.unwrap();
        poison(&backend.descriptors);
        assert_eq!(
            backend.create(&descriptor).await.unwrap_err(),
            Error::Unavailable
        );
        assert_eq!(
            backend.descriptor(&record).await.unwrap_err(),
            Error::Unavailable
        );
        assert_eq!(
            backend.read(&record, 0).await.unwrap_err(),
            Error::Unavailable
        );
        let backend = NetworkBackend::new(transport.clone(), TestVerifier);
        backend.create(&descriptor).await.unwrap();
        poison(&backend.rechecked);
        assert_eq!(
            backend.rehydrate(&record, 0, &value).await.unwrap_err(),
            Error::Unavailable
        );
        // Local interruption never changes any independently owned record bytes.
        for index in 0..5 {
            assert_eq!(
                transport.store(index).get(&record, 0).await.unwrap(),
                Some(value.clone())
            );
        }
    });
}

#[test]
fn interruptions_during_real_inspection_never_become_successful_rechecks() {
    use std::task::{Context, Poll, Waker};
    block_on(async {
        for holders in [1, 5] {
            let transport = SimNetwork::new(5, crate::Capacity::NATIVE);
            let backend = NetworkBackend::new(transport.clone(), TestVerifier);
            let descriptor =
                Descriptor::create(&crate::Schema::dflt(1).unwrap(), &key(54)).unwrap();
            let record = descriptor.key();
            let value = SignedValue::sign(&descriptor.owner, 0, 0, vec![], &key(54)).unwrap();
            backend.create(&descriptor).await.unwrap();
            for index in 0..holders {
                transport.store(index).create(&descriptor).await.unwrap();
                transport
                    .store(index)
                    .set(&record, 0, &value)
                    .await
                    .unwrap();
            }
            transport.pause_get_replies(true);
            let mut request = std::pin::pin!(backend.rehydrate(&record, 0, &value));
            assert!(matches!(
                request
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop())),
                Poll::Pending
            ));
            poison(&backend.rechecked);
            transport.pause_get_replies(false);
            assert_eq!(request.await.unwrap_err(), Error::Unavailable);
            for index in 0..5 {
                assert_eq!(
                    transport.store(index).get(&record, 0).await.unwrap(),
                    Some(value.clone())
                );
            }
            let watch = backend.watch(&record).await.unwrap();
            poison(&backend.watches);
            assert_eq!(
                backend.cancel_watch(watch).await.unwrap_err(),
                Error::Unavailable
            );
            assert_eq!(
                backend.changes(watch).await.unwrap_err(),
                Error::Unavailable
            );
        }
    });
}

//! Original signed WatchValue/ENV0 authority with the ported bounded lease state.
mod common;
use cdht::{
    Descriptor, Error, Member, RecordKey, Schema, Signer,
    rpc::{
        Query, Question, SubkeyRanges, UnverifiedPeerInfoBytes,
        envelope::{AuthenticatedOperation, Envelope, TimeWindow},
        peers::{Advertisement, DHTV, DIRECT, ExtensionDialInfo},
    },
    watches::{InboundWatches, WatchLease, WatchLimits},
};
use common::{NodeCipher, TestVerifier, key};
use std::num::NonZeroUsize;

fn request(
    record: RecordKey,
    watcher: u8,
    node: u8,
    ranges: SubkeyRanges,
    duration: u64,
    count: u32,
    id: u64,
) -> AuthenticatedOperation {
    let node_key = key(node);
    let destination = key(250);
    let ad = UnverifiedPeerInfoBytes::sign_extension(
        Advertisement {
            timestamp_us: 100,
            capabilities: vec![DHTV],
            outbound_protocols: vec![u32::from_be_bytes(*b"TOR3")],
            address_types: vec![u32::from_be_bytes(*b"TOR3")],
            dial_info: vec![ExtensionDialInfo {
                class: DIRECT,
                protocol: u32::from_be_bytes(*b"TOR3"),
                detail: vec![7; 65],
            }],
        },
        &node_key,
    )
    .unwrap();
    let signed = Question::new(&Query::Watch {
        key: record,
        subkeys: ranges,
        duration_us: duration,
        count,
        watch_id: id,
    })
    .unwrap()
    .with_sender(&ad)
    .unwrap()
    .sign(&destination.public_key(), &key(watcher))
    .unwrap();
    let envelope = Envelope::seal(
        signed.as_bytes(),
        &destination.public_key(),
        100,
        &node_key,
        &NodeCipher(node),
    )
    .unwrap();
    Envelope::verify(
        envelope,
        &destination.public_key(),
        100,
        TimeWindow {
            behind_us: 0,
            ahead_us: 0,
        },
        &TestVerifier,
    )
    .unwrap()
    .open_operation(&NodeCipher(250), &TestVerifier)
    .unwrap()
}
fn ranges() -> SubkeyRanges {
    SubkeyRanges::from_iter([0, 1, 2])
}
fn limits(capacity: usize) -> WatchLimits {
    WatchLimits {
        min_duration_us: 10,
        max_duration_us: 100,
        ..WatchLimits::native(10, NonZeroUsize::new(capacity).unwrap())
    }
}
fn apply(
    table: &mut InboundWatches,
    descriptor: &Descriptor,
    watcher: u8,
    node: u8,
    count: u32,
    id: u64,
) -> WatchLease {
    table
        .apply(
            &request(descriptor.key(), watcher, node, ranges(), 0, count, id),
            descriptor,
            100,
            &TestVerifier,
        )
        .unwrap()
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn original_schema_member_and_public_quotas_use_independent_watcher_and_node_target() {
    let descriptor = Descriptor::create(
        &Schema::new(
            1,
            vec![Member {
                writer: key(2).public_key(),
                subkeys: 2,
            }],
        )
        .unwrap(),
        &key(1),
    )
    .unwrap();
    let mut table = InboundWatches::new(limits(100)).unwrap();
    for node in 10..18 {
        let lease = apply(&mut table, &descriptor, 1, node, 5, 0);
        assert_ne!(lease.id, 0);
        assert_eq!(lease.duration_us, 100);
    }
    assert_eq!(apply(&mut table, &descriptor, 1, 18, 5, 0).duration_us, 0);
    // A second schema member owns an independent eight-slot budget, even when
    // sharing a node target with the owner. The ninth is still rejected.
    for node in 10..18 {
        assert_eq!(
            apply(&mut table, &descriptor, 2, node, 5, 0).duration_us,
            100
        );
    }
    assert_eq!(apply(&mut table, &descriptor, 2, 19, 5, 0).duration_us, 0);
    // Anonymous watcher identities share one per-record budget and duplicate
    // target protection. Rotating a watcher key does not buy another slot.
    for node in 30..62 {
        assert_eq!(
            apply(&mut table, &descriptor, node + 100, node, 5, 0).duration_us,
            100
        );
    }
    assert_eq!(apply(&mut table, &descriptor, 190, 62, 5, 0).duration_us, 0);
    assert_eq!(apply(&mut table, &descriptor, 191, 30, 5, 0).duration_us, 0);
    let mut other = InboundWatches::new(limits(10)).unwrap();
    assert_eq!(apply(&mut other, &descriptor, 1, 10, 5, 0).duration_us, 100);
    assert_eq!(apply(&mut other, &descriptor, 1, 10, 5, 0).duration_us, 0);
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn renewal_cancellation_expiry_and_changes_keep_original_record_and_watcher_authority() {
    let descriptor = Descriptor::create(&Schema::dflt(3).unwrap(), &key(1)).unwrap();
    let mut table = InboundWatches::new(limits(2)).unwrap();
    let lease = apply(&mut table, &descriptor, 1, 10, 2, 0);
    assert_ne!(lease.id, 0);
    assert_eq!(
        apply(&mut table, &descriptor, 2, 10, 0, lease.id).duration_us,
        0
    );
    assert_eq!(
        apply(&mut table, &descriptor, 2, 11, 5, lease.id).duration_us,
        0
    );
    let wrong = Descriptor::create(&Schema::dflt(3).unwrap(), &key(2)).unwrap();
    assert_eq!(apply(&mut table, &wrong, 1, 10, 0, lease.id).duration_us, 0);
    assert!(matches!(
        table.apply(
            &request(wrong.key(), 1, 10, ranges(), 0, 2, 0),
            &descriptor,
            100,
            &TestVerifier
        ),
        Err(Error::WrongRecord)
    ));
    table.changed(
        &descriptor.key(),
        &SubkeyRanges::from_iter([0]),
        Some(&key(10).public_key()),
    );
    assert!(table.take_changes(100).unwrap().is_empty());
    table.changed(&descriptor.key(), &SubkeyRanges::from_iter([0]), None);
    table.changed(&descriptor.key(), &SubkeyRanges::from_iter([2]), None);
    let changes = table.take_changes(100).unwrap();
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].target, key(10).public_key());
    assert_eq!(changes[0].hint.key, descriptor.key());
    assert_eq!(changes[0].hint.watch_id, lease.id);
    assert_eq!(changes[0].hint.count, 1);
    assert_eq!(changes[0].hint.subkeys, SubkeyRanges::from_iter([0, 2]));
    assert!(changes[0].hint.value.is_none());
    let renewed = request(
        descriptor.key(),
        1,
        11,
        SubkeyRanges::from_iter([1]),
        40,
        1,
        lease.id,
    );
    assert_eq!(
        table
            .apply(&renewed, &descriptor, 110, &TestVerifier)
            .unwrap()
            .duration_us,
        40
    );
    table.changed(&descriptor.key(), &SubkeyRanges::from_iter([0]), None);
    assert!(table.take_changes(111).unwrap().is_empty());
    // An overlapping committed transaction contributes its entire changed range.
    table.changed(&descriptor.key(), &SubkeyRanges::from_iter([0, 1, 2]), None);
    let changes = table.take_changes(112).unwrap();
    assert_eq!(changes[0].target, key(11).public_key());
    assert_eq!(changes[0].hint.subkeys, ranges());
    assert_eq!(changes[0].hint.count, 0);
    assert!(table.take_changes(113).unwrap().is_empty());
    assert_eq!(
        table
            .apply(&renewed, &descriptor, 114, &TestVerifier)
            .unwrap()
            .duration_us,
        0
    );
    let new_request = request(descriptor.key(), 1, 10, ranges(), 10, 5, 0);
    let new = table
        .apply(&new_request, &descriptor, 120, &TestVerifier)
        .unwrap();
    table.changed(&descriptor.key(), &ranges(), None);
    assert!(table.take_changes(130).unwrap().is_empty());
    assert_eq!(
        table
            .apply(
                &request(descriptor.key(), 1, 10, ranges(), 0, 1, new.id),
                &descriptor,
                130,
                &TestVerifier
            )
            .unwrap()
            .duration_us,
        0
    );
    assert!(matches!(table.advance(129), Err(Error::Unavailable)));
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn watch_capacity_short_duration_and_eviction_refuse_without_false_leases() {
    let descriptor = Descriptor::create(&Schema::dflt(3).unwrap(), &key(1)).unwrap();
    let mut table = InboundWatches::new(limits(1)).unwrap();
    let lease = apply(&mut table, &descriptor, 1, 10, 5, 0);
    assert_eq!(apply(&mut table, &descriptor, 2, 11, 5, 0).duration_us, 0);
    let cancel = request(descriptor.key(), 1, 10, ranges(), 9, 5, lease.id);
    assert_eq!(
        table
            .apply(&cancel, &descriptor, 100, &TestVerifier)
            .unwrap()
            .duration_us,
        0
    );
    let next = apply(&mut table, &descriptor, 2, 11, 5, 0);
    assert_ne!(next.id, 0);
    assert_ne!(next.id, lease.id);
    table.remove_record(&descriptor.key());
    assert_eq!(
        apply(&mut table, &descriptor, 2, 11, 0, next.id).duration_us,
        0
    );
    let last = apply(&mut table, &descriptor, 1, 10, 5, 0);
    assert_eq!(
        apply(&mut table, &descriptor, 1, 10, 0, last.id).duration_us,
        0
    );
    table.changed(&descriptor.key(), &ranges(), None);
    assert!(table.take_changes(100).unwrap().is_empty());
    for min in [0, 51] {
        let mut invalid = limits(1);
        invalid.min_duration_us = min;
        assert!(InboundWatches::new(invalid).is_err());
    }
}

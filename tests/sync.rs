//! Sync rules: hybrid logical clock, per-device logs, tombstones, keep-both.

use cdht::Error;
use cdht::sync::{
    Clock, DeviceLog, ItemState, Op, Timestamp, decode_segments, encode_segments, merge,
};

const A: [u8; 32] = [0xa; 32];
const B: [u8; 32] = [0xb; 32];

fn put(value: &[u8]) -> Op {
    Op::Put {
        value: value.to_vec(),
    }
}

#[test]
fn clock_is_monotonic_even_when_wall_time_goes_back() {
    let mut clock = Clock::new(60_000);
    let t1 = clock.tick(1_000).unwrap();
    let t2 = clock.tick(1_000).unwrap();
    let t3 = clock.tick(500).unwrap();
    let t4 = clock.tick(2_000).unwrap();
    assert!(t1 < t2 && t2 < t3 && t3 < t4);
    assert_eq!(
        t3,
        Timestamp {
            wall: 1_000,
            counter: 2
        }
    );
    assert_eq!(
        t4,
        Timestamp {
            wall: 2_000,
            counter: 0
        }
    );
}

#[test]
fn clock_orders_after_observed_remote_times_and_rejects_drift() {
    let mut clock = Clock::new(1_000);
    clock.tick(10_000).unwrap();
    let remote = Timestamp {
        wall: 10_500,
        counter: 7,
    };
    clock.observe(remote, 10_000).unwrap();
    assert!(clock.tick(10_000).unwrap() > remote);
    assert_eq!(
        clock
            .observe(
                Timestamp {
                    wall: 20_000,
                    counter: 0
                },
                10_000
            )
            .unwrap_err(),
        Error::ClockDrift
    );
    let resumed = Clock::resume(clock.last(), 1_000);
    assert_eq!(resumed.last(), clock.last());
}

#[test]
fn edits_on_one_device_replace_each_other() {
    let mut clock = Clock::new(60_000);
    let mut log = DeviceLog::new(A);
    let first = log
        .append(&mut clock, 1, "contact/alice", vec![], put(b"v1"))
        .unwrap();
    log.append(&mut clock, 2, "contact/alice", vec![first], put(b"v2"))
        .unwrap();
    let state = merge(&[log]).unwrap();
    match &state["contact/alice"] {
        ItemState::Value { value, .. } => assert_eq!(value, b"v2"),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn concurrent_edits_keep_both_until_the_member_chooses() {
    let mut clock_a = Clock::new(60_000);
    let mut clock_b = Clock::new(60_000);
    let mut log_a = DeviceLog::new(A);
    let mut log_b = DeviceLog::new(B);
    let base = log_a
        .append(&mut clock_a, 1, "draft", vec![], put(b"original"))
        .unwrap();
    // Both devices edit the same version without seeing each other.
    log_a
        .append(&mut clock_a, 5, "draft", vec![base], put(b"edit on a"))
        .unwrap();
    log_b
        .append(&mut clock_b, 3, "draft", vec![base], put(b"edit on b"))
        .unwrap();
    let state = merge(&[log_a.clone(), log_b.clone()]).unwrap();
    let versions = match &state["draft"] {
        ItemState::Conflict(versions) => versions.clone(),
        other => panic!("unexpected {other:?}"),
    };
    let values: Vec<&[u8]> = versions.iter().map(|(_, v)| v.as_slice()).collect();
    assert_eq!(values, vec![&b"edit on b"[..], &b"edit on a"[..]]);

    // The member picks one: an edit based on both heads resolves the conflict.
    let heads = state["draft"].heads();
    assert_eq!(heads.len(), 2);
    log_b
        .append(&mut clock_b, 9, "draft", heads, put(b"edit on a"))
        .unwrap();
    match &merge(&[log_a, log_b]).unwrap()["draft"] {
        ItemState::Value { value, .. } => assert_eq!(value, b"edit on a"),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn tombstones_are_monotonic() {
    let mut clock_a = Clock::new(60_000);
    let mut clock_b = Clock::new(60_000);
    let mut log_a = DeviceLog::new(A);
    let mut log_b = DeviceLog::new(B);
    let created = log_a
        .append(&mut clock_a, 1, "block/mallory", vec![], put(b"blocked"))
        .unwrap();
    log_a
        .append(&mut clock_a, 2, "block/mallory", vec![created], Op::Delete)
        .unwrap();
    // A concurrent, later edit on B does not resurrect the item.
    log_b
        .append(
            &mut clock_b,
            50,
            "block/mallory",
            vec![created],
            put(b"edited"),
        )
        .unwrap();
    assert!(matches!(
        merge(&[log_a, log_b]).unwrap()["block/mallory"],
        ItemState::Deleted { .. }
    ));
}

#[test]
fn logs_are_validated() {
    let mut clock = Clock::new(60_000);
    let mut log = DeviceLog::new(A);
    log.append(&mut clock, 1, "x", vec![], put(b"1")).unwrap();
    log.append(&mut clock, 2, "y", vec![], put(b"2")).unwrap();
    log.validate().unwrap();

    let mut reordered = log.clone();
    reordered.entries.reverse();
    assert_eq!(reordered.validate().unwrap_err(), Error::InvalidLog);

    let mut foreign = log.clone();
    foreign.entries[0].stamp.author = B;
    assert_eq!(foreign.validate().unwrap_err(), Error::InvalidLog);

    // One log per author.
    assert_eq!(
        merge(&[log.clone(), log.clone()]).unwrap_err(),
        Error::InvalidLog
    );
    assert_eq!(
        log.append(&mut clock, 3, "", vec![], put(b"")).unwrap_err(),
        Error::Encoding
    );
}

#[test]
fn compaction_keeps_the_merged_state() {
    let mut clock_a = Clock::new(60_000);
    let mut clock_b = Clock::new(60_000);
    let mut log_a = DeviceLog::new(A);
    let mut log_b = DeviceLog::new(B);
    let mut last = log_a
        .append(&mut clock_a, 1, "setting/theme", vec![], put(b"light"))
        .unwrap();
    for (i, value) in [&b"dark"[..], b"sepia", b"dark"].iter().enumerate() {
        last = log_a
            .append(
                &mut clock_a,
                2 + i as u64,
                "setting/theme",
                vec![last],
                put(value),
            )
            .unwrap();
    }
    let gone = log_a
        .append(&mut clock_a, 10, "contact/old", vec![], put(b"x"))
        .unwrap();
    log_b
        .append(&mut clock_b, 11, "contact/old", vec![gone], Op::Delete)
        .unwrap();
    let before = merge(&[log_a.clone(), log_b.clone()]).unwrap();
    let compacted = log_a.compact(&[log_a.clone(), log_b.clone()]);
    assert_eq!(compacted.entries.len(), 1);
    assert_eq!(merge(&[compacted, log_b]).unwrap(), before);
}

#[test]
fn logs_split_into_subkey_segments() {
    let mut clock = Clock::new(60_000);
    let mut log = DeviceLog::new(A);
    for i in 0..40u64 {
        log.append(
            &mut clock,
            i,
            &format!("message/{i}"),
            vec![],
            put(&[7u8; 100]),
        )
        .unwrap();
    }
    let segments = encode_segments(&log, 2_048, 16).unwrap();
    assert!(segments.len() > 1);
    assert!(segments.iter().all(|s| s.len() <= 2_048));
    let slots: Vec<Option<Vec<u8>>> = segments.into_iter().map(Some).chain([None]).collect();
    assert_eq!(decode_segments(&A, &slots).unwrap(), log);
    assert_eq!(decode_segments(&B, &slots).unwrap_err(), Error::InvalidLog);
    assert_eq!(encode_segments(&log, 2_048, 2).unwrap_err(), Error::LogFull);
    assert_eq!(
        encode_segments(&log, 64, 100).unwrap_err(),
        Error::ValueTooLarge
    );
    let empty = encode_segments(&DeviceLog::new(A), 2_048, 1).unwrap();
    assert_eq!(empty.len(), 1);
    assert_eq!(
        decode_segments(&A, &[Some(empty[0].clone())]).unwrap(),
        DeviceLog::new(A)
    );
}

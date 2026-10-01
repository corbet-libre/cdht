//! Hostile external wire structures use the actual upstream generated schema.
use super::*;
use crate::test_crypto as common;
use common::{TestVerifier, key};
fn authenticate(builder: Builder<HeapAllocator>) -> SignedOperation {
    let owner = key(1);
    SignedOperation::sign(bytes(builder).unwrap(), &key(2).public_key(), &owner).unwrap()
}
#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn rpc_refuses_wrong_kinds_malformed_payloads_and_unknown_questions() {
    let owner = key(1);
    let descriptor = Descriptor::create(&crate::Schema::dflt(1).unwrap(), &owner).unwrap();
    let mut value =
        SignedValue::sign(&owner.public_key(), 0, 0, b"record".to_vec(), &owner).unwrap();
    let mut trailing = ValueBytes::encode(&value).unwrap().as_bytes().to_vec();
    trailing.extend_from_slice(&[0; 8]);
    assert!(ValueBytes::from_bytes(trailing).is_err());
    value = SignedValue::from_blob(value.raw_blob().unwrap(), value.signature).unwrap();
    value.data.push(1);
    assert!(ValueBytes::encode(&value).is_err());
    let mut builder = Builder::new_default();
    let mut root = builder.init_root::<wire::signed_value_data::Builder>();
    root.set_value_data(&[]);
    root.init_signature().set_kind(0);
    assert!(ValueBytes::from_bytes(bytes(builder).unwrap()).is_err());
    let mut builder = Builder::new_default();
    let mut root = builder.init_root::<wire::signed_value_descriptor::Builder>();
    let mut owner_key = root.reborrow().init_owner();
    owner_key.set_kind(KIND);
    owner_key.set_value(&[0; 31]);
    root.init_signature().set_kind(KIND);
    assert!(DescriptorBytes::from_bytes(bytes(builder).unwrap()).is_err());
    let mut builder = Builder::new_default();
    builder
        .init_root::<wire::operation::Builder>()
        .get_kind()
        .init_answer();
    assert!(query(&authenticate(builder)).is_err());
    let mut builder = Builder::new_default();
    let mut question = builder
        .init_root::<wire::operation::Builder>()
        .get_kind()
        .init_question();
    question.reborrow().get_respond_to().init_private_route();
    question.get_detail().init_get_value_q();
    assert!(query(&authenticate(builder)).is_err());
    let mut builder = Builder::new_default();
    let mut question = builder
        .init_root::<wire::operation::Builder>()
        .get_kind()
        .init_question();
    question.reborrow().get_respond_to().set_sender(());
    question.get_detail().init_status_q();
    assert!(query(&authenticate(builder)).is_err());
    let value = SignedValue::sign(&owner.public_key(), 0, 0, b"record".to_vec(), &owner).unwrap();
    assert!(
        Question::new(&Query::Set {
            key: crate::RecordKey([0; 32]),
            subkey: 0,
            value: Box::new(value.clone()),
            descriptor: Some(descriptor.clone())
        })
        .is_err()
    );
    let question = Question::new(&Query::Set {
        key: descriptor.key(),
        subkey: 0,
        value: Box::new(value),
        descriptor: None,
    })
    .unwrap();
    let operation = question.sign(&key(2).public_key(), &owner).unwrap();
    assert!(matches!(
        query(&operation).unwrap().1,
        Query::Set {
            descriptor: None,
            ..
        }
    ));
    assert!(
        SignedOperation::verify(
            vec![0; MAX_RPC_BYTES + 1],
            &key(2).public_key(),
            &owner.public_key(),
            &TestVerifier
        )
        .is_err()
    );
    let mut builder = Builder::new_default();
    builder
        .init_root::<wire::signed_value_data::Builder>()
        .set_value_data(&vec![0; MAX_RPC_BYTES]);
    assert!(bytes(builder).is_err());
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn raw_upstream_values_refuse_reserved_sequences_wrong_kinds_and_nonce_lengths() {
    for (seq, length, kind, writer_len, nonce_len, expected) in [
        (u32::MAX, 0, KIND, 32, 24, Error::SeqExhausted),
        (
            0,
            crate::MAX_SUBKEY_SIZE + 1,
            KIND,
            32,
            24,
            Error::ValueTooLarge,
        ),
        (0, 0, 0, 32, 24, Error::Encoding),
        (0, 0, KIND, 31, 24, Error::Encoding),
        (0, 0, KIND, 32, 23, Error::Encoding),
    ] {
        let mut message = Builder::new_default();
        let mut value = message.init_root::<wire::value_data::Builder>();
        value.set_seq(seq);
        value.set_data(&vec![0; length]);
        let mut writer = value.reborrow().init_writer();
        writer.set_kind(kind);
        writer.set_value(&vec![0; writer_len]);
        value.init_nonce().set_value(&vec![0; nonce_len]);
        // These are hostile external upstream wire bytes, never our domain fakes.
        let blob = capnp::serialize::write_message_to_words(&message);
        assert_eq!(SignedValue::from_blob(blob, [0; 64]).unwrap_err(), expected);
    }
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn answer_peer_hints_preserve_opaque_bytes_without_asserting_node_authority() {
    // Deliberately not valid NodeInfo: the codec must not invent routing authority
    // for an opaque hint. The routing owner must independently reject this body.
    let body = b"unverified external node-info message";
    let mut peer = Builder::new_default();
    let mut root = peer.init_root::<wire::peer_info::Builder>();
    root.set_node_info_message(body);
    let mut signatures = root.init_signatures(1);
    let mut signature = signatures.reborrow().get(0);
    signature.set_kind(KIND);
    signature.set_value(&key(2).sign(body).unwrap());
    let encoded = bytes(peer).unwrap();
    let owner = key(1);
    let descriptor = Descriptor::create(&crate::Schema::dflt(1).unwrap(), &owner).unwrap();
    for query in [
        Query::Get {
            key: descriptor.key(),
            subkey: 0,
            want_descriptor: true,
        },
        Query::Set {
            key: descriptor.key(),
            subkey: 0,
            value: Box::new(SignedValue::sign(&owner.public_key(), 0, 0, vec![], &owner).unwrap()),
            descriptor: Some(descriptor.clone()),
        },
        Query::Watch {
            key: descriptor.key(),
            subkeys: SubkeyRanges::new(),
            duration_us: 1,
            count: 1,
            watch_id: 0,
        },
    ] {
        let get = matches!(query, Query::Get { .. });
        let watch = matches!(query, Query::Watch { .. });
        let question = Question::new(&query).unwrap();
        let request = question.sign(&key(2).public_key(), &owner).unwrap();
        for count in [1, 20, 21] {
            let peers = (0..count)
                .map(|_| UnverifiedPeerInfoBytes::from_bytes(encoded.clone()).unwrap())
                .collect();
            let response = if watch {
                Response::Watch {
                    accepted: false,
                    duration_us: 0,
                    watch_id: 0,
                    peers,
                }
            } else if get {
                Response::Get {
                    accepted: false,
                    value: None,
                    descriptor: None,
                    peers,
                }
            } else {
                Response::Set {
                    accepted: false,
                    need_descriptor: true,
                    value: None,
                    peers,
                }
            };
            let answer = Answer::new(&request, &response);
            if count == 21 {
                assert!(answer.is_err());
                continue;
            }
            let answer = answer.unwrap().sign(&owner.public_key(), &key(2)).unwrap();
            let response = question
                .answer(&answer, Some(&descriptor), &TestVerifier)
                .unwrap();
            let peers = match response {
                Response::Get { peers, .. }
                | Response::Set { peers, .. }
                | Response::Watch { peers, .. } => peers,
            };
            assert_eq!(peers.len(), count);
            for peer in peers {
                assert_eq!(peer.as_bytes(), encoded);
            }
        }
    }
    assert!(UnverifiedPeerInfoBytes::from_bytes(vec![]).is_err());
    let mut wrong_root = Builder::new_default();
    wrong_root.init_root::<capnp::text::Builder>();
    assert!(matches!(
        UnverifiedPeerInfoBytes::from_bytes(bytes(wrong_root).unwrap()),
        Err(Error::Encoding)
    ));
    let mut peer = Builder::new_default();
    peer.init_root::<wire::peer_info::Builder>()
        .set_node_info_message(body);
    assert!(UnverifiedPeerInfoBytes::from_bytes(bytes(peer).unwrap()).is_err());
    let mut peer = Builder::new_default();
    peer.init_root::<wire::peer_info::Builder>()
        .init_signatures(0);
    assert!(UnverifiedPeerInfoBytes::from_bytes(bytes(peer).unwrap()).is_err());
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn watch_questions_preserve_ranges_duration_count_and_node_scoped_lease() {
    for (duration_us, count, watch_id) in [(0, 1, 0), (5_000_000, u32::MAX, 0), (u64::MAX, 0, 7)] {
        for subkeys in [
            SubkeyRanges::new(),
            SubkeyRanges::from_iter([0, 1, 5]),
            SubkeyRanges::from_iter(std::iter::once(0..=u32::MAX)),
            SubkeyRanges::from_iter((0..512).map(|n| n * 2)),
        ] {
            let request = Query::Watch {
                key: crate::RecordKey([9; 32]),
                subkeys: subkeys.clone(),
                duration_us,
                count,
                watch_id,
            };
            let question = Question::new(&request).unwrap();
            let sent = question.sign(&key(2).public_key(), &key(1)).unwrap();
            let (
                id,
                Query::Watch {
                    key: locator,
                    subkeys: decoded,
                    duration_us: got_duration,
                    count: got_count,
                    watch_id: got_id,
                },
            ) = query(&sent).unwrap()
            else {
                panic!("watch");
            };
            assert_eq!(id, question.id());
            assert_eq!(locator, crate::RecordKey([9; 32]));
            assert_eq!(decoded, subkeys);
            assert_eq!(
                (got_duration, got_count, got_id),
                (duration_us, count, watch_id)
            );
            let response = Response::Watch {
                accepted: true,
                duration_us: 5_000_000,
                watch_id: 7,
                peers: vec![],
            };
            let answer = Answer::new(&sent, &response)
                .unwrap()
                .sign(&key(1).public_key(), &key(2))
                .unwrap();
            let response = question.answer(&answer, None, &TestVerifier).unwrap();
            assert!(matches!(
                response,
                Response::Watch {
                    accepted: true,
                    duration_us: 5_000_000,
                    watch_id: 7,
                    ..
                }
            ));
        }
    }
    for (subkeys, count, watch_id) in [
        (SubkeyRanges::new(), 0, 0),
        (SubkeyRanges::from_iter((0..513).map(|n| n * 2)), 1, 0),
    ] {
        assert!(
            Question::new(&Query::Watch {
                key: crate::RecordKey([9; 32]),
                subkeys,
                duration_us: 1,
                count,
                watch_id
            })
            .is_err()
        );
    }
    for ranges in [
        vec![(2, 1)],
        vec![(1, 2), (2, 3)],
        vec![(5, 7), (0, 1)],
        (0..513).map(|n| (2 * n, 2 * n)).collect(),
    ] {
        let mut builder = Builder::new_default();
        let mut q = builder
            .init_root::<wire::operation::Builder>()
            .get_kind()
            .init_question()
            .get_detail()
            .init_watch_value_q();
        key_encode(&crate::RecordKey([9; 32]), q.reborrow().init_key());
        q.set_count(1);
        let mut wire_ranges = q.init_subkeys(ranges.len() as u32);
        for (i, (start, end)) in ranges.into_iter().enumerate() {
            let mut entry = wire_ranges.reborrow().get(i as u32);
            entry.set_start(start);
            entry.set_end(end);
        }
        assert!(query(&authenticate(builder)).is_err());
    }
    for (has_key, has_ranges) in [(false, false), (true, false), (false, true), (true, true)] {
        let mut builder = Builder::new_default();
        let mut q = builder
            .init_root::<wire::operation::Builder>()
            .get_kind()
            .init_question()
            .get_detail()
            .init_watch_value_q();
        if has_key {
            key_encode(&crate::RecordKey([9; 32]), q.reborrow().init_key());
        }
        if has_ranges {
            q.reborrow().init_subkeys(0);
        }
        // Absent fields or cancellation without an existing lease are refused.
        assert!(query(&authenticate(builder)).is_err());
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
#[ignore = "requires actual upstream oracle; mandatory conformance CI"]
fn upstream_watch_vectors() {
    let path = std::env::var("CDHT_VECTORS").unwrap();
    let vectors: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let decode = |v: &serde_json::Value| {
        data_encoding::BASE64URL_NOPAD
            .decode(v.as_str().unwrap().as_bytes())
            .unwrap()
    };
    for encoded in std::iter::once(&vectors["changeCancelled"]).chain(
        vectors["values"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| &v["valueChanged"]),
    ) {
        let operation =
            SignedOperation::sign(decode(encoded), &key(2).public_key(), &key(1)).unwrap();
        let (id, hint) = value_changed(&operation).unwrap();
        assert_eq!(
            Statement::encode(&hint, id).unwrap().as_bytes(),
            operation.operation()
        );
    }
    for vector in vectors["watches"].as_array().unwrap() {
        let operation =
            SignedOperation::sign(decode(&vector["question"]), &key(2).public_key(), &key(1))
                .unwrap();
        let (id, request) = query(&operation).unwrap();
        assert!(matches!(request, Query::Watch { .. }));
        assert_eq!(
            Question::encode(&request, id).unwrap().as_bytes(),
            operation.operation()
        );
        let response = Response::Watch {
            accepted: true,
            duration_us: 5_000_000,
            watch_id: 7,
            peers: vec![],
        };
        assert_eq!(
            Answer::new(&operation, &response).unwrap().as_bytes(),
            decode(&vector["answer"])
        );
    }
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn authenticated_nodes_cannot_return_wrong_answer_kinds_or_unbounded_peer_lists() {
    let owner = key(1);
    let descriptor = Descriptor::create(&crate::Schema::dflt(1).unwrap(), &owner).unwrap();
    for kind in 0..3 {
        let request = match kind {
            0 => Query::Get {
                key: descriptor.key(),
                subkey: 0,
                want_descriptor: true,
            },
            1 => Query::Set {
                key: descriptor.key(),
                subkey: 0,
                value: Box::new(
                    SignedValue::sign(&owner.public_key(), 0, 0, vec![], &owner).unwrap(),
                ),
                descriptor: Some(descriptor.clone()),
            },
            _ => Query::Watch {
                key: descriptor.key(),
                subkeys: SubkeyRanges::new(),
                duration_us: 1,
                count: 1,
                watch_id: 0,
            },
        };
        let question = Question::new(&request).unwrap();
        for oversized in [false, true] {
            let mut builder = Builder::new_default();
            let mut operation = builder.init_root::<wire::operation::Builder>();
            operation.set_op_id(question.id());
            let detail = operation.get_kind().init_answer().get_detail();
            if oversized {
                match kind {
                    0 => {
                        detail.init_get_value_a().init_peers(21);
                    }
                    1 => {
                        detail.init_set_value_a().init_peers(21);
                    }
                    _ => {
                        detail.init_watch_value_a().init_peers(21);
                    }
                }
            } else {
                detail.init_status_a();
            }
            let answer =
                SignedOperation::sign(bytes(builder).unwrap(), &owner.public_key(), &key(2))
                    .unwrap();
            assert!(matches!(
                question.answer(&answer, Some(&descriptor), &TestVerifier),
                Err(Error::Encoding)
            ));
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn malformed_or_unrelated_statements_cannot_become_change_hints() {
    for kind in 0..4 {
        let mut builder = Builder::new_default();
        let detail = builder
            .init_root::<wire::operation::Builder>()
            .get_kind()
            .init_statement()
            .get_detail();
        if kind == 0 {
            detail.init_app_message();
        } else {
            let mut changed = detail.init_value_changed();
            if kind >= 2 {
                key_encode(&crate::RecordKey([9; 32]), changed.reborrow().init_key());
            }
            if kind == 2 {
                changed.reborrow().init_subkeys(0);
            }
        }
        assert!(value_changed(&authenticate(builder)).is_err());
    }
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn valid_node_signatures_do_not_make_corrupted_operation_bodies_valid() {
    let owner = key(1);
    let descriptor = Descriptor::create(&crate::Schema::dflt(1).unwrap(), &owner).unwrap();
    let value = SignedValue::sign(&descriptor.owner, 0, 0, vec![7; 64], &owner).unwrap();
    let mut operations = Vec::new();
    let get = Question::new(&Query::Get {
        key: descriptor.key(),
        subkey: 0,
        want_descriptor: true,
    })
    .unwrap();
    operations.push(get.as_bytes().to_vec());
    let set = Question::new(&Query::Set {
        key: descriptor.key(),
        subkey: 0,
        value: Box::new(value.clone()),
        descriptor: Some(descriptor.clone()),
    })
    .unwrap();
    operations.push(set.as_bytes().to_vec());
    operations.push(
        Answer::new(
            &set.sign(&key(2).public_key(), &owner).unwrap(),
            &Response::Set {
                accepted: true,
                need_descriptor: false,
                value: Some(Box::new(value.clone())),
                peers: vec![],
            },
        )
        .unwrap()
        .as_bytes()
        .to_vec(),
    );
    operations.push(
        Question::new(&Query::Watch {
            key: descriptor.key(),
            subkeys: SubkeyRanges::new(),
            duration_us: 1,
            count: 1,
            watch_id: 0,
        })
        .unwrap()
        .as_bytes()
        .to_vec(),
    );
    operations.push(
        Answer::new(
            &get.sign(&key(2).public_key(), &owner).unwrap(),
            &Response::Get {
                accepted: true,
                value: Some(Box::new(value.clone())),
                descriptor: Some(descriptor.clone()),
                peers: vec![],
            },
        )
        .unwrap()
        .as_bytes()
        .to_vec(),
    );
    operations.push(
        Statement::value_changed(&ChangeHint {
            key: descriptor.key(),
            subkeys: SubkeyRanges::from_iter([0]),
            count: 1,
            watch_id: 1,
            value: Some(Box::new(value)),
        })
        .unwrap()
        .as_bytes()
        .to_vec(),
    );
    let mut authenticated = 0;
    let mut refused = 0;
    for original in operations {
        for (index, mask) in
            (0..original.len()).flat_map(|index| [1, 0xff].map(|mask| (index, mask)))
        {
            let mut changed = original.clone();
            changed[index] ^= mask;
            // An adversarial node signs its actual malformed body using real VLD0.
            let Ok(operation) = SignedOperation::sign(changed, &key(2).public_key(), &owner) else {
                continue;
            };
            let verified = SignedOperation::verify(
                operation.as_bytes().to_vec(),
                &key(2).public_key(),
                &owner.public_key(),
                &TestVerifier,
            )
            .unwrap();
            authenticated += 1;
            if query(&verified).is_err() {
                refused += 1;
            }
            if get
                .answer(&verified, Some(&descriptor), &TestVerifier)
                .is_err()
            {
                refused += 1;
            }
            if set
                .answer(&verified, Some(&descriptor), &TestVerifier)
                .is_err()
            {
                refused += 1;
            }
            if value_changed(&verified).is_err() {
                refused += 1;
            }
        }
    }
    assert!(authenticated > 100);
    assert!(refused > authenticated);
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn both_unpacked_and_packed_message_bounds_are_enforced() {
    fn message(length: usize) -> Builder<HeapAllocator> {
        let mut message = Builder::new(HeapAllocator::new().first_segment_words(8192));
        message
            .init_root::<wire::signed_operation::Builder>()
            .set_operation_data(&vec![0x55; length]);
        message
    }
    assert!(matches!(
        bytes(message(MAX_RPC_BYTES + 1024)),
        Err(Error::ValueTooLarge)
    ));
    let mut expanded = false;
    for length in MAX_RPC_BYTES - 128..MAX_RPC_BYTES {
        if bytes(message(length)).is_ok()
            && matches!(packed(message(length)), Err(Error::ValueTooLarge))
        {
            expanded = true;
            break;
        }
    }
    assert!(
        expanded,
        "nonzero Cap'n Proto words can expand under packed encoding"
    );
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn opaque_peer_hints_keep_unknown_pointer_copy_failures_fallible() {
    let mut message = Builder::new_default();
    let mut peer = message.init_root::<wire::peer_info::Builder>();
    peer.set_node_info_message(b"untrusted node info");
    let mut list = peer.init_signatures(1);
    let mut signature = list.reborrow().get(0);
    signature.set_kind(KIND);
    signature.set_value(&[17; 64]);
    let original = bytes(message).unwrap();
    let question = Question::new(&Query::Get {
        key: crate::RecordKey([7; 32]),
        subkey: 0,
        want_descriptor: false,
    })
    .unwrap();
    let signed = question.sign(&key(2).public_key(), &key(1)).unwrap();
    // The generated fixture has a one-segment PeerInfo root with two pointers.
    // Increase only the actual signature list's declared word/pointer counts.
    // Its known value pointer remains valid, while an extra unknown pointer
    // aliases 0x11 bytes in the existing signature data and is malformed.
    // This is corruption of upstream output, not a replacement wire encoder.
    assert_eq!(&original[..4], &[0; 4]);
    let list_pointer = 24;
    let low = u32::from_le_bytes(original[list_pointer..list_pointer + 4].try_into().unwrap());
    assert_eq!(low & 3, 1);
    let tag = (list_pointer as i32 + 8 + ((low as i32) >> 2) * 8) as usize;
    let mut changed = original;
    assert_eq!(
        u32::from_le_bytes(
            changed[list_pointer + 4..list_pointer + 8]
                .try_into()
                .unwrap()
        ),
        (2 << 3) | 7
    );
    assert_eq!(
        u16::from_le_bytes(changed[tag + 6..tag + 8].try_into().unwrap()),
        1
    );
    changed[list_pointer + 4..list_pointer + 8].copy_from_slice(&((3u32 << 3) | 7).to_le_bytes());
    changed[tag + 6..tag + 8].copy_from_slice(&2u16.to_le_bytes());
    let peer = UnverifiedPeerInfoBytes::from_bytes(changed).unwrap();
    let response = Response::Get {
        accepted: false,
        value: None,
        descriptor: None,
        peers: vec![peer],
    };
    assert!(matches!(
        Answer::new(&signed, &response),
        Err(Error::Encoding)
    ));
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn peer_signature_count_obeys_the_upstream_bound_before_iteration() {
    for count in [0, 1, 3, 4] {
        let mut message = Builder::new_default();
        let mut peer = message.init_root::<wire::peer_info::Builder>();
        peer.set_node_info_message(b"opaque routing body");
        let mut signatures = peer.init_signatures(count);
        for index in 0..count {
            signatures.reborrow().get(index).set_value(&[17; 64]);
        }
        assert_eq!(
            UnverifiedPeerInfoBytes::from_bytes(bytes(message).unwrap()).is_ok(),
            count <= 3
        );
    }
}

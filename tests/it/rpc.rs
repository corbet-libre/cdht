//! Original signed record and upstream RPC bytes, native and actual Wasm.
use crate::common::{TestVerifier, key};
use cdht::rpc::{Answer, Response};
use cdht::rpc::{DescriptorBytes, Query, Question, SignedOperation, ValueBytes, query};
use cdht::{Backend, LocalBackend, SetOutcome};
use cdht::{Descriptor, Error, Schema, SignedValue, Signer};
#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn opaque_bytes_preserve_nonce_signature_and_original_value_blob() {
    let owner = key(1);
    let target = key(2).public_key();
    let descriptor = Descriptor::create(&Schema::dflt(1).unwrap(), &owner).unwrap();
    let key = descriptor.key();
    for size in [0, 1, 32768] {
        let value = SignedValue::sign_with_nonce(
            &owner.public_key(),
            0,
            7,
            vec![42; size],
            Some([3; 24]),
            &owner,
        )
        .unwrap();
        let original = value.raw_blob().unwrap();
        let signature = value.signature;
        let encoded = ValueBytes::encode(&value).unwrap();
        let copied = ValueBytes::from_bytes(encoded.as_bytes().to_vec()).unwrap();
        let decoded = copied.decode().unwrap();
        assert_eq!(decoded.raw_blob().unwrap(), original);
        assert_eq!(decoded.signature, signature);
        assert_eq!(decoded.nonce, Some([3; 24]));
        let desc = DescriptorBytes::encode(&descriptor).unwrap();
        let desc = DescriptorBytes::from_bytes(desc.as_bytes().to_vec())
            .unwrap()
            .decode()
            .unwrap();
        assert_eq!(desc, descriptor);
        let q = Question::new(&Query::Set {
            key,
            subkey: 0,
            value: Box::new(decoded),
            descriptor: Some(desc),
        })
        .unwrap();
        let packet = q.sign(&target, &owner).unwrap();
        let authenticated = SignedOperation::verify(
            packet.as_bytes().to_vec(),
            &target,
            &owner.public_key(),
            &TestVerifier,
        )
        .unwrap();
        assert_eq!(authenticated.as_bytes(), packet.as_bytes());
        assert_eq!(authenticated.operation(), q.as_bytes());
        assert_eq!(authenticated.signer(), &owner.public_key());
        let (
            id,
            Query::Set {
                key: got,
                subkey,
                value,
                descriptor,
            },
        ) = query(&authenticated).unwrap()
        else {
            panic!("set")
        };
        assert_eq!(id, q.id());
        assert_eq!(got, key);
        assert_eq!(subkey, 0);
        assert_eq!(descriptor.unwrap().key(), key);
        assert_eq!(value.raw_blob().unwrap(), original);
        assert_eq!(value.signature, signature);
    }
}
#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn rpc_binding_refuses_other_signer_destination_and_trailing_input() {
    let owner = key(1);
    let target = key(2).public_key();
    let stranger = key(3).public_key();
    let key = Descriptor::create(&Schema::dflt(1).unwrap(), &owner)
        .unwrap()
        .key();
    let q = Question::new(&Query::Get {
        key,
        subkey: 0,
        want_descriptor: true,
    })
    .unwrap();
    let packet = q.sign(&target, &owner).unwrap();
    let mut trailing = packet.as_bytes().to_vec();
    trailing.push(0);
    assert!(matches!(
        SignedOperation::verify(
            packet.as_bytes().to_vec(),
            &stranger,
            &owner.public_key(),
            &TestVerifier
        ),
        Err(Error::BadSignature)
    ));
    assert!(matches!(
        SignedOperation::verify(
            packet.as_bytes().to_vec(),
            &target,
            &stranger,
            &TestVerifier
        ),
        Err(Error::BadSignature)
    ));
    assert!(
        SignedOperation::verify(trailing, &target, &owner.public_key(), &TestVerifier).is_err()
    );
    let packet = SignedOperation::verify(
        packet.as_bytes().to_vec(),
        &target,
        &owner.public_key(),
        &TestVerifier,
    )
    .unwrap();
    let (
        id,
        Query::Get {
            key: got,
            subkey,
            want_descriptor,
        },
    ) = query(&packet).unwrap()
    else {
        panic!("get")
    };
    assert_eq!(id, q.id());
    assert_eq!(got, key);
    assert_eq!(subkey, 0);
    assert!(want_descriptor);
    assert!(SignedOperation::sign(vec![], &target, &owner).is_err());
    assert!(ValueBytes::from_bytes(vec![0; cdht::rpc::MAX_RPC_BYTES + 1]).is_err());
    assert!(DescriptorBytes::from_bytes(vec![]).is_err());
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn original_answers_roundtrip_through_an_independent_record_store() {
    futures_executor::block_on(async {
        let owner = key(1);
        let node = key(2);
        let descriptor = Descriptor::create(&Schema::dflt(1).unwrap(), &owner).unwrap();
        let store = LocalBackend::new(TestVerifier);
        store.create(&descriptor).await.unwrap();
        let value = SignedValue::sign_with_nonce(
            &owner.public_key(),
            0,
            4,
            b"opaque ciphertext".to_vec(),
            Some([7; 24]),
            &owner,
        )
        .unwrap();
        let original = value.raw_blob().unwrap();
        let set = Question::new(&Query::Set {
            key: descriptor.key(),
            subkey: 0,
            value: Box::new(value.clone()),
            descriptor: Some(descriptor.clone()),
        })
        .unwrap();
        let sent = set.sign(&node.public_key(), &owner).unwrap();
        let received = SignedOperation::verify(
            sent.as_bytes().to_vec(),
            &node.public_key(),
            &owner.public_key(),
            &TestVerifier,
        )
        .unwrap();
        let (
            _,
            Query::Set {
                key: locator,
                subkey,
                value: offered,
                descriptor: offered_descriptor,
            },
        ) = query(&received).unwrap()
        else {
            panic!("set")
        };
        assert_eq!(offered.raw_blob().unwrap(), original);
        let outcome = store.set(&locator, subkey, &offered).await.unwrap();
        assert!(matches!(outcome, SetOutcome::Accepted));
        assert_eq!(offered_descriptor.unwrap(), descriptor);
        let response = Response::Set {
            accepted: true,
            need_descriptor: false,
            value: None,
            peers: vec![],
        };
        let answer = Answer::new(&received, &response).unwrap();
        let signed = answer.sign(&owner.public_key(), &node).unwrap();
        let arrived = SignedOperation::verify(
            signed.as_bytes().to_vec(),
            &owner.public_key(),
            &node.public_key(),
            &TestVerifier,
        )
        .unwrap();
        assert_eq!(arrived.operation(), answer.as_bytes());
        assert!(matches!(
            set.answer(&arrived, None, &TestVerifier).unwrap(),
            Response::Set {
                accepted: true,
                need_descriptor: false,
                value: None,
                ..
            }
        ));
        let get = Question::new(&Query::Get {
            key: locator,
            subkey: 0,
            want_descriptor: true,
        })
        .unwrap();
        let sent = get.sign(&node.public_key(), &owner).unwrap();
        let received = SignedOperation::verify(
            sent.as_bytes().to_vec(),
            &node.public_key(),
            &owner.public_key(),
            &TestVerifier,
        )
        .unwrap();
        let response = Response::Get {
            accepted: true,
            value: store.get(&locator, 0).await.unwrap().map(Box::new),
            descriptor: store.descriptor(&locator).await.unwrap(),
            peers: vec![],
        };
        let answer = Answer::new(&received, &response)
            .unwrap()
            .sign(&owner.public_key(), &node)
            .unwrap();
        let arrived = SignedOperation::verify(
            answer.as_bytes().to_vec(),
            &owner.public_key(),
            &node.public_key(),
            &TestVerifier,
        )
        .unwrap();
        let Response::Get {
            accepted,
            value: Some(value),
            descriptor: Some(returned),
            peers,
        } = get
            .answer(&arrived, Some(&descriptor), &TestVerifier)
            .unwrap()
        else {
            panic!("get")
        };
        assert!(accepted);
        assert!(peers.is_empty());
        assert_eq!(returned, descriptor);
        assert_eq!(value.raw_blob().unwrap(), original);
        assert_eq!(value.nonce, Some([7; 24]));
        let unrelated = Question::new(&Query::Get {
            key: locator,
            subkey: 0,
            want_descriptor: true,
        })
        .unwrap();
        assert!(
            unrelated
                .answer(&arrived, Some(&descriptor), &TestVerifier)
                .is_err()
        );
        assert!(
            Answer::new(
                &received,
                &Response::Set {
                    accepted: true,
                    need_descriptor: false,
                    value: None,
                    peers: vec![]
                }
            )
            .is_err()
        );
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn authenticated_responder_cannot_substitute_records_or_unsigned_values() {
    let owner = key(1);
    let node = key(2);
    let descriptor = Descriptor::create(&Schema::dflt(2).unwrap(), &owner).unwrap();
    let value = SignedValue::sign(&owner.public_key(), 0, 2, vec![42], &owner).unwrap();
    let get = Question::new(&Query::Get {
        key: descriptor.key(),
        subkey: 0,
        want_descriptor: true,
    })
    .unwrap();
    let request = get.sign(&node.public_key(), &owner).unwrap();
    let answer = |response| {
        Answer::new(&request, &response)
            .unwrap()
            .sign(&owner.public_key(), &node)
            .unwrap()
    };
    let missing = answer(Response::Get {
        accepted: false,
        value: None,
        descriptor: None,
        peers: vec![],
    });
    assert!(matches!(
        get.answer(&missing, None, &TestVerifier).unwrap(),
        Response::Get {
            accepted: false,
            value: None,
            ..
        }
    ));
    let missing_descriptor = answer(Response::Get {
        accepted: true,
        value: Some(Box::new(value.clone())),
        descriptor: None,
        peers: vec![],
    });
    assert!(matches!(
        get.answer(&missing_descriptor, None, &TestVerifier),
        Err(Error::UnknownRecord)
    ));
    assert!(
        get.answer(&missing_descriptor, Some(&descriptor), &TestVerifier)
            .is_ok()
    );
    let other = Descriptor::create(&Schema::dflt(1).unwrap(), &owner).unwrap();
    let wrong = answer(Response::Get {
        accepted: true,
        value: None,
        descriptor: Some(other),
        peers: vec![],
    });
    assert!(
        get.answer(&wrong, Some(&descriptor), &TestVerifier)
            .is_err()
    );
    let mut forged = value.clone();
    forged.signature[0] ^= 1;
    let forged = answer(Response::Get {
        accepted: true,
        value: Some(Box::new(forged)),
        descriptor: Some(descriptor.clone()),
        peers: vec![],
    });
    assert!(get.answer(&forged, None, &TestVerifier).is_err());
    let other_subkey = SignedValue::sign(&owner.public_key(), 1, 2, vec![42], &owner).unwrap();
    let wrong = answer(Response::Get {
        accepted: true,
        value: Some(Box::new(other_subkey)),
        descriptor: Some(descriptor.clone()),
        peers: vec![],
    });
    assert!(get.answer(&wrong, None, &TestVerifier).is_err());
    assert!(
        get.answer(&request, Some(&descriptor), &TestVerifier)
            .is_err()
    );
    let set = Question::new(&Query::Set {
        key: descriptor.key(),
        subkey: 0,
        value: Box::new(value.clone()),
        descriptor: None,
    })
    .unwrap();
    let request = set.sign(&node.public_key(), &owner).unwrap();
    let answer = Answer::new(
        &request,
        &Response::Set {
            accepted: false,
            need_descriptor: true,
            value: Some(Box::new(value)),
            peers: vec![],
        },
    )
    .unwrap()
    .sign(&owner.public_key(), &node)
    .unwrap();
    assert!(matches!(
        set.answer(&answer, None, &TestVerifier),
        Err(Error::UnknownRecord)
    ));
    assert!(matches!(
        set.answer(&answer, Some(&descriptor), &TestVerifier)
            .unwrap(),
        Response::Set {
            accepted: false,
            need_descriptor: true,
            value: Some(_),
            ..
        }
    ));
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn hostile_wire_mutations_cannot_change_authenticated_record_or_operation_bytes() {
    let owner = key(1);
    let node = key(2);
    let descriptor = Descriptor::create(&Schema::dflt(1).unwrap(), &owner).unwrap();
    let value = SignedValue::sign_with_nonce(
        &owner.public_key(),
        0,
        0,
        b"opaque record contents".to_vec(),
        Some([7; 24]),
        &owner,
    )
    .unwrap();
    let original_blob = value.raw_blob().unwrap();
    let encoded_value = ValueBytes::encode(&value).unwrap();
    let encoded_descriptor = DescriptorBytes::encode(&descriptor).unwrap();
    let question = Question::new(&Query::Set {
        key: descriptor.key(),
        subkey: 0,
        value: Box::new(value),
        descriptor: Some(descriptor.clone()),
    })
    .unwrap();
    let operation = question.sign(&node.public_key(), &owner).unwrap();
    // Bounded mutations of actual generated wire objects include pointer,
    // segment-table, typed-key, nonce and packed-container corruption. Successful
    // shape decoding alone never establishes authority. Padding-only mutations
    // may be accepted, but must leave every authenticated byte unchanged.
    for (kind, original) in [
        (0, encoded_value.as_bytes()),
        (1, encoded_descriptor.as_bytes()),
        (2, operation.as_bytes()),
    ] {
        for index in 0..original.len() {
            for xor in [1, 128, 255] {
                let mut mutated = original.to_vec();
                mutated[index] ^= xor;
                match kind {
                    0 => {
                        if let Ok(decoded) =
                            ValueBytes::from_bytes(mutated).and_then(|b| b.decode())
                            && decoded
                                .validate(
                                    &descriptor.key(),
                                    &descriptor.owner,
                                    &Schema::dflt(1).unwrap(),
                                    0,
                                    &TestVerifier,
                                )
                                .is_ok()
                        {
                            assert_eq!(decoded.raw_blob().unwrap(), original_blob);
                        }
                    }
                    1 => {
                        if let Ok(decoded) =
                            DescriptorBytes::from_bytes(mutated).and_then(|b| b.decode())
                            && decoded.validate(&TestVerifier).is_ok()
                        {
                            assert_eq!(decoded, descriptor);
                        }
                    }
                    2 => {
                        if let Ok(decoded) = SignedOperation::verify(
                            mutated,
                            &node.public_key(),
                            &owner.public_key(),
                            &TestVerifier,
                        ) {
                            assert_eq!(decoded.operation(), operation.operation());
                        }
                    }
                    _ => unreachable!(),
                }
            }
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn accepted_watch_answers_keep_the_upstream_node_lease_binding() {
    for (requested, returned, duration_us, accepted, valid) in [
        (7, 8, 1, true, false),
        (7, 0, 0, true, false),
        (0, 0, 1, true, false),
        (0, 0, 0, true, true),
        (7, 7, 1, true, true),
        (0, 8, 1, true, true),
        (7, 8, 1, false, true),
        (0, 0, 1, false, true),
    ] {
        let question = Question::new(&Query::Watch {
            key: cdht::RecordKey([9; 32]),
            subkeys: cdht::rpc::SubkeyRanges::new(),
            duration_us: 1,
            count: 1,
            watch_id: requested,
        })
        .unwrap();
        let request = question.sign(&key(2).public_key(), &key(1)).unwrap();
        let answer = Answer::new(
            &request,
            &Response::Watch {
                accepted,
                duration_us,
                watch_id: returned,
                peers: vec![],
            },
        )
        .unwrap()
        .sign(&key(1).public_key(), &key(2))
        .unwrap();
        assert_eq!(question.answer(&answer, None, &TestVerifier).is_ok(), valid);
    }
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn original_change_statements_preserve_hints_without_authorizing_a_watch() {
    use cdht::rpc::{ChangeHint, Statement, SubkeyRanges, value_changed};
    let owner = key(1);
    let descriptor = Descriptor::create(&Schema::dflt(2).unwrap(), &owner).unwrap();
    let value = SignedValue::sign_with_nonce(
        &owner.public_key(),
        1,
        3,
        b"opaque change".to_vec(),
        Some([7; 24]),
        &owner,
    )
    .unwrap();
    for (ranges, with_value, count, id, valid) in [
        (SubkeyRanges::new(), false, 0, 7, true),
        (SubkeyRanges::from_iter([1]), true, 9, 7, true),
        (SubkeyRanges::from_iter([0, 1]), false, u32::MAX, 7, true),
        (SubkeyRanges::new(), true, 9, 7, false),
        (SubkeyRanges::new(), false, 9, 0, false),
        (
            SubkeyRanges::from_iter((0..513).map(|n| n * 2)),
            false,
            9,
            7,
            false,
        ),
    ] {
        let hint = ChangeHint {
            key: descriptor.key(),
            subkeys: ranges.clone(),
            count,
            watch_id: id,
            value: with_value.then(|| Box::new(value.clone())),
        };
        let encoded = Statement::value_changed(&hint);
        assert_eq!(encoded.is_ok(), valid);
        if !valid {
            continue;
        }
        let encoded = encoded.unwrap();
        let packet = encoded.sign(&key(2).public_key(), &owner).unwrap();
        assert_eq!(packet.operation(), encoded.as_bytes());
        let (_, decoded) = value_changed(&packet).unwrap();
        assert_eq!(decoded.key, descriptor.key());
        assert_eq!(decoded.subkeys, ranges);
        assert_eq!((decoded.count, decoded.watch_id), (count, id));
        if let Some(returned) = decoded.value {
            returned
                .validate(
                    &descriptor.key(),
                    &descriptor.owner,
                    &Schema::dflt(2).unwrap(),
                    1,
                    &TestVerifier,
                )
                .unwrap();
            assert_eq!(returned.raw_blob().unwrap(), value.raw_blob().unwrap());
            assert_eq!(returned.signature, value.signature);
        }
    }
    let question = Question::new(&Query::Get {
        key: descriptor.key(),
        subkey: 0,
        want_descriptor: true,
    })
    .unwrap();
    assert!(value_changed(&question.sign(&key(2).public_key(), &owner).unwrap()).is_err());
}

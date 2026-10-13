//! Original signed application operations; public fixture seeds, no runtime custody.
use super::*;
use crate::test_crypto::{TestVerifier, key};

fn authenticated(encoded: &[u8], sender: u8, recipient: u8) -> SignedOperation {
    let signer = key(sender);
    let destination = key(recipient).public_key();
    let signed = SignedOperation::sign(encoded.to_vec(), &destination, &signer).unwrap();
    SignedOperation::verify(
        signed.as_bytes().to_vec(),
        &destination,
        &signer.public_key(),
        &TestVerifier,
    )
    .unwrap()
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn signed_application_round_trips_preserve_original_kinds_ids_and_payloads() {
    for payload in [
        vec![],
        b"ENV0 is opaque application content".to_vec(),
        vec![0xa5; 1024],
    ] {
        let question = Question::application(&payload).unwrap();
        let call = authenticated(question.as_bytes(), 1, 2);
        assert_eq!(
            application(&call).unwrap(),
            (question.id(), Application::Call(payload.clone()))
        );
        let answer = Answer::application(&call, &payload).unwrap();
        let reply = authenticated(answer.as_bytes(), 2, 1);
        assert_eq!(
            application(&reply).unwrap(),
            (question.id(), Application::Reply(payload.clone()))
        );
        assert_eq!(question.application_answer(&reply).unwrap(), payload);
        let statement = Statement::application(&payload).unwrap();
        let message = authenticated(statement.as_bytes(), 1, 2);
        let wire_message = read(statement.as_bytes()).unwrap();
        let id = wire_message
            .get_root::<wire::operation::Reader>()
            .unwrap()
            .get_op_id();
        assert_eq!(
            application(&message).unwrap(),
            (id, Application::Message(payload))
        );
    }
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn answer_requires_original_application_question_type_and_exact_id() {
    let question = Question::application(b"request").unwrap();
    let call = authenticated(question.as_bytes(), 1, 2);
    let answer = Answer::application(&call, b"response").unwrap();
    let reply = authenticated(answer.as_bytes(), 2, 1);
    assert!(question.application_answer(&call).is_err());
    assert!(Answer::application(&reply, b"not a question").is_err());
    let statement = Statement::application(b"message").unwrap();
    let message = authenticated(statement.as_bytes(), 2, 1);
    assert!(question.application_answer(&message).is_err());
    assert!(Answer::application(&message, b"not a question").is_err());

    let original = read(answer.as_bytes()).unwrap();
    let mut changed = Builder::new_default();
    changed
        .set_root(original.get_root::<wire::operation::Reader>().unwrap())
        .unwrap();
    changed
        .get_root::<wire::operation::Builder>()
        .unwrap()
        .set_op_id(question.id().wrapping_add(1));
    let wrong_id = authenticated(&bytes(changed).unwrap(), 2, 1);
    assert!(question.application_answer(&wrong_id).is_err());

    // Even a deliberately matching ID cannot turn a Records question into AppCallQ.
    let records = Question::encode(
        &Query::Get {
            key: crate::RecordKey([9; 32]),
            subkey: 0,
            want_descriptor: false,
        },
        question.id(),
    )
    .unwrap();
    let record_call = authenticated(records.as_bytes(), 1, 2);
    assert!(application(&record_call).is_err());
    assert!(Answer::application(&record_call, b"not an application call").is_err());
    assert!(records.application_answer(&reply).is_err());
    let record_answer = Answer::new(
        &record_call,
        &Response::Get {
            accepted: false,
            value: None,
            descriptor: None,
            peers: vec![],
        },
    )
    .unwrap();
    let record_reply = authenticated(record_answer.as_bytes(), 2, 1);
    assert!(question.application_answer(&record_reply).is_err());
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn encoding_overhead_counts_toward_original_rpc_limit() {
    let question = Question::application(b"request").unwrap();
    let call = authenticated(question.as_bytes(), 1, 2);
    for size in [MAX_RPC_BYTES, MAX_RPC_BYTES + 1] {
        let oversized = vec![0; size];
        assert!(matches!(
            Question::application(&oversized),
            Err(Error::ValueTooLarge)
        ));
        assert!(matches!(
            Answer::application(&call, &oversized),
            Err(Error::ValueTooLarge)
        ));
        assert!(matches!(
            Statement::application(&oversized),
            Err(Error::ValueTooLarge)
        ));
    }
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn signed_unsupported_or_unknown_details_and_private_routes_are_refused() {
    let mut unsupported = Builder::new_default();
    unsupported
        .init_root::<wire::operation::Builder>()
        .get_kind()
        .init_question()
        .get_detail()
        .init_status_q();
    assert!(application(&authenticated(&bytes(unsupported).unwrap(), 1, 2)).is_err());

    let question = Question::application(b"payload").unwrap();
    let original = read(question.as_bytes()).unwrap();
    let mut routed = Builder::new_default();
    routed
        .set_root(original.get_root::<wire::operation::Reader>().unwrap())
        .unwrap();
    let wire::operation::kind::Question(q) = routed
        .get_root::<wire::operation::Builder>()
        .unwrap()
        .get_kind()
        .which()
        .unwrap()
    else {
        panic!("question");
    };
    q.unwrap().get_respond_to().init_private_route();
    assert!(application(&authenticated(&bytes(routed).unwrap(), 1, 2)).is_err());

    // Upstream Question's data word: respondTo u16=0, detail u16=2 (AppCallQ).
    let mut unknown = question.as_bytes().to_vec();
    let offsets: Vec<_> = unknown
        .chunks_exact(8)
        .enumerate()
        .filter_map(|(i, word)| (word == [0, 0, 2, 0, 0, 0, 0, 0]).then_some(i * 8))
        .collect();
    assert_eq!(offsets.len(), 1);
    unknown[offsets[0] + 2..offsets[0] + 4].copy_from_slice(&u16::MAX.to_le_bytes());
    assert!(application(&authenticated(&unknown, 1, 2)).is_err());
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn tampered_application_cannot_cross_the_signed_operation_boundary() {
    let question = Question::application(b"unique application payload").unwrap();
    let signer = key(1);
    let destination = key(2).public_key();
    let signed = question.sign(&destination, &signer).unwrap();
    let original = read_packed(signed.as_bytes()).unwrap();
    let mut tampered = Builder::new_default();
    tampered
        .set_root(
            original
                .get_root::<wire::signed_operation::Reader>()
                .unwrap(),
        )
        .unwrap();
    let mut operation = signed.operation().to_vec();
    let position = operation
        .windows(b"unique application payload".len())
        .position(|bytes| bytes == b"unique application payload")
        .unwrap();
    operation[position] ^= 1;
    tampered
        .get_root::<wire::signed_operation::Builder>()
        .unwrap()
        .set_operation_data(&operation);
    assert!(
        SignedOperation::verify(
            packed(tampered).unwrap(),
            &destination,
            &signer.public_key(),
            &TestVerifier
        )
        .is_err()
    );
    for (recipient, expected) in [
        (key(3).public_key(), signer.public_key()),
        (destination, key(3).public_key()),
    ] {
        assert!(
            SignedOperation::verify(
                signed.as_bytes().to_vec(),
                &recipient,
                &expected,
                &TestVerifier
            )
            .is_err()
        );
    }
}

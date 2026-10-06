use super::*;
use crate::{
    Backend, LocalBackend, Schema,
    test_crypto::{TestVerifier, key},
};

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn original_inspection_reports_actual_values_and_absence_without_inventing_content() {
    futures_executor::block_on(async {
        let owner = key(51);
        let node = key(52);
        let descriptor = Descriptor::create(&Schema::dflt(4).unwrap(), &owner).unwrap();
        let value = SignedValue::sign(&descriptor.owner, 2, 7, b"actual".to_vec(), &owner).unwrap();
        let store = LocalBackend::new(TestVerifier);
        store.create(&descriptor).await.unwrap();
        store.set(&descriptor.key(), 2, &value).await.unwrap();
        for (subkeys, expected) in [
            (SubkeyRanges::new(), vec![u32::MAX, u32::MAX, 7, u32::MAX]),
            (SubkeyRanges::from_iter([2]), vec![7]),
            (
                SubkeyRanges::from_iter([0..=u32::MAX]),
                vec![u32::MAX, u32::MAX, 7, u32::MAX],
            ),
            (SubkeyRanges::from_iter([5..=8]), vec![]),
        ] {
            let request = Inspection {
                key: descriptor.key(),
                subkeys: subkeys.clone(),
                want_descriptor: true,
            };
            let question = request.question().unwrap();
            let sent = question.sign(&node.public_key(), &owner).unwrap();
            let (id, received) = inspection(&sent).unwrap();
            assert_eq!(id, question.id());
            assert_eq!(received.subkeys, subkeys);
            let (stored, seqs) = store
                .inspect(&received.key, &received.subkeys)
                .unwrap()
                .unwrap();
            assert_eq!(seqs, expected);
            let answer = Answer::inspection(
                &sent,
                &InspectionResponse {
                    accepted: true,
                    seqs,
                    peers: vec![],
                    descriptor: Some(stored),
                },
            )
            .unwrap()
            .sign(&owner.public_key(), &node)
            .unwrap();
            let received = question
                .inspection_answer(&answer, Some(&descriptor), &TestVerifier)
                .unwrap();
            assert!(received.accepted);
            assert_eq!(received.seqs, expected);
            assert_eq!(received.descriptor.unwrap().key(), descriptor.key());
        }
        assert!(
            store
                .inspect(&crate::RecordKey([11; 32]), &SubkeyRanges::new())
                .unwrap()
                .is_none()
        );
        assert_eq!(store.get(&descriptor.key(), 2).await.unwrap(), Some(value));
    });
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn inspection_refuses_wrong_id_kind_record_and_unbounded_sequence_lists() {
    let signer = key(53);
    let descriptor = Descriptor::create(&Schema::dflt(1).unwrap(), &signer).unwrap();
    let request = Inspection {
        key: descriptor.key(),
        subkeys: SubkeyRanges::from_iter([0]),
        want_descriptor: true,
    };
    let question = request.question().unwrap();
    let sent = question.sign(&signer.public_key(), &signer).unwrap();
    for count in [2, crate::MAX_SUBKEY_COUNT] {
        let answer = Answer::inspection(
            &sent,
            &InspectionResponse {
                accepted: true,
                seqs: vec![0; count],
                peers: vec![],
                descriptor: Some(descriptor.clone()),
            },
        )
        .unwrap()
        .sign(&signer.public_key(), &signer)
        .unwrap();
        assert!(matches!(
            question.inspection_answer(&answer, None, &TestVerifier),
            Err(Error::Encoding)
        ));
    }
    assert!(
        Answer::inspection(
            &sent,
            &InspectionResponse {
                accepted: true,
                seqs: vec![0; crate::MAX_SUBKEY_COUNT + 1],
                peers: vec![],
                descriptor: None
            }
        )
        .is_err()
    );
    let wrong = Descriptor::create(&Schema::dflt(2).unwrap(), &signer).unwrap();
    let answer = Answer::inspection(
        &sent,
        &InspectionResponse {
            accepted: true,
            seqs: vec![0],
            peers: vec![],
            descriptor: Some(wrong),
        },
    )
    .unwrap()
    .sign(&signer.public_key(), &signer)
    .unwrap();
    assert!(matches!(
        question.inspection_answer(&answer, None, &TestVerifier),
        Err(Error::WrongRecord)
    ));
    let other = request.encode(question.id().wrapping_add(1)).unwrap();
    assert!(matches!(
        other.inspection_answer(&answer, None, &TestVerifier),
        Err(Error::Encoding)
    ));
    assert!(matches!(
        question.inspection_answer(&sent, None, &TestVerifier),
        Err(Error::Encoding)
    ));
    assert!(
        Inspection {
            key: descriptor.key(),
            subkeys: SubkeyRanges::from_iter((0..513).map(|n| n * 2)),
            want_descriptor: false
        }
        .question()
        .is_err()
    );
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
#[ignore = "requires actual upstream vector generator"]
fn upstream_inspect_vectors() {
    let vectors: serde_json::Value =
        serde_json::from_slice(&std::fs::read(std::env::var("CDHT_VECTORS").unwrap()).unwrap())
            .unwrap();
    let decode = |v: &serde_json::Value| {
        data_encoding::BASE64URL_NOPAD
            .decode(v.as_str().unwrap().as_bytes())
            .unwrap()
    };
    let owner = key(1);
    let node = key(2);
    let vectors = vectors["inspections"].as_array().unwrap();
    assert_eq!(vectors.len(), 3);
    for (index, vector) in vectors.iter().enumerate() {
        let signed =
            SignedOperation::sign(decode(&vector["question"]), &node.public_key(), &owner).unwrap();
        let (id, request) = inspection(&signed).unwrap();
        let question = request.encode(id).unwrap();
        assert_eq!(question.as_bytes(), signed.operation());
        let answered =
            SignedOperation::sign(decode(&vector["answer"]), &owner.public_key(), &node).unwrap();
        let response = question
            .inspection_answer(&answered, None, &TestVerifier)
            .unwrap();
        assert_eq!(
            response.seqs,
            match index {
                0 => vec![0, u32::MAX],
                1 => vec![1, 2, u32::MAX],
                _ => vec![u32::MAX; crate::MAX_SUBKEY_COUNT],
            }
        );
        assert_eq!(
            Answer::inspection(&signed, &response).unwrap().as_bytes(),
            answered.operation()
        );
    }
}

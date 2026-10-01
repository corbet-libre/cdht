//! Original signed record and upstream RPC bytes, native and actual Wasm.
mod common;
use cdht::rpc::{DescriptorBytes, Query, Question, SignedOperation, ValueBytes, query};
use cdht::{Descriptor, Error, Schema, SignedValue, Signer};
use common::{TestVerifier, key};
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

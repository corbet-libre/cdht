//! CI-only vector generator compiled inside the pinned, otherwise unchanged Veilid crate.
use crate::storage_manager::{EncryptedValueData, SignedValueData, SignedValueDescriptor};
use crate::*;
use data_encoding::BASE64URL_NOPAD;

fn b64(bytes: impl AsRef<[u8]>) -> String {
    BASE64URL_NOPAD.encode(bytes.as_ref())
}

/// Exercise the actual upstream implementation without attaching to a network.
pub async fn generate() {
    let (callback, config) = tests::fixture_veilid_core();
    let api = api_startup(callback, config).await.unwrap();
    let crypto = api.crypto().unwrap();
    let vcrypto = crypto.get(CRYPTO_KIND_VLD0).unwrap().as_async();
    let pair = |seed: u8| {
        let (public, secret) =
            veilid_core_optimized::ed25519_generate_keypair(&mut |bytes| bytes.fill(seed));
        (
            PublicKey::new(CRYPTO_KIND_VLD0, BarePublicKey::new(&public)),
            SecretKey::new(CRYPTO_KIND_VLD0, BareSecretKey::new(&secret)),
        )
    };
    let (owner, owner_secret) = pair(1);
    let (writer, writer_secret) = pair(2);
    let member = |key: &PublicKey, count| DHTSchemaSMPLMember {
        m_key: BareMemberId::new(key.ref_value()),
        m_cnt: count,
    };
    let schemas = vec![
        DHTSchema::dflt(1).unwrap(),
        DHTSchema::dflt(1024).unwrap(),
        DHTSchema::smpl(0, vec![member(&writer, 1)]).unwrap(),
        DHTSchema::smpl(
            1,
            vec![
                member(&writer, 0),
                member(&writer, 2),
                member(&writer, 1),
                member(&owner, 1),
            ],
        )
        .unwrap(),
        DHTSchema::smpl(0, (0..256).map(|_| member(&writer, 1)).collect()).unwrap(),
    ];
    let mut schema_vectors = vec![];
    for schema in schemas {
        let compiled = schema.compile();
        let descriptor = SignedValueDescriptor::make_signature(
            owner.clone(),
            compiled.clone().into(),
            &vcrypto,
            owner_secret.clone(),
        )
        .await
        .unwrap();
        let key = api
            .get_dht_record_key(schema.clone(), owner.clone(), None)
            .await
            .unwrap();
        let mut rpc_descriptor = capnp::message::Builder::new_default();
        crate::rpc_processor::cdht_descriptor_encode(
            &descriptor,
            &mut rpc_descriptor
                .init_root::<crate::veilid_capnp::signed_value_descriptor::Builder>(),
        )
        .unwrap();
        let descriptor_blob = crate::rpc_processor::cdht_rpc_bytes(rpc_descriptor);
        schema_vectors.push(serde_json::json!({"schema": b64(&compiled), "owner": b64(owner.ref_value()),
            "key": key.to_string(), "signature": b64(descriptor.ref_signature().ref_value()), "count": schema.subkey_count(), "rpcDescriptor": b64(&descriptor_blob)}));
    }
    let schema = DHTSchema::smpl(1, vec![member(&writer, 1)]).unwrap();
    let secret = SharedSecret::new(CRYPTO_KIND_VLD0, BareSharedSecret::new(&[42; 32]));
    let full_key = api
        .get_dht_record_key(schema.clone(), owner.clone(), Some(secret.clone()))
        .await
        .unwrap();
    let descriptor = SignedValueDescriptor::make_signature(
        owner.clone(),
        schema.compile().into(),
        &vcrypto,
        owner_secret.clone(),
    )
    .await
    .unwrap();
    let mut values = vec![];
    for size in [0usize, 1, 7, 8, 9, 127, 1024, 8191, 8192, 32768] {
        for seq in [0u32, 1, u32::MAX - 1] {
            let plain: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            for encrypted in [false, true] {
                let nonce = encrypted.then(|| Nonce::new(&[3; 24]));
                let ciphertext = if let Some(nonce) = &nonce {
                    vcrypto
                        .crypt_no_auth_unaligned(Bytes::copy_from_slice(&plain), nonce, &secret)
                        .await
                        .unwrap()
                } else {
                    plain.clone()
                };
                let data = EncryptedValueData::new(
                    seq.into(),
                    ciphertext.clone().into(),
                    writer.clone(),
                    nonce,
                )
                .unwrap();
                let signed =
                    SignedValueData::make_signature(data, &owner, 1, &vcrypto, &writer_secret)
                        .await
                        .unwrap();
                assert!(signed.validate(&owner, 1, &vcrypto).await.unwrap());
                let mut rpc_value = capnp::message::Builder::new_default();
                crate::rpc_processor::cdht_value_encode(
                    &signed,
                    &mut rpc_value.init_root::<crate::veilid_capnp::signed_value_data::Builder>(),
                )
                .unwrap();
                let value_blob = crate::rpc_processor::cdht_rpc_bytes(rpc_value);
                let changed = crate::rpc_processor::cdht_changed(Some(signed.clone()));
                let (get_answer, set_answer, set_question) =
                    crate::rpc_processor::cdht_record_answers(signed.clone(), descriptor.clone());
                values.push(serde_json::json!({"seq":seq, "encrypted": encrypted,
                    "valueChanged": b64(changed), "getAnswer": b64(get_answer), "setAnswer": b64(set_answer), "setQuestion": b64(set_question),
                    "plaintext": b64(&plain), "data": b64(&ciphertext),
                    "blob": b64(signed.value_data().raw_blob()), "rpcValue": b64(&value_blob), "signature": b64(signed.signature().ref_value())}));
            }
        }
    }
    let mut request = capnp::message::Builder::new_default();
    let mut operation = request.init_root::<crate::veilid_capnp::operation::Builder>();
    operation.set_op_id(7);
    let mut question = operation.get_kind().init_question();
    question.reborrow().get_respond_to().set_sender(());
    let mut get = question.get_detail().init_get_value_q();
    get.set_subkey(3);
    get.set_want_descriptor(true);
    let mut locator = get.init_key();
    locator.set_kind(u32::from(CRYPTO_KIND_VLD0));
    locator.set_value(&[9; 32]);
    let operation_data = crate::rpc_processor::cdht_rpc_bytes(request);
    let mut transcript: Vec<u8> = writer.clone().into();
    transcript.extend_from_slice(&operation_data);
    let signature = vcrypto
        .sign(&owner, &owner_secret, transcript.into())
        .await
        .unwrap();
    let rpc_packet = crate::rpc_processor::cdht_signed_packet(
        Bytes::copy_from_slice(&operation_data),
        owner.clone(),
        signature,
    );
    let watches: Vec<_> = crate::rpc_processor::cdht_watch_vectors()
        .into_iter()
        .map(
            |(question, answer)| serde_json::json!({"question":b64(question),"answer":b64(answer)}),
        )
        .collect();
    let output = serde_json::json!({"commit":"dd8e2cdd72b5bf817172ac31c20872b168c5c8fc",
        "changeCancelled": b64(crate::rpc_processor::cdht_changed(None)), "watches":watches, "rpcOperation":b64(&operation_data), "rpcPacket":b64(&rpc_packet), "schemas":schema_vectors, "schema":b64(schema.compile()), "owner":b64(owner.ref_value()),
        "writer":b64(writer.ref_value()), "full_key":full_key.to_string(), "values":values});
    std::fs::write(
        std::env::var("CDHT_VECTORS").unwrap(),
        serde_json::to_vec_pretty(&output).unwrap(),
    )
    .unwrap();
    api.shutdown().await;
    import_original_record_into_native_store().await;
}

// Real upstream StorageManager and TableStore. Never attach to a network here;
// this proves byte-preserving import/reopen, not owner fanout or Tor restore.
async fn import_original_record_into_native_store() {
    use crate::storage_manager::{InboundGetValueResult, InboundSetValueResult};
    let input: serde_json::Value =
        serde_json::from_slice(&std::fs::read(std::env::var("CDHT_IMPORT").unwrap()).unwrap())
            .unwrap();
    let decode = |v: &serde_json::Value| {
        BASE64URL_NOPAD
            .decode(v.as_str().unwrap().as_bytes())
            .unwrap()
    };
    let descriptor_bytes = decode(&input["descriptor"]);
    let value_bytes = decode(&input["value"]);
    let descriptor_message =
        capnp::serialize::read_message(&mut &descriptor_bytes[..], Default::default()).unwrap();
    let value_message =
        capnp::serialize::read_message(&mut &value_bytes[..], Default::default()).unwrap();
    let descriptor =
        crate::rpc_processor::cdht_descriptor_decode(&descriptor_message.get_root().unwrap())
            .unwrap();
    let value =
        crate::rpc_processor::cdht_value_decode(&value_message.get_root().unwrap()).unwrap();
    let record: OpaqueRecordKey = input["key"].as_str().unwrap().parse().unwrap();
    let target = Target::NodeId(NodeId::new(CRYPTO_KIND_VLD0, BareNodeId::new(&[9; 32])));
    let (callback, mut config) = tests::fixture_veilid_core_with_namespace("cdht-import");
    let api = api_startup(callback.clone(), config.clone()).await.unwrap();
    {
        let storage = api.core_context().unwrap().registry().storage_manager();
        let forged = SignedValueData::new(
            value.value_data().clone(),
            Signature::new(CRYPTO_KIND_VLD0, BareSignature::new(&[0; 64])),
        );
        let refusal = storage
            .inbound_set_value(
                &record,
                0,
                Arc::new(forged),
                Some(Arc::new(descriptor.clone())),
                target.clone(),
            )
            .await
            .unwrap();
        assert!(!matches!(
            refusal,
            NetworkResult::Value(InboundSetValueResult::Success)
        ));
        let NetworkResult::Value(InboundGetValueResult::Success(before)) =
            storage.inbound_get_value(&record, 0, true).await.unwrap()
        else {
            panic!("inspect empty store");
        };
        assert!(before.opt_value.is_none());
        let accepted = storage
            .inbound_set_value(
                &record,
                0,
                Arc::new(value.clone()),
                Some(Arc::new(descriptor.clone())),
                target,
            )
            .await
            .unwrap();
        assert!(matches!(
            accepted,
            NetworkResult::Value(InboundSetValueResult::Success)
        ));
        storage
            .cdht_import_local_original(&record, descriptor, value)
            .await;
    }
    api.shutdown().await;
    config.table_store.delete = false;
    config.block_store.delete = false;
    config.protected_store.delete = false;
    let reopened = api_startup(callback, config).await.unwrap();
    {
        let storage = reopened
            .core_context()
            .unwrap()
            .registry()
            .storage_manager();
        let NetworkResult::Value(InboundGetValueResult::Success(stored)) =
            storage.inbound_get_value(&record, 0, true).await.unwrap()
        else {
            panic!("reopen imported store");
        };
        let mut encoded_value = capnp::message::Builder::new_default();
        crate::rpc_processor::cdht_value_encode(
            &stored.opt_value.unwrap(),
            &mut encoded_value.init_root(),
        )
        .unwrap();
        assert_eq!(
            crate::rpc_processor::cdht_rpc_bytes(encoded_value),
            value_bytes
        );
        let mut encoded_descriptor = capnp::message::Builder::new_default();
        crate::rpc_processor::cdht_descriptor_encode(
            &stored.opt_descriptor.unwrap(),
            &mut encoded_descriptor.init_root(),
        )
        .unwrap();
        assert_eq!(
            crate::rpc_processor::cdht_rpc_bytes(encoded_descriptor),
            descriptor_bytes
        );
        let (local_value, local_descriptor) = storage.cdht_reopen_imported_local(&record).await;
        let mut value = capnp::message::Builder::new_default();
        crate::rpc_processor::cdht_value_encode(&local_value, &mut value.init_root()).unwrap();
        assert_eq!(crate::rpc_processor::cdht_rpc_bytes(value), value_bytes);
        let mut descriptor = capnp::message::Builder::new_default();
        crate::rpc_processor::cdht_descriptor_encode(
            &local_descriptor,
            &mut descriptor.init_root(),
        )
        .unwrap();
        assert_eq!(
            crate::rpc_processor::cdht_rpc_bytes(descriptor),
            descriptor_bytes
        );
    }
    reopened.shutdown().await;
    println!(
        "original Records bytes survived native Veilid remote/local store import and reopen; upstream open queued owner rehydration; network fanout not exercised"
    );
}

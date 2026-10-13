//! Real VLD0 PeerInfo signatures and unchanged extension payloads.
mod common;
use cdht::{
    Error, Signer,
    rpc::{
        UnverifiedPeerInfoBytes,
        peers::{Advertisement, DHTV, DIRECT, ExtensionDialInfo},
    },
};
use common::{TestKey, TestVerifier, key};

fn advertisement() -> Advertisement {
    Advertisement {
        timestamp_us: 17,
        capabilities: vec![DHTV],
        outbound_protocols: vec![u32::from_be_bytes(*b"TOR3")],
        address_types: vec![u32::from_be_bytes(*b"TOR3")],
        dial_info: vec![ExtensionDialInfo {
            class: DIRECT,
            protocol: u32::from_be_bytes(*b"TOR3"),
            detail: vec![7; 65],
        }],
    }
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn original_node_info_signature_binds_coordinate_and_endpoint() {
    let owner = key(75);
    let info = UnverifiedPeerInfoBytes::sign_extension(advertisement(), &owner).unwrap();
    let verified = info.verify_extension(&TestVerifier).unwrap();
    assert_eq!(verified.node_id(), &owner.public_key());
    assert_eq!(verified.advertisement().timestamp_us, 17);
    assert_eq!(verified.advertisement().dial_info[0].detail, vec![7; 65]);
    assert_eq!(verified.original().as_bytes(), info.as_bytes());
    let bytes = verified.original().as_bytes().to_vec();
    let mut tampered = bytes.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(
        UnverifiedPeerInfoBytes::from_bytes(tampered)
            .unwrap()
            .verify_extension(&TestVerifier)
            .is_err()
    );
    assert!(UnverifiedPeerInfoBytes::from_bytes([bytes, vec![0]].concat()).is_err());
    struct Substitution {
        advertised: TestKey,
        actual: TestKey,
    }
    impl Signer for Substitution {
        fn public_key(&self) -> [u8; 32] {
            self.advertised.public_key()
        }
        fn sign(&self, data: &[u8]) -> Result<[u8; 64], Error> {
            self.actual.sign(data)
        }
    }
    let substituted = UnverifiedPeerInfoBytes::sign_extension(
        advertisement(),
        &Substitution {
            advertised: key(75),
            actual: key(76),
        },
    )
    .unwrap();
    assert!(matches!(
        substituted.verify_extension(&TestVerifier),
        Err(Error::BadSignature)
    ));
    let mut bootstrap = advertisement();
    bootstrap.capabilities.clear();
    let bootstrap = UnverifiedPeerInfoBytes::sign_extension(bootstrap, &owner)
        .unwrap()
        .verify_extension(&TestVerifier)
        .unwrap();
    assert!(!bootstrap.advertisement().capabilities.contains(&DHTV));
    for field in 0..10 {
        let mut bad = advertisement();
        match field {
            0 => bad.capabilities = vec![DHTV; 65],
            1 => bad.capabilities.push(DHTV),
            2 => bad.outbound_protocols.clear(),
            3 => bad.outbound_protocols = vec![1; 17],
            4 => bad.address_types.clear(),
            5 => bad.address_types = vec![1; 17],
            6 => bad.dial_info.clear(),
            7 => bad.dial_info[0].detail = vec![0; 4097],
            8 => bad.dial_info[0].class = 0,
            _ => bad.dial_info[0].protocol = 0,
        }
        assert!(UnverifiedPeerInfoBytes::sign_extension(bad, &owner).is_err());
    }
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn bootstrap_find_node_preserves_original_peer_authority_and_request_binding() {
    use cdht::rpc::{
        SignedOperation,
        peers::{FindAnswer, find_node, find_query, find_response},
    };
    let client = key(71);
    let bootstrap = key(72);
    let storage = key(73);
    let question = find_node(&[99; 32], &[DHTV])
        .unwrap()
        .sign(&bootstrap.public_key(), &client)
        .unwrap();
    let received = SignedOperation::verify(
        question.as_bytes().to_vec(),
        &bootstrap.public_key(),
        &client.public_key(),
        &TestVerifier,
    )
    .unwrap();
    let (_, coordinate, caps) = find_query(&received).unwrap();
    assert_eq!(coordinate, [99; 32]);
    assert_eq!(caps, [DHTV]);
    let info = UnverifiedPeerInfoBytes::sign_extension(advertisement(), &storage).unwrap();
    let original = info.as_bytes().to_vec();
    let reply = FindAnswer::new(&received, &[info])
        .unwrap()
        .sign(&client.public_key(), &bootstrap)
        .unwrap();
    let reply = SignedOperation::verify(
        reply.as_bytes().to_vec(),
        &client.public_key(),
        &bootstrap.public_key(),
        &TestVerifier,
    )
    .unwrap();
    let peers = find_response(&question, &reply, &TestVerifier).unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].node_id(), &storage.public_key());
    assert_eq!(peers[0].original().as_bytes(), original);
    assert!(
        SignedOperation::verify(
            reply.as_bytes().to_vec(),
            &[0; 32],
            &bootstrap.public_key(),
            &TestVerifier
        )
        .is_err()
    );
    let other = find_node(&[99; 32], &[DHTV])
        .unwrap()
        .sign(&bootstrap.public_key(), &client)
        .unwrap();
    assert!(find_response(&other, &reply, &TestVerifier).is_err());
    let mut no_storage = advertisement();
    no_storage.capabilities.clear();
    let info = UnverifiedPeerInfoBytes::sign_extension(no_storage, &storage).unwrap();
    let bad_capability = FindAnswer::new(&received, &[info])
        .unwrap()
        .sign(&client.public_key(), &bootstrap)
        .unwrap();
    assert!(find_response(&question, &bad_capability, &TestVerifier).is_err());
    let empty = FindAnswer::new(&received, &[])
        .unwrap()
        .sign(&client.public_key(), &bootstrap)
        .unwrap();
    assert!(
        find_response(&question, &empty, &TestVerifier)
            .unwrap()
            .is_empty()
    );
    assert!(find_node(&[1; 32], &[DHTV; 65]).is_err());
    let many = (0..21)
        .map(|_| UnverifiedPeerInfoBytes::sign_extension(advertisement(), &storage).unwrap())
        .collect::<Vec<_>>();
    assert!(FindAnswer::new(&received, &many).is_err());
    assert!(find_query(&reply).is_err());
    assert!(find_response(&question, &question, &TestVerifier).is_err());
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn discovery_sender_must_own_both_packet_and_advertisement() {
    use cdht::rpc::{SignedOperation, peers::find_node};
    let caller = key(85);
    let destination = key(86);
    let stranger = key(87);
    let info = UnverifiedPeerInfoBytes::sign_extension(advertisement(), &caller).unwrap();
    let question = find_node(&[2; 32], &[DHTV])
        .unwrap()
        .with_sender(&info)
        .unwrap();
    let sent = question.sign(&destination.public_key(), &caller).unwrap();
    let received = SignedOperation::verify_sender(
        sent.as_bytes().to_vec(),
        &destination.public_key(),
        &TestVerifier,
    )
    .unwrap();
    assert_eq!(
        received.sender_peer(&TestVerifier).unwrap().node_id(),
        &caller.public_key()
    );
    assert_eq!(
        received
            .sender_peer(&TestVerifier)
            .unwrap()
            .original()
            .as_bytes(),
        info.as_bytes()
    );
    assert!(
        SignedOperation::verify_sender(
            sent.as_bytes().to_vec(),
            &stranger.public_key(),
            &TestVerifier
        )
        .is_err()
    );
    let substituted = question.sign(&destination.public_key(), &stranger).unwrap();
    let received = SignedOperation::verify_sender(
        substituted.as_bytes().to_vec(),
        &destination.public_key(),
        &TestVerifier,
    )
    .unwrap();
    assert!(matches!(
        received.sender_peer(&TestVerifier),
        Err(Error::BadSignature)
    ));
    let absent = find_node(&[2; 32], &[DHTV])
        .unwrap()
        .sign(&destination.public_key(), &caller)
        .unwrap();
    assert!(absent.sender_peer(&TestVerifier).is_err());
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn discovery_queue_queries_dynamic_authenticated_hints_once_and_never_promotes_bootstrap() {
    use cdht::discovery::Discovery;
    use std::{num::NonZeroUsize, sync::Arc};
    let authenticated = |seed, storage: bool| {
        let mut ad = advertisement();
        if !storage {
            ad.capabilities.clear();
        }
        Arc::new(
            UnverifiedPeerInfoBytes::sign_extension(ad, &key(seed))
                .unwrap()
                .verify_extension(&TestVerifier)
                .unwrap(),
        )
    };
    let own = authenticated(88, true);
    let bootstrap = authenticated(89, false);
    let first = authenticated(90, true);
    let second = authenticated(91, true);
    let mut lookup = Discovery::new([42; 32], *own.node_id(), NonZeroUsize::new(3).unwrap());
    lookup.insert(own).unwrap();
    assert!(lookup.exhausted());
    lookup.insert(bootstrap.clone()).unwrap();
    assert!(!lookup.exhausted());
    assert!(lookup.storage_peers().is_empty());
    assert_eq!(lookup.next_peer().unwrap().node_id(), bootstrap.node_id());
    assert!(lookup.next_peer().is_none());
    assert!(!lookup.exhausted());
    lookup.finish(bootstrap.node_id(), true).unwrap();
    assert!(lookup.exhausted());
    assert!(lookup.storage_peers().is_empty());
    lookup.insert(first.clone()).unwrap();
    lookup.insert(second.clone()).unwrap();
    lookup.insert(first.clone()).unwrap();
    let mut expected = [first, second];
    expected.sort_by_key(|peer| std::array::from_fn::<_, 32, _>(|i| peer.node_id()[i] ^ 42));
    assert!(matches!(
        lookup.finish(expected[0].node_id(), true),
        Err(Error::Conflict)
    ));
    for peer in &expected {
        assert_eq!(lookup.next_peer().unwrap().node_id(), peer.node_id());
    }
    assert!(lookup.next_peer().is_none());
    lookup.finish(expected[0].node_id(), true).unwrap();
    lookup.finish(expected[1].node_id(), false).unwrap();
    assert!(lookup.exhausted());
    assert_eq!(lookup.storage_peers().len(), 1);
    assert_eq!(lookup.storage_peers()[0].node_id(), expected[0].node_id());
    assert!(matches!(
        lookup.finish(&[0; 32], true),
        Err(Error::UnknownRecord)
    ));
    assert!(matches!(
        lookup.finish(expected[0].node_id(), true),
        Err(Error::Conflict)
    ));
    assert!(lookup.insert(authenticated(92, true)).is_err());
    assert!(lookup.limited());
    assert!(!lookup.exhausted());
}

//! Actual maintained VLD0 DH/cipher/signature round trips for original ENV0.
mod common;
use cdht::{
    Signer,
    rpc::envelope::{Envelope, EnvelopeCipher, MAX_BODY_BYTES, TimeWindow},
};
use common::{NodeCipher, TestVerifier, key};

fn window() -> TimeWindow {
    TimeWindow {
        behind_us: 5,
        ahead_us: 2,
    }
}
#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn original_node_envelope_authenticates_destination_and_keeps_watcher_independent() {
    use cdht::rpc::{
        SignedOperation,
        peers::{DHTV, find_node},
    };
    let node = key(94);
    let destination = key(95);
    let watcher = key(96);
    let advertisement = cdht::rpc::UnverifiedPeerInfoBytes::sign_extension(
        cdht::rpc::peers::Advertisement {
            timestamp_us: 100,
            capabilities: vec![DHTV],
            outbound_protocols: vec![u32::from_be_bytes(*b"TOR3")],
            address_types: vec![u32::from_be_bytes(*b"TOR3")],
            dial_info: vec![cdht::rpc::peers::ExtensionDialInfo {
                class: cdht::rpc::peers::DIRECT,
                protocol: u32::from_be_bytes(*b"TOR3"),
                detail: vec![7; 65],
            }],
        },
        &node,
    )
    .unwrap();
    let operation = find_node(&[1; 32], &[DHTV])
        .unwrap()
        .with_sender(&advertisement)
        .unwrap()
        .sign(&destination.public_key(), &watcher)
        .unwrap();
    let bytes = Envelope::seal(
        operation.as_bytes(),
        &destination.public_key(),
        100,
        &node,
        &NodeCipher(94),
    )
    .unwrap();
    assert_eq!(&bytes[..8], b"ENV0VLD0");
    assert_eq!(
        usize::from(u16::from_le_bytes(bytes[8..10].try_into().unwrap())),
        bytes.len()
    );
    assert!(!bytes.windows(32).any(|part| part == watcher.public_key()));
    let received = Envelope::verify(
        bytes.clone(),
        &destination.public_key(),
        100,
        window(),
        &TestVerifier,
    )
    .unwrap();
    assert_eq!(received.sender(), &node.public_key());
    let authenticated = received
        .open_operation(&NodeCipher(95), &TestVerifier)
        .unwrap();
    assert_eq!(authenticated.sender(), &node.public_key());
    assert_eq!(authenticated.operation().signer(), &watcher.public_key());
    assert_eq!(
        authenticated.sender_peer(&TestVerifier).unwrap().node_id(),
        &node.public_key()
    );
    assert!(
        authenticated
            .operation()
            .sender_peer(&TestVerifier)
            .is_err()
    );
    assert_eq!(received.timestamp_us(), 100);
    assert_eq!(received.as_bytes(), bytes);
    let body = received.open(&NodeCipher(95)).unwrap();
    assert_eq!(&*body, operation.as_bytes());
    let inner =
        SignedOperation::verify_sender(body.to_vec(), &destination.public_key(), &TestVerifier)
            .unwrap();
    assert_eq!(inner.signer(), &watcher.public_key());
    assert_ne!(inner.signer(), received.sender());
    assert!(received.open(&NodeCipher(96)).is_err());
    let again = Envelope::seal(
        operation.as_bytes(),
        &destination.public_key(),
        100,
        &node,
        &NodeCipher(94),
    )
    .unwrap();
    assert_ne!(&bytes[18..42], &again[18..42]);
    assert_ne!(bytes, again);
    for now in [98, 105] {
        assert!(
            Envelope::verify(
                bytes.clone(),
                &destination.public_key(),
                now,
                window(),
                &TestVerifier
            )
            .is_ok()
        );
    }
    for now in [97, 106] {
        assert!(
            Envelope::verify(
                bytes.clone(),
                &destination.public_key(),
                now,
                window(),
                &TestVerifier
            )
            .is_err()
        );
    }
    assert!(
        Envelope::verify(
            bytes.clone(),
            &watcher.public_key(),
            100,
            window(),
            &TestVerifier
        )
        .is_err()
    );
    for index in [0, 4, 8, 10, 18, 42, 74, 106, bytes.len() - 1] {
        let mut tampered = bytes.clone();
        tampered[index] ^= 1;
        assert!(
            Envelope::verify(
                tampered,
                &destination.public_key(),
                100,
                window(),
                &TestVerifier
            )
            .is_err()
        );
    }
    for length in [0, 3, 169, bytes.len() - 1] {
        assert!(
            Envelope::verify(
                bytes[..length].to_vec(),
                &destination.public_key(),
                100,
                window(),
                &TestVerifier
            )
            .is_err()
        );
    }
    let reply = Envelope::seal(
        b"actual response",
        &node.public_key(),
        101,
        &destination,
        &NodeCipher(95),
    )
    .unwrap();
    assert_eq!(
        &*Envelope::verify(reply, &node.public_key(), 101, window(), &TestVerifier)
            .unwrap()
            .open(&NodeCipher(94))
            .unwrap(),
        b"actual response"
    );
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn envelope_refuses_oversized_or_mismatched_capabilities_and_bounds_authenticated_expansion() {
    let sender = key(97);
    let destination = key(98);
    assert!(
        Envelope::seal(
            b"same node",
            &sender.public_key(),
            100,
            &sender,
            &NodeCipher(97)
        )
        .is_err()
    );
    assert!(
        Envelope::seal(
            b"wrong owner",
            &destination.public_key(),
            100,
            &sender,
            &NodeCipher(98)
        )
        .is_err()
    );
    assert!(
        Envelope::seal(
            &vec![0; MAX_BODY_BYTES + 1],
            &destination.public_key(),
            100,
            &sender,
            &NodeCipher(97)
        )
        .is_err()
    );
    let boundary = Envelope::seal(
        &vec![1; MAX_BODY_BYTES],
        &destination.public_key(),
        100,
        &sender,
        &NodeCipher(97),
    )
    .unwrap();
    assert_eq!(
        Envelope::verify(
            boundary,
            &destination.public_key(),
            100,
            window(),
            &TestVerifier
        )
        .unwrap()
        .open(&NodeCipher(98))
        .unwrap()
        .len(),
        MAX_BODY_BYTES
    );
    struct WrongLength;
    impl EnvelopeCipher for WrongLength {
        fn node_id(&self) -> [u8; 32] {
            key(97).public_key()
        }
        fn crypt(
            &self,
            _: &[u8; 32],
            _: &[u8; 24],
            _: &[u8],
        ) -> Result<zeroize::Zeroizing<Vec<u8>>, cdht::Error> {
            Ok(zeroize::Zeroizing::new(vec![]))
        }
    }
    assert!(
        Envelope::seal(
            b"refuse malformed cipher",
            &destination.public_key(),
            100,
            &sender,
            &WrongLength
        )
        .is_err()
    );
    // A malicious but genuinely authenticated sender encrypts a huge declared LZ4
    // expansion. The receiver must reject before that declaration allocates memory.
    let mut bytes = Envelope::seal(
        b"initial body",
        &destination.public_key(),
        100,
        &sender,
        &NodeCipher(97),
    )
    .unwrap();
    let nonce: [u8; 24] = bytes[18..42].try_into().unwrap();
    let end = bytes.len() - 64;
    let mut compressed = NodeCipher(97)
        .crypt(&destination.public_key(), &nonce, &bytes[106..end])
        .unwrap();
    compressed[..4].copy_from_slice(&u32::MAX.to_le_bytes());
    let ciphertext = NodeCipher(97)
        .crypt(&destination.public_key(), &nonce, &compressed)
        .unwrap();
    bytes[106..end].copy_from_slice(&ciphertext);
    let signature = sender.sign(&bytes[..end]).unwrap();
    bytes[end..].copy_from_slice(&signature);
    let checked = Envelope::verify(
        bytes,
        &destination.public_key(),
        100,
        window(),
        &TestVerifier,
    )
    .unwrap();
    assert!(matches!(
        checked.open(&NodeCipher(98)),
        Err(cdht::Error::ValueTooLarge)
    ));
}

fn sealed(node: &common::TestKey, destination: &common::TestKey, at: u64) -> Vec<u8> {
    Envelope::seal(
        b"body",
        &destination.public_key(),
        at,
        node,
        &NodeCipher(94),
    )
    .unwrap()
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn replay_inside_the_time_window_is_refused_and_expiry_frees_the_entry() {
    use cdht::{Error, rpc::envelope::ReplayCache};
    let node = key(94);
    let destination = key(95);
    let dest = destination.public_key();
    let bytes = sealed(&node, &destination, 100);
    let mut cache = ReplayCache::new(8);
    let verify = |bytes: &[u8], now: u64, cache: &mut ReplayCache| {
        Envelope::verify_once(bytes.to_vec(), &dest, now, window(), &TestVerifier, cache)
    };
    assert!(verify(&bytes, 100, &mut cache).is_ok());
    assert_eq!(cache.len(), 1);
    // The same authenticated bytes inside the window, early and late.
    assert!(matches!(
        verify(&bytes, 100, &mut cache),
        Err(Error::Replay)
    ));
    assert!(matches!(
        verify(&bytes, 105, &mut cache),
        Err(Error::Replay)
    ));
    // A fresh envelope (new random nonce) is accepted.
    let fresh = sealed(&node, &destination, 100);
    assert!(verify(&fresh, 101, &mut cache).is_ok());
    // Past the window the old bytes fail the time check and the entries are pruned.
    assert!(verify(&bytes, 106, &mut cache).is_err());
    let later = sealed(&node, &destination, 200);
    assert!(verify(&later, 200, &mut cache).is_ok());
    assert_eq!(cache.len(), 1);
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn full_replay_cache_fails_closed_and_unauthenticated_bytes_are_not_remembered() {
    use cdht::{Error, rpc::envelope::ReplayCache};
    let node = key(94);
    let destination = key(95);
    let dest = destination.public_key();
    let mut cache = ReplayCache::new(1);
    let first = sealed(&node, &destination, 100);
    let second = sealed(&node, &destination, 100);
    assert!(Envelope::verify_once(first, &dest, 100, window(), &TestVerifier, &mut cache).is_ok());
    assert!(matches!(
        Envelope::verify_once(
            second.clone(),
            &dest,
            100,
            window(),
            &TestVerifier,
            &mut cache
        ),
        Err(Error::Unavailable)
    ));
    // A tampered envelope fails authentication and never reaches the cache.
    let mut roomy = ReplayCache::new(4);
    let mut tampered = second;
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(
        Envelope::verify_once(tampered, &dest, 100, window(), &TestVerifier, &mut roomy).is_err()
    );
    assert!(roomy.is_empty());
}

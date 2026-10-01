//! CI-only original Records bytes for an independent native Veilid store import.
#[path = "../tests/common/mod.rs"]
mod common;
use cdht::{Dht, EncryptionKey, LocalBackend, Schema};
use common::{TestVerifier, key};
use data_encoding::BASE64URL_NOPAD;
fn main() {
    let mut client = Dht::new(LocalBackend::new(TestVerifier), TestVerifier);
    let owner = key(19);
    let record = client
        .queue_create(&Schema::dflt(1).unwrap(), &owner)
        .unwrap();
    client
        .queue_set(
            &record,
            0,
            b"original cross-implementation ciphertext",
            &owner,
            Some(&EncryptionKey::from_bytes([23; 32])),
        )
        .unwrap();
    let value = &client.state().queue()[0].value;
    let descriptor = cdht::Descriptor::create(&Schema::dflt(1).unwrap(), &owner).unwrap();
    let output = serde_json::json!({
        "key": record.to_string(),
        "value": BASE64URL_NOPAD.encode(cdht::rpc::ValueBytes::encode(value).unwrap().as_bytes()),
        "descriptor": BASE64URL_NOPAD.encode(cdht::rpc::DescriptorBytes::encode(&descriptor).unwrap().as_bytes()),
    });
    std::fs::write(
        std::env::var("CDHT_IMPORT").unwrap(),
        serde_json::to_vec(&output).unwrap(),
    )
    .unwrap();
}

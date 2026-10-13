#!/usr/bin/env bash
# Compile the real pinned upstream in CI. No production dependency on veilid-core.
set -euo pipefail
: "${CI:?Run this on CI only}"
cdht_root=$(pwd)
cdht_revision=dd8e2cdd72b5bf817172ac31c20872b168c5c8fc
cdht_upstream="${RUNNER_TEMP:?}/cdht-veilid"
git -c http.userAgent=record-conformance init "$cdht_upstream"
git -C "$cdht_upstream" -c http.userAgent=record-conformance fetch --depth=1 https://gitlab.com/veilid/veilid.git "$cdht_revision"
git -C "$cdht_upstream" switch --detach FETCH_HEAD
test "$(git -C "$cdht_upstream" rev-parse HEAD)" = "$cdht_revision"
python3 - "$cdht_upstream" <<'PYCODE'
import re
import sys
from pathlib import Path
upstream = Path(sys.argv[1], "veilid-core/proto/veilid_capnp.rs").read_text()
local = Path("src/veilid_capnp.rs").read_text()
for name in Path("ci/upstream-modules.txt").read_text().splitlines():
    pattern = rf"^pub mod {name} \{{.*?(?=^pub mod |\Z)"
    expected = re.search(pattern, upstream, re.M | re.S).group(0).rstrip()
    actual = re.search(pattern, local, re.M | re.S).group(0).rstrip()
    assert expected == actual, f"upstream generated module changed: {name}"
PYCODE
cat >> "$cdht_upstream/veilid-core/src/rpc_processor/mod.rs" <<'RS'
pub(crate) use coders::{encode_signed_value_data as cdht_value_encode,
    encode_signed_value_descriptor as cdht_descriptor_encode,
    decode_signed_value_data as cdht_value_decode,
    decode_signed_value_descriptor as cdht_descriptor_decode};
pub(crate) fn cdht_rpc_bytes<T: capnp::message::Allocator>(builder: capnp::message::Builder<T>) -> Vec<u8> {
    canonical_message_builder_to_bytes_writer_unpacked(builder, BytesWriter::with_capacity)
        .unwrap().into_inner().to_vec()
}
pub(crate) fn cdht_signed_packet(operation_data: Bytes, signer: PublicKey, signature: Signature) -> Vec<u8> {
    let signed = RPCSignedOperation::new(operation_data, Some(RPCSignerSignature { signer, signature }));
    let mut builder = capnp::message::Builder::new_default();
    signed.encode(&mut builder.init_root::<crate::veilid_capnp::signed_operation::Builder>()).unwrap();
    canonical_message_builder_to_bytes_writer_packed(builder, BytesWriter::with_capacity)
        .unwrap().into_inner().to_vec()
}
pub(crate) fn cdht_record_answers(value: crate::storage_manager::SignedValueData,
    descriptor: crate::storage_manager::SignedValueDescriptor) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut get = capnp::message::Builder::new_default();
    let mut operation = get.init_root::<crate::veilid_capnp::operation::Builder>();
    operation.set_op_id(7);
    RPCOperationGetValueA::new(true, Some(value.clone()), vec![], Some(descriptor)).unwrap()
        .encode(&mut operation.get_kind().init_answer().get_detail().init_get_value_a()).unwrap();
    let mut set = capnp::message::Builder::new_default();
    let mut operation = set.init_root::<crate::veilid_capnp::operation::Builder>();
    operation.set_op_id(7);
    RPCOperationSetValueA::new(false, false, Some(value.clone()), vec![]).unwrap()
        .encode(&mut operation.get_kind().init_answer().get_detail().init_set_value_a()).unwrap();
    let mut request = capnp::message::Builder::new_default();
    let mut operation = request.init_root::<crate::veilid_capnp::operation::Builder>();
    operation.set_op_id(7);
    let mut question = operation.get_kind().init_question();
    question.reborrow().get_respond_to().set_sender(());
    let mut set_question = question.get_detail().init_set_value_q();
    let mut key = set_question.reborrow().init_key();
    key.set_kind(u32::from(CRYPTO_KIND_VLD0));
    key.set_value(&[9; 32]);
    set_question.set_subkey(1);
    encode_signed_value_data(&value, &mut set_question.init_value()).unwrap();
    (cdht_rpc_bytes(get), cdht_rpc_bytes(set), cdht_rpc_bytes(request))
}
pub(crate) fn cdht_watch_vectors() -> Vec<(Vec<u8>,Vec<u8>)> {
    let mut result = Vec::new();
    let mut sparse = ValueSubkeyRangeSet::single_range(2,4);
    sparse.insert(8);
    for (subkeys, duration, count, id) in [
        (ValueSubkeyRangeSet::new(), 5_000_000, u32::MAX, None),
        (sparse, u64::MAX, 1, Some(7)),
        (ValueSubkeyRangeSet::full(), 0, 0, Some(7)),
    ] {
        let mut question = capnp::message::Builder::new_default();
        let mut operation = question.init_root::<crate::veilid_capnp::operation::Builder>();
        operation.set_op_id(7);
        let mut q = operation.get_kind().init_question();
        q.reborrow().get_respond_to().set_sender(());
        RPCOperationWatchValueQ::new(OpaqueRecordKey::new(CRYPTO_KIND_VLD0, BareOpaqueRecordKey::new(&[9;32])), subkeys, TimestampDuration::new(duration), count, id).unwrap()
            .encode(&mut q.get_detail().init_watch_value_q()).unwrap();
        let mut answer = capnp::message::Builder::new_default();
        let mut operation = answer.init_root::<crate::veilid_capnp::operation::Builder>();
        operation.set_op_id(7);
        let granted_duration = if count == 0 { 0 } else { 5_000_000 };
        RPCOperationWatchValueA::new(true, TimestampDuration::new(granted_duration),vec![],7).unwrap()
            .encode(&mut operation.get_kind().init_answer().get_detail().init_watch_value_a()).unwrap();
        result.push((cdht_rpc_bytes(question),cdht_rpc_bytes(answer)));
    }
    result
}

pub(crate) fn cdht_inspect_vectors() -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut result = Vec::new();
    for (subkeys, seqs) in [
        (ValueSubkeyRangeSet::new(), vec![0, u32::MAX]),
        (ValueSubkeyRangeSet::single_range(2,4), vec![1,2,u32::MAX]),
        (ValueSubkeyRangeSet::full(), vec![u32::MAX; DHTSchema::MAX_SUBKEY_COUNT]),
    ] {
        let mut question = capnp::message::Builder::new_default();
        let mut operation = question.init_root::<crate::veilid_capnp::operation::Builder>();
        operation.set_op_id(7);
        let mut q = operation.get_kind().init_question();
        q.reborrow().get_respond_to().set_sender(());
        RPCOperationInspectValueQ::new(OpaqueRecordKey::new(CRYPTO_KIND_VLD0, BareOpaqueRecordKey::new(&[9;32])), subkeys, true).unwrap()
            .encode(&mut q.get_detail().init_inspect_value_q()).unwrap();
        let mut answer = capnp::message::Builder::new_default();
        let mut operation = answer.init_root::<crate::veilid_capnp::operation::Builder>();
        operation.set_op_id(7);
        RPCOperationInspectValueA::new(true, seqs.into_iter().map(ValueSeqNum::from).collect(), vec![], None).unwrap()
            .encode(&mut operation.get_kind().init_answer().get_detail().init_inspect_value_a()).unwrap();
        result.push((cdht_rpc_bytes(question),cdht_rpc_bytes(answer)));
    }
    result
}

pub(crate) fn cdht_changed(value: Option<crate::storage_manager::SignedValueData>) -> Vec<u8> {
    let subkeys = if value.is_some() { ValueSubkeyRangeSet::single(1) } else { ValueSubkeyRangeSet::new() };
    let count = if value.is_some() { 9 } else { 0 };
    let changed = RPCOperationValueChanged::new(OpaqueRecordKey::new(CRYPTO_KIND_VLD0,BareOpaqueRecordKey::new(&[9;32])),subkeys,count,7,value).unwrap();
    let mut message = capnp::message::Builder::new_default();
    let mut operation = message.init_root::<crate::veilid_capnp::operation::Builder>();
    operation.set_op_id(7);
    changed.encode(&mut operation.get_kind().init_statement().get_detail().init_value_changed()).unwrap();
    cdht_rpc_bytes(message)
}

RS
cp ci/veilid_store_oracle.rs "$cdht_upstream/veilid-core/src/storage_manager/cdht_store_oracle.rs"
cat >> "$cdht_upstream/veilid-core/src/storage_manager/mod.rs" <<'RS'
#[path = "cdht_store_oracle.rs"]
mod cdht_store_oracle;
RS
cp ci/veilid_oracle.rs "$cdht_upstream/veilid-core/src/cdht_oracle.rs"
cat >> "$cdht_upstream/veilid-core/src/lib.rs" <<'RS'
#[doc(hidden)]
pub mod cdht_oracle;
RS
mkdir -p "$cdht_upstream/veilid-core/examples"
cat > "$cdht_upstream/veilid-core/examples/cdht_vectors.rs" <<'RS'
fn main() {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
        .block_on(veilid_core::cdht_oracle::generate());
}
RS
# Avoid linking unused FFI library variants for this Rust-only test harness.
sed -i 's/crate-type = \["cdylib", "staticlib", "rlib"\]/crate-type = ["rlib"]/' "$cdht_upstream/veilid-core/Cargo.toml"
export CDHT_VECTORS="$cdht_root/target/veilid-vectors.json"
export CDHT_IMPORT="$cdht_root/target/cdht-import.json"
mkdir -p "$cdht_root/target"
cargo run --locked --example upstream_import
export CARGO_TARGET_DIR="$cdht_root/target/veilid-oracle"
export CARGO_BUILD_JOBS=2
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_DEV_OPT_LEVEL=0
mkdir -p "$cdht_root/target"
cd "$cdht_upstream"
cargo run --locked -p veilid-core --example cdht_vectors --no-default-features --features rt-tokio,enable-crypto-vld0,test-util
cp Cargo.lock "$cdht_root/target/veilid-Cargo.lock"
cd "$cdht_root"
unset CARGO_TARGET_DIR
cargo test --locked --test conformance -- --ignored --nocapture

cargo test --locked --lib upstream_ -- --ignored --nocapture

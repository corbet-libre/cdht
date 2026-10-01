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
    encode_signed_value_descriptor as cdht_descriptor_encode};
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

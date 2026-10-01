# Veilid conformance

Target: `veilid-core` package version 0.5.7 at main commit
`dd8e2cdd72b5bf817172ac31c20872b168c5c8fc`. This is not the 0.5.7 release tag.
The main revision has encrypted record formats absent from older releases.

## Mirrored source inventory

All paths below are relative to [the pinned upstream tree](https://gitlab.com/veilid/veilid/-/tree/dd8e2cdd72b5bf817172ac31c20872b168c5c8fc).
Ports retain MPL-2.0 notices. The generated Cap'n Proto module closure listed in `ci/upstream-modules.txt` is reused
unchanged; RustCrypto and dalek provide primitives. `veilid-core` is too broad
for this network-free library; it belongs to the network adapter.

| Upstream file | Local implementation |
|---|---|
| `veilid-core/src/storage_manager/record_key.rs` | `src/record.rs` |
| `veilid-core/src/veilid_api/types/dht/derivation.rs` | `src/record.rs`, `src/schema.rs` |
| `veilid-core/src/storage_manager/schema.rs` | `src/schema.rs` |
| `veilid-core/src/veilid_api/types/dht/schema/mod.rs` | `src/schema.rs` |
| `veilid-core/src/veilid_api/types/dht/schema/dflt.rs` | `src/schema.rs` |
| `veilid-core/src/veilid_api/types/dht/schema/smpl.rs` | `src/schema.rs` |
| `veilid-core/src/storage_manager/types/signed_value_descriptor.rs` | `src/record.rs` |
| `veilid-core/src/storage_manager/types/signed_value_data.rs` | `src/record.rs` |
| `veilid-core/src/storage_manager/types/encrypted_value_data.rs` | `src/record.rs` |
| `veilid-core/src/storage_manager/record_encryption.rs` | `src/crypto.rs` |
| `veilid-core/src/crypto/crypto_system/vld0/mod.rs` | cipher in `src/crypto.rs`; signing and verification ports |
| `veilid-core/src/crypto/types/record_key.rs` | full read-capability encoding in `src/crypto.rs` |
| `veilid-core/proto/veilid.capnp` | source of the generated ValueData/PublicKey/Nonce modules |
| `veilid-core/proto/veilid_capnp.rs` | `src/veilid_capnp.rs` (unchanged closure listed in ci/upstream-modules.txt) |
| `veilid-core/src/rpc_processor/coders/mod.rs` | `SignedValue::raw_blob` canonicalization |
| `veilid-core/src/storage_manager/set_value.rs` | sequence assignment in `src/client.rs`; node acceptance in `src/backend.rs` |
| `veilid-core/src/storage_manager/get_value.rs` | validation and cache in `src/client.rs` |
| `veilid-core/src/storage_manager/rehydrate.rs` | signed-value replay on open in `src/client.rs` |
| `veilid-core/src/storage_manager/offline_subkey_writes.rs` | coalescing queue in `src/client.rs` |

## Verification

The required `conformance` CI job compiles this exact upstream checkout and runs
its own `DHTSchema`, record-key derivation, `SignedValueDescriptor`,
`EncryptedValueData`, `SignedValueData` and VLD0 crypto implementation. It never
attaches to a network. The only checkout changes add the generator module/example
and suppress unused static/CDylib outputs; no algorithm is patched.
A CI-only internal storage hook also imports independently signed Records bytes
into actual native remote and local stores, rejects a forged remote value,
reopens TableStore, and compares original descriptor/value bytes. Upstream
open_record must queue the usual full-record owner rehydration after local
reopen without receiving a signer or read secret. This proves storage and
scheduling only when the oracle passes; it never attaches to a network or
claims that owner fanout or Tor lost-device restore completed.

The actual native import/reopen and owner-rehydration scheduling oracle passed at
`aaf8b6d46b8f2abebbd4c7d2f16b3fb7d7f0e88d` in
[CI 36930027164](https://github.com/corbet-foss/cdht/actions/runs/36930027164),
alongside strict native and executed Wasm vectors. The full run remained red at
the strict coverage gate (1815/1861 production lines, 310/340 branch outcomes;
zero handwritten exclusions). This is component evidence, not acceptance.

Five schema cases include DFLT boundaries, zero owner slots, zero-sized members,
repeated writers and owner-as-member. Sixty value cases cover clear/encrypted
records, sequence 0/1/MAX and lengths 0/1/7/8/9/127/1024/8191/8192/32768, including
multi-segment canonicalization. cdht independently recreates each value and
requires byte equality for schema, locator, full read capability, descriptor
signature, ciphertext, raw blob and value signature, then validates received
upstream blobs. Vectors and both Cargo lockfiles are retained as CI artifacts.
The ordinary Rust job explicitly ignores this test; the oracle job must run it.

`tests/network.rs`, `tests/records.rs`, `tests/adversarial.rs` and the existing
record tests exercise independent node storage, 5/3 fanout, partial read evidence,
owner restore into empty nodes, offline supersession, forged acknowledgments,
sequence exhaustion, LRU/count/byte limits, no TTL and watch lease loss.
[CHURN](CHURN.md) records population measurements and their model limitations.

## Behavioral sources and scope

Additional behavior mirrored from the same commit:

| Upstream file | Local implementation |
|---|---|
| `veilid-core/src/veilid_config.rs` | native/browser capacity and 5/3 targets |
| `veilid-core/src/storage_manager/constants.rs` | five-minute rehydration recheck |
| `veilid-core/src/storage_manager/record_store/record_store_limits.rs` | bounded remote stores and public leases |
| `veilid-core/src/storage_manager/record_store/record_store_inner/record_index.rs` | LRU eviction |
| `veilid-core/src/storage_manager/watch_value.rs` | watch port, subscription loss and change hints |
| `veilid-core/src/storage_manager/record_store/record_store_inner/inbound_watches/inbound_watch_list.rs` | expiry/count tracking |
| `veilid-core/src/storage_manager/tasks/offline_subkey_writes.rs` | explicit caller-driven flush |
| `veilid-core/src/storage_manager/get_value.rs` | `NetworkBackend::read`, equal-value agreement and partial results |
| `veilid-core/src/storage_manager/set_value.rs` | `NetworkBackend::set`, conflict restart and five acknowledgments |
| `veilid-core/src/storage_manager/rehydrate.rs` | consensus inspection and verbatim republishing on open |
| `veilid-core/src/routing_table/types/hash_coordinate.rs` | VLD0 XOR coordinates in `src/network.rs` |

Relevant upstream tests reviewed: `crypto/tests_crypto/test_crypto_sign.rs`,
`crypto/tests_crypto/test_crypto_no_auth.rs`,
`storage_manager/tests_storage_manager/test_encrypted_value_data.rs`,
`storage_manager/tests_storage_manager/test_inbound_set_value_signature.rs`,
and schema serialization tests under `veilid_api/tests_veilid_api`.

## Deviations requiring manager review

No entry in this table is an approved change to the binding architecture. Format
byte equality is tested; complete StorageManager/runtime equivalence is not claimed.

| ID | Deviation / open integration | Reason and consequence |
|---|---|---|
| D1 | Mesh/Tor and Veilid runtime adapters remain outside this repository. The historical Mesh hook dropped signatures/nonces and accepted secret signing keys; its message-only replacement removes those hooks. | [NETWORK-PORT](NETWORK-PORT.md) specifies the original-byte adapter. Actual native import/reopen and owner-rehydration scheduling passed in the oracle above; there is no live Tor DHT or attached-network owner-fanout result yet. Re-signing through the historical hook is forbidden. |
| D2 | Fanout is sequential over at most 20 discovered candidates, with at most 20 conflict restarts. | The runtime-independent port has no scheduler, iterative routing table, node-reliability ranking or RPC deadline policy. Upstream uses concurrent iterative fanout, consensus-width 10 and background continuation. Same 5/3 targets do not imply identical scheduling, latency or failure behavior. Equal-sequence conflicts can remain unavailable; no custom winner is invented. |
| D3 | Rehydration performs per-subkey reads/sets synchronously on open, caching successful checks for five minutes. | Upstream inspects ranges and schedules background requests per record, including transaction-set rehydration. Both require an answered inspection before repair; failed checks here retry on the next open. This API has no multi-record transactions; it preserves each signed value but does not reproduce transaction atomicity or task scheduling. |
| D4 | Watch implementation covers public full-record subscriptions, coalescing, count, ten-minute leases and the 32-public-watch limit. | The eight-per-member authenticated watch class, subkey-range subscriptions, multi-node reconciliation, fallback inspection, route pinning and automatic renewal are not implemented in this record engine. Mesh must surface lease loss; clients refresh after gaps. This is the principal remaining behavior gap within cdht. |
| D5 | Remote storage is an in-memory implementation with logical-byte accounting; durable storage is an adapter responsibility. | Upstream's byte estimate includes TableStore JSON/encryption overhead. Default record/byte limits and LRU policy match, but byte-triggered eviction can differ with custom tight limits. Node snapshots are not compatible with Veilid TableStore. |
| D6 | Local state is an exported caller-persisted snapshot; signing and production record encryption use external scoped capability ports. | No second Veilid runtime, private-key custody or implicit key generation is introduced. `create` returns the opaque locator; the caller separately holds the full read capability. A valid old whole-store snapshot needs an external freshness floor. |
| D7 | Explicit `flush`/open/clock calls replace autonomous maintenance timers. | The embedding runtime must drive them. Stopped/suspended applications perform no maintenance. This is observable in offline availability and watches, and is tested as such in the session model. |
| D8 | Application sync and epoch formats are outside Records. | Removed the former epoch-header and sync API. Per-device logs, clocks, tombstones and keep-both semantics belong to the data-owning library inside opaque record contents. Ordinary create reserves no subkey. Record keys, signature inputs and ciphertext framing remain Veilid formats. |
| D9 | Strict bounded decoding rejects trailing Cap'n Proto bytes and malformed VLD0 key/nonce lengths earlier than the upstream deserializer. | Arrival must be validated before use. Valid original blob bytes are retained, including noncanonical encodings, so signatures are never checked against rewritten input. |
| D10 | Churn uses synthetic phone schedules and an ideal in-process transport. | It measures this implementation under the stated population/session/storage assumptions. It is not actual Tor bootstrap, routing, transport-loss or public-network retention evidence. |

These deviations and open adapter work must be reviewed before calling the full
Tor/Veilid switching requirement complete. The current CI proves the recorded
format and component behaviors, not end-to-end transport equivalence.

## Original RPC byte boundary

`rpc` uses the unchanged upstream generated modules and mirrors the existing
SignedValueData, SignedValueDescriptor and SignedOperation coders. It preserves
the original signed ValueData blob and VLD0 nonce. SignedOperation binds the
original Operation bytes to the typed destination public key exactly as upstream;
expected peer keys still require authenticated node routing information.
GetValueQ/SetValueQ and their answers use upstream operation IDs and schema fields.
Answers validate record authority against their originating question. Opaque
PeerInfo hints preserve signed NodeInfo bytes but remain unverified until the
routing owner validates them. The upstream oracle also compares answer bytes
through its original GetValueA/SetValueA coders. A signed
packet alone is not record freshness, membership, node discovery or D1 completion.
WatchValueQ/WatchValueA now mirror the upstream coders and are compared with
actual upstream vectors. range-set-blaze 0.6 is the same maintained range
collection used by Veilid; no separate merging algorithm is added.
ValueChanged statement bytes are also compared against the upstream coder.
Watch/inspect handlers, notification delivery and full runtime fanout remain
integration work; watch vectors do not close D4.

Generated upstream `veilid_capnp.rs` is excluded from our line/branch denominator:
it is compiler output, copied unchanged, checked byte-for-byte against upstream
on every oracle run. All handwritten record, RPC, client, store and network code
remains inside the strict gates. The upstream oracle also compares the complete
SignedValueData and SignedValueDescriptor RPC bytes, including multi-segment
canonicalization. These byte tests are not real Tor restore evidence.

Descriptor identity follows upstream cmp_no_sig after signature validation:
compare owner and schema, preserving the descriptor already stored. An ordinary
native/Wasm fixture uses maintained dalek's low-level signing API solely to
produce a second valid signature over the same public test seed and content.
No production key construction or signing algorithm is implemented here.

The standalone record-cipher capability now rejects more than the upstream
32 KiB subkey bound before allocating output. Every accepted call constructs a
fresh RustCrypto XChaCha20. Its
[maintained implementation](https://docs.rs/chacha20/latest/src/chacha20/xchacha.rs.html)
uses64-byte blocks and a u32 counter, and its
[constructor](https://docs.rs/chacha20/latest/src/chacha20/lib.rs.html)
starts that counter at zero. The bounded input therefore cannot exhaust it;
a compile-time upper-bound assertion preserves that precondition. The counter
error was an unreachable mapper for bounded record use and is now an explicit
invariant assertion. Native/Wasm vectors cover empty, maximum and oversized
inputs. Valid record encryption bytes and the owner-supplied RecordCipher port
are unchanged; no cipher implementation or coverage exclusion is introduced.


Locally generated Cap'n Proto builders own a valid root and contain data/struct
pointers created by maintained setters. Incoming PeerInfo is copied only by the
fallible deep-copy setter before it enters such a builder; a failed copy exits.
Canonicalizing these completed builders therefore uses explicit assertions for
that construction invariant. Immutable PeerInfo roots were shape-checked by their
only public constructor. Unknown nested PeerInfo pointers remain fallible during
copying; no input decoder is replaced by an assertion.

The locked capnp0.26.2 `serialize_packed::write_message` documents that only the
writer can return an error. Our concrete writer is `Vec<u8>`: append succeeds or
allocation aborts; it cannot return an I/O error. This invariant is distinct from
fallible bounded external-message decoding. Existing native/Wasm maximum-sized,
multi-segment and hostile-pointer vectors continue to exercise both boundaries.


Opaque PeerInfo shape decoding follows upstream `decode_peer_info`'s maximum of
three signature entries (`crypto::MAX_CRYPTO_KINDS`) before iterating them. This
is a bound only, not authentication or a new supported cryptosystem. A dedicated
fixture alters the generated list's word/pointer counts so a valid known field
coexists with an invalid unknown pointer; deep copying must still return Encoding.

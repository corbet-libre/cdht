# Agent instructions

Write all code comments and documentation in English.

## Product boundary

- Signed replicated records with Veilid DHT semantics (DFLT/SMPL schemas, record key
  derivation and limits identical to Veilid), a client with offline queue, watch,
  VLD0 encryption and optional epochs, the `Backend` / `Network` ports, independent
  capacity-bounded node stores, closest-node replication, and the sync
  rules (per-device logs, hybrid logical clock, monotonic tombstones, keep-both).
- No production secret keys: sign/verify through `Signer` / `Verifier` and encrypt/open through scoped `RecordCipher`; independent upstream read-capability codecs are not a Keys export path.
- No network code: remote fillings come through `cmsh`'s DHT capability (no layer
  skipping; never depend on `veilid-core` here).
- No policy: which records exist and who may write them is decided by `cvlt`.
- No CRDT library (decision 2026-09-25); keep-both instead of merging.
- Never trust a backend or persisted state: validate descriptors and values on arrival.
- LGPL-3.0-only WITH LGPL-3.0-linking-exception. Do not add code available only under the
  full GPL or AGPL. Code copied from Veilid (MPL-2.0) goes into its own MPL-2.0 file with
  the upstream notice.

## Layout

- `src/schema.rs`, `src/record.rs`: schema, descriptor, record key, signed value.
- `src/backend.rs`: `Backend` port, capacity-bounded `LocalBackend`.
- `src/network.rs`: `Network` port, `NetworkBackend`, read agreement and write fanout.
- `src/veilid_capnp.rs`: unchanged upstream generated record modules (MPL-2.0).
- `src/client.rs`: `Dht`, queue, epochs, `ClientState`.
- `src/crypto.rs`: ports and record encryption.
- `src/sync.rs`: sync rules.
- `tests/common`: actual maintained dalek VLD0 signing and verification for fixtures.

## Quality boundary

- `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, and
  `cargo clippy --lib --target wasm32-unknown-unknown -- -D warnings` — all green in CI
  (GitHub Actions). No local workstation builds.

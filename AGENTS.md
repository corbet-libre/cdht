# cdht — agent instructions

Work in a lane, never in ~/agents/scratch/ws. From the repo dir:
`cargo fmt --all -- --check`,
`cargo clippy --locked --all-targets -- -D warnings`,
`cargo test --locked --no-fail-fast`,
`cargo clippy --locked --lib --target wasm32-unknown-unknown -- -D warnings`,
`CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner cargo test
--locked --target wasm32-unknown-unknown --lib --test records --test network
--test adversarial --test rpc`.
Conformance oracle: `ci/veilid-vectors.sh` (byte-identical Veilid, D1–D10).
Coverage gate: `python3 .github/test-source-coverage.py &&
python3 .github/check-source-coverage.py coverage.lcov coverage.json coverage.txt`.
First-party git deps on main, one locked revision
(`python3 .github/check-first-party.py`).

Invariants (rules: docs/CONTRACT.md):
- Never trust the network: forged/malformed/replayed backend replies never ack
  or discard signed queue/cache (tests/adversarial.rs).
- Transport preserves original blobs, signatures, sequence and nonces; forward
  unchanged, never re-sign, renumber or re-encrypt (tests/rpc.rs).
- 5 closest copies, 3-copy read agreement + explicit partial evidence;
  silence/offline is never absence or ack (tests/network.rs:52,139,187,725).
- Bounded stores: LRU, no TTL/expiry, record + byte quotas (tests/network.rs:220,317).
- Owner rehydration reuses existing signed values without re-signing (:106).
- queue_original stages an already-signed pair unchanged; cached observations and
  same-slot obligations fence generation; equal-sequence differences refuse
  (tests/original_publication.rs).
- No secret keys: sign/verify via Signer/Verifier, open via scoped RecordCipher;
  get_signed before open_value (tests/records.rs:493,544).
- Watch events are hints, not contents; leases explicit, loss observable
  (tests/watches.rs).
- No policy (cvlt decides records/writers), no application formats in contents,
  no veilid-core dep, no record expiry.

Pointers: docs/CONTRACT.md, docs/CONFORMANCE.md, docs/CHURN.md,
docs/NETWORK-PORT.md, docs/COVERAGE.md, tests/records.rs, tests/network.rs,
tests/adversarial.rs, tests/original_publication.rs, tests/exact_publication.rs.

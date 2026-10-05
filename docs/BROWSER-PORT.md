# cdht browser port contract (for real `cmsg` over Tor)

Intended caller: real `cmsg`, with a Tor record runtime filling
[`Network`](../src/network.rs) over Mesh's message port. That runtime is
missing: this repository holds no transport, and the Tor backend advertises
`dht: false` (a byte-preserving DHT port, only when independently qualified).
DHT record work belongs to Records layered over messages, not to a new Mesh DHT capability.
`cdht` opens no sockets and production code never depends on `veilid-core` ([README](../README.md), [CONTRACT](CONTRACT.md), [NETWORK-PORT](NETWORK-PORT.md)).

## What the intended caller must provide (missing)

- Storage: `ClientState` is a plain-data snapshot the caller persists in its
  encrypted store; `LocalBackend` is one in-memory node only — only a future
  adapter can own a durable peer store ([client](../src/client.rs), [backend](../src/backend.rs), [NETWORK-PORT](NETWORK-PORT.md)).
- Network: a Tor object implementing [`Network`](../src/network.rs) (`now_ms`, `closest`,
  per-node `descriptor`/`get`/`set`/`watch`/`cancel_watch`/`changes`) carrying original
  signed RPC bytes over the message port ([NETWORK-PORT](NETWORK-PORT.md), [rpc](../src/rpc.rs)).
- Clock: `Network::now_ms` plus `LocalBackend::advance_to`; the runtime must drive
  `flush`/`open`/clock — there is no timer thread ([network](../src/network.rs), [backend](../src/backend.rs)).
- Keys: `Signer`, `Verifier`, scoped `RecordCipher` from Keys; standalone
  `EncryptionKey` is Veilid-interop only, not a Keys export ([crypto](../src/crypto.rs), [CONTRACT](CONTRACT.md)).

## Public surface the caller programs against

- Client: `Dht<B, V>`, `ClientState`, `QueuedWrite`, `WriteOutcome`, `FlushReport`:
  `create`/`open`/`get`/`get_signed`/`open_value`/`set`/`queue_create`/`queue_set`/
  `flush`/`watch`/`cancel_watch`/`changes` ([client](../src/client.rs), [lib](../src/lib.rs)).
- Node port: `Backend`, `LocalBackend`, `Capacity`, `SetOutcome`, `Change`, `WatchId`,
  `MAX_WATCH_MS`, `PUBLIC_WATCH_LIMIT` ([backend](../src/backend.rs)).
- Replication port: `Network`, `NetworkBackend`, `ReadReport` (`has_consensus`), `NodeId`,
  `SET_VALUE_COUNT = 5`, `GET_VALUE_COUNT = 3`, `MAX_FANOUT_NODES = 20` ([network](../src/network.rs)).
- Records: `RecordKey` (`VLD0:<base64url>`), `Descriptor`, `SignedValue`
  (`raw_blob`/`from_blob`/`signed_bytes`/`validate`), `Schema`/`Member`, `MAX_SEQ`,
  32 KiB/subkey, 1 MiB/record, 1024 subkeys, 256 writers ([record](../src/record.rs), [schema](../src/schema.rs)).
- RPC bytes: `rpc::Query`/`Question`/`SignedOperation`/`Answer`/
  `ValueBytes`/`DescriptorBytes`, `MAX_RPC_BYTES = 65507`; adapters must forward
  bytes verbatim — never re-sign, renumber, re-encrypt or synthesize acks
  ([rpc](../src/rpc.rs), [NETWORK-PORT](NETWORK-PORT.md)).

## Browser build selectors (configured; not executed here)

- `getrandom` uses feature `wasm_js` under
  `cfg(all(target_arch = "wasm32", target_os = "unknown"))`; nothing else is
  browser-conditional in `[dependencies]` ([manifest](../Cargo.toml)).
- `LocalBackend::new` selects `Capacity::BROWSER` under that same `cfg`, `NATIVE` otherwise ([backend](../src/backend.rs)).
- CI (configured): `cargo clippy --locked --lib --target wasm32-unknown-unknown -- -D warnings` and
  `cargo test --locked --target wasm32-unknown-unknown --lib --test records --test network --test
  adversarial --test rpc` under `wasm-bindgen-test-runner` ([ci](../.github/workflows/ci.yml)).
  Native `cargo test`, native clippy, `cargo fmt --check`, oracle and coverage gates are unchanged.
- Selector gaps (reported, CI untouched): the wasm selector runs `records`, `network`, `adversarial`,
  `rpc` plus lib only — not [conformance](../tests/conformance.rs) (ordinary job ignores it; the
  oracle job must run it), not [churn](../examples/churn.rs), and no Tor-connected browser-peer path
  is configured here ([ci](../.github/workflows/ci.yml), [CONFORMANCE](CONFORMANCE.md)).

## Browser capacity policy

- Browser node: 64 remote records / 128 MiB; native: 128 / 256 MiB
  (`Capacity::BROWSER` / `NATIVE`, from `veilid_config.rs` at `dd8e2cdd`).
- LRU eviction, no record expiry; the device's own `ClientState` lives outside remote LRU;
  watch leases cap at 10 min / 32 public watches per record
  ([backend](../src/backend.rs), [CONFORMANCE](CONFORMANCE.md)).

## Persisted / outbox / reopen / agreement semantics

- Stage inside the key-owner callback: `queue_create`/`queue_set` sign
  synchronously, then persist `ClientState` through the vault transaction
  before `flush`; `flush` needs no signer and forwards exact queued bytes.
  A queued sequence is local intent, never an acknowledgment
  ([client](../src/client.rs), [NETWORK-PORT](NETWORK-PORT.md)).
- Read split: `get_signed` fetches signed bytes, `open_value` validates then
  opens them under the scoped cipher inside the owner callback ([client](../src/client.rs)).
- Reopen: `with_state` re-validates every descriptor/value; `open` refreshes the descriptor
  and rehydrates cached signed values verbatim; a failed check retries on the next open and
  never becomes a blind write ([client](../src/client.rs)).
- Agreement: writes complete on 5 distinct acknowledgments; reads seek 3 identical values
  and report partial evidence via `ReadReport` (`has_consensus`); exhaustion may return
  a below-target validated value ([network](../src/network.rs)).
- Absence: this codebase has no `KnownAbsent` symbol. A reachable node without the
  record/subkey answers `Ok(None)`; silence/unreachability is `Unavailable`; unknown local
  state is `UnknownRecord`/`NotOpen`. Missing replicas never prove an empty vault and never
  erase local state ([error](../src/error.rs), [network](../src/network.rs), [NETWORK-PORT](NETWORK-PORT.md)).
- No restore API is defined here: no PRF-derived-locator lookup and no passkey recovery
  entry point. `EncryptionKey::parse_record_key` only splits a full read capability ([crypto](../src/crypto.rs)).

## What the checked-in tests are (and are not)

- Crypto/schema byte vectors: configured upstream-oracle targets (`veilid-core` 0.5.7 +
  main `dd8e2cdd`) and configured native and Wasm test targets
  ([conformance](../tests/conformance.rs), [records](../tests/records.rs),
  [rpc encoding](../tests/support/rpc_encoding.rs); [CONFORMANCE](CONFORMANCE.md)).
  This package produced no execution evidence; source review is not proof.
- Controlled in-memory network tests: per-node stores over a simulated port — e.g.
  `five_closest_copies_three_read_agreement_and_partial_evidence`, `owner_rehydrates_after_all_remote_copies_are_lost_without_resigning`,
  `rehydration_requires_an_answer_and_does_not_treat_silence_as_absence`,
  `concurrent_equal_sequence_holders_never_manufacture_a_winner`, and
  `fresh_device_restores_sealed_state_and_offline_messages_without_the_old_device` (injected
  capabilities; not WebAuthn/PRF, identity/membership or Tor — [CHURN](CHURN.md)),
  plus `offline_writes_are_queued_and_flushed` and `capacity_uses_lru_and_no_record_ttl`
  ([network](../tests/network.rs), [records](../tests/records.rs),
  [adversarial](../tests/adversarial.rs), [rpc](../tests/rpc.rs)).
- Not present: deployed browser peers, a Tor-connected record path, or active-member
  restore/holding acceptance. Required next evidence is actual browser build/execution plus
  a real Tor-connected create/get/set/watch, offline-queue and owner-rehydration run with
  independent participants, no operator store and no direct peer sockets ([CONTRACT](CONTRACT.md),
  [NETWORK-PORT](NETWORK-PORT.md)). Endpoint parsing is not such evidence.

## Historical capacity measurement (with provenance and limits)

- From [CI run 36886335654](https://github.com/corbet-foss/cdht/actions/runs/36886335654),
  source `5cc20d9c92fedd6e37a86d3d8f98404b89bbf414`,
  [raw CSV](results/churn-5cc20d9.csv): the pressure workload (browser
  capacity, 3 records/phone) restored 50/59 observed device losses within 24 h
  at 1,000 phones (9 missed) and 9/12 at 250 phones; native capacity with one
  record/phone had no observed failure in its small samples ([CHURN](CHURN.md)).
- Limits preserved: synthetic schedules, ideal in-process transport, no Tor /
  browser-suspension / privacy model; not a restore promise or Tor
  qualification ([CHURN](CHURN.md)).

## Owner prerequisites for a real browser/Tor gate

1. A Tor record runtime filling [`Network`](../src/network.rs) with authenticated peers, bounded
   RPCs/deadlines, durable per-node stores and a driven watch clock; `cmsg` persisting
   `ClientState` and driving `flush`/`open`/clock.
2. Vault/Keys scoping `Signer`/`Verifier`/`RecordCipher` (browser executor
   safe); `cprz` compress-then-Padmé before Records encrypts (Records adds no
   compression/padding of its own) ([NETWORK-PORT](NETWORK-PORT.md)).
3. Browser execution of the configured wasm selector plus a two-device
   Tor run: offline flush, watch loss/recovery, restart, owner rehydration —
   then measured active-device-loss recovery with the old device offline
   ([NETWORK-PORT](NETWORK-PORT.md), [CONTRACT](CONTRACT.md)).

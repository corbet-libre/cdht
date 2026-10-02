# cdht

**Signed replicated records with Veilid DHT semantics.**

Authorisation is part of the record: the owner signs the schema, the schema lists
writers and subkeys, and every write is checked wherever it lands.

## Scope

**Purpose.** Encrypted replicated records with Veilid-identical formats carry vault restore, device state, and offline messages over either network backend.

**Owns.**
- Veilid-identical DFLT/SMPL schemas, descriptors, record keys, signed values, encrypted values, and VLD0 signatures; no re-signing, renumbering, or re-encryption in transit.
- DHT client operations create, open, get, set, and watch, with an offline write queue and owner rehydration of existing signed values on open.
- Node behavior while the app is in use with bounded per-node storage (128 records / 256 MB native, 64 records / 128 MB in browsers), least-recently-used eviction, no record expiry, writes to the 5 closest nodes, and reads requiring agreement of 3.
- Restore from the passkey-derived locator, and per-device sync using signed logs, hybrid logical clocks, keep-both versions, and monotonic tombstones without a CRDT library.

**Never.**
- No record expiry, operator storage, volunteer mailboxes, always-on nodes, Tor-only formats, or invented keys, schemas, consensus, or retention rules.
- No contact or group policy decisions; record owners decide which records and writers exist.
- No secret-key custody and no network or socket code; signing, verification, and record encryption arrive through injected `Signer`, `Verifier`, and `RecordCipher` ports supplied by `ckmg`, transport arrives through `cmsh`, and production never depends on `veilid-core` directly.
- No plaintext or cross-community replication, no restore guarantee without a surviving passkey and available replicas, and missing replicas are never treated as empty.

**States.**
- Per record, queued write to flushed; active watch to lost lease to refreshed; reads report Available or Unavailable, never empty from missing replicas; the device serves as a node while in use.

**Test obligations.**
- Upstream byte conformance on native and WebAssembly for schemas, keys, descriptors, signatures, ciphertext, and VLD0, with the upstream implementation as oracle.
- Queued writes, watches, quorum reads and writes, capacity and eviction, and stale and conflicting records under upstream rules, including no local winner for equal-sequence conflicts, plus import of existing signed values across backends without conversion.
- Device-loss restore with the same synced passkey on a new device recovers identity, memberships, contacts, and history without operator storage; loss of all device copies plus no recoverable replicas means equal loss for every passkey, and a network outage alone is not permanent loss.
- Data is packed with `cprz` compression, then padding, then VLD0 encryption into as few records as possible so size reveals nothing; population churn is measured and reported honestly with evidence that no record lives on operator storage.
- Common obligations: stable Rust for native and WebAssembly with identical vectors; explicit state machines with injected clock, randomness, storage, and network; full line and branch coverage with real round trips and injected delay, loss, cancellation, corruption, and conflicts; atomic publication with durable acceptance before acknowledgement and reconciliation of unknown outcomes; per-community isolation; bounded work with secrets omitted from errors; reused third-party cryptography; no personal identifiers in outbound requests.

## Records

| Concept | Behaviour | Veilid equivalent |
|---|---|---|
| Schema | DFLT owner slots; SMPL owner and member slot ranges | DFLT and SMPL, byte-identical compiled form |
| Descriptor | owner signs the compiled schema | `SignedValueDescriptor` |
| Record key | BLAKE3(`VLD0` ‖ owner ‖ schema), text `VLD0:<base64url>` | opaque record key, identical |
| Value | sequence number + data + writer + writer signature; higher seq wins | `SignedValueData` (upstream byte oracle in CI) |
| Limits | 32 KiB per subkey, 1 MiB per record, 1024 subkeys, 256 writers | same constants |
| Encryption | optional per-record key, XChaCha20, nonce authenticated by the value signature | encrypted records |

DFLT and SMPL match the referenced Veilid schemas, including zero owner slots,
zero-sized member entries, repeated writers and owner-as-member slots. Ordinary
`create` leaves every subkey empty.

Value signatures use Veilid's legacy owner/subkey/sequence/data input for clear
records, and its unpacked Cap'n Proto blob input for encrypted records. Record
encryption is XChaCha20 with a separate signed nonce, without an AEAD tag. Wrong
read keys produce garbage; application formats must detect unusable plaintext.
No adapter may re-sign, renumber or re-encrypt a stored value during transport.
See [CONFORMANCE](docs/CONFORMANCE.md) for the source inventory and deviations.

## Client

`Dht<B: Backend, V: Verifier>`: create, open, get, set, watch; an **offline write queue**
(writes that cannot reach the backend apply locally, queue, and flush later; a newer write
to the same subkey supersedes a queued one; stale queued writes are reported); persisted
state (`ClientState`, no secrets) is re-validated on resume; nothing a backend returns is
trusted.

## Backends and network port

`NetworkBackend<N, V>` performs closest-node fanout over `Network`: five write
acknowledgments, three-copy read agreement, explicit partial read evidence,
validated conflict responses and owner rehydration of existing signed values.
`LocalBackend` is one independently bounded node store, with native/browser
capacity presets, LRU eviction, no record expiry and bounded public watch leases.

Mesh supplies message transport. Its previous signature/nonce-losing DHT
hook has been retired; the replacement runtime adapter and durable node store
remain incomplete. [NETWORK-PORT](docs/NETWORK-PORT.md) specifies the integration.
The future Veilid adapter must import and republish existing signed values;
calling a signing `set_dht_value` API alone is insufficient.

`cdht` contains no network implementation and never depends on `veilid-core` in
production. Its dedicated conformance CI job builds an exact upstream revision as an
independent oracle. [CHURN](docs/CHURN.md) describes the simulated population
measurements; they are not live Tor measurements.

## Crypto ports

`Signer` and `Verifier` are ports: `cdht` never holds a secret key. In the vault, `cvlt`
adapts `ckmg` (VLD0: Ed25519ph with context `VLD0_SIGN`); the tests use the maintained ed25519-dalek
implementation with the same semantics. This also keeps `cdht` free of private dependencies, so
its CI runs on hosted runners.

## Boundaries

No application policy: data owners choose records and writer sets; `ckmg` owns device
lineage. No secret keys or socket code. Restore depends on available peer records.

## Open points / TODO

- Mesh/Tor and Veilid adapter integration (above).
- Group membership without a server (MLS commit arbitration) is a separate design topic
  (`cgrp`), not part of `cdht`.
## License

Copyright 2026 Julian Y. Richard Corbet. Licensed under
[LGPL-3.0-only](LICENSES/LGPL-3.0-only.txt)
[WITH LGPL-3.0-linking-exception](LICENSES/LGPL-3.0-linking-exception.txt).
See [LICENSE.md](LICENSE.md).

## Continuous verification

Dependency updates follow main and are tested against one CI-resolved lockfile.
Line and branch coverage target 100%; failures remain blocking. See
[the coverage contract](docs/COVERAGE.md) for measurement and exclusions.

Watch RPC range encoding reuses upstream's maintained `range-set-blaze` 0.6
collection. The codec retains upstream microsecond durations, notification count
and node-local lease identifiers; it does not introduce a watch policy or timer.
Actual upstream WatchValueQ/WatchValueA coders supply independent byte vectors.

# cdht

**Signed replicated records with Veilid DHT semantics.**

Authorisation is part of the record: the owner signs the schema, the schema lists
writers and subkeys, and every write is checked wherever it lands.

## Scope

**Purpose.** Carry encrypted vault, device and offline-message records over either
network backend using Veilid-compatible schemas, descriptors, signatures and VLD0.

**Owns.** Record validation, create/open/get/set/watch, an offline write queue,
owner rehydration, bounded device-node storage and the Veilid replication rules.
Application data stays opaque. All subkeys are available to the record owner.

**Never.** Store operator records, impose record expiry, invent retention or
consensus, interpret application sync or membership formats, retain signing keys,
or perform socket I/O. Missing replicas never establish an empty vault.
Domain libraries own per-device logs, clocks, keep-both and tombstones inside
record contents; they compress and pad before Records encrypts.

**States and ports.** Queued → flushed writes; leased watches with explicit loss;
Available / Unavailable reads. `Dht`, `Backend`, `Network`, and scoped `Signer`,
`Verifier`, `RecordCipher` capabilities. Mesh carries original signed record RPC
bytes. The device stores its own copy and serves other records while in use.

**Invariants and tests.** Preserve original signatures and nonces; no secret-key
export or operator record store. Upstream native/Wasm byte conformance, queue,
watch, capacity/LRU, conflict and rehydration tests are required. Active-device-loss
restore and Tor-to-Veilid import require real network evidence beyond format tests.
See [CONTRACT](docs/CONTRACT.md), [CONFORMANCE](docs/CONFORMANCE.md) and
[CHURN](docs/CHURN.md) for the exact incomplete production seams and failed churn
acceptance evidence. No retention or complete restore claim is made here.

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

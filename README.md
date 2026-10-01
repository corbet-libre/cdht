# cdht

**Signed replicated records with Veilid DHT semantics, and the sync rules for a member's
own devices.**

`cdht` replaces the former lineage and sync libraries of the member vault with one
building block, the DHT record. Authorisation is part of the data structure: the owner
signs the schema, the schema lists the writers and their subkeys, and every write is
checked against it wherever it lands.

## Records

| Concept | Behaviour | Veilid equivalent |
|---|---|---|
| Schema | DFLT owner slots; SMPL owner and member slot ranges | DFLT and SMPL, byte-identical compiled form |
| Descriptor | owner signs the compiled schema | `SignedValueDescriptor` |
| Record key | BLAKE3(`VLD0` ‖ owner ‖ schema), text `VLD0:<base64url>` | opaque record key, identical |
| Value | sequence number + data + writer + writer signature; higher seq wins | `SignedValueData` (upstream byte oracle in CI) |
| Limits | 32 KiB per subkey, 1 MiB per record, 1024 subkeys, 256 writers | same constants |
| Encryption | optional per-record key, XChaCha20, nonce authenticated by the value signature | encrypted records |

DFLT and SMPL match the pinned Veilid schemas, including zero owner slots,
zero-sized member entries, repeated writers and owner-as-member slots. Ordinary
`create` leaves every subkey empty. `create_epoch` opts into the application header.

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

**Epochs:** a schema never changes, so a new writer set (device removal) is a new record:
`rotate` creates it (new owner key and encryption key allowed), writes the predecessor
link into its header and the successor link into the old header; `latest` follows the
chain and stops before a successor the reader cannot decrypt — a removed device keeps
only the old epoch.

## Backends and network port

`NetworkBackend<N, V>` performs closest-node fanout over `Network`: five write
acknowledgments, three-copy read agreement, explicit partial read evidence,
validated conflict responses and owner rehydration of existing signed values.
`LocalBackend` is one independently bounded node store, with native/browser
capacity presets, LRU eviction, no record expiry and bounded public watch leases.

Mesh supplies actual transport and durable node storage. The current Mesh DHT
hook loses signatures/nonces and therefore needs revision before it can carry
these records. [NETWORK-PORT](docs/NETWORK-PORT.md) specifies the integration.
The future Veilid adapter must import and republish existing signed values;
calling a signing `set_dht_value` API alone is insufficient.

`cdht` contains no network implementation and never depends on `veilid-core` in
production. Its dedicated conformance CI job builds the pinned upstream as an
independent oracle. [CHURN](docs/CHURN.md) describes the simulated population
measurements; they are not live Tor measurements.

## Sync rules (`sync`)

No CRDT library. Per-device signed logs (each device writes its own subkeys), ordered by a
hybrid logical clock (monotonic despite wrong device clocks, bounded drift); each edit
names its base versions; concurrent versions are kept (**keep both**, the member
chooses; an edit based on all heads resolves it); tombstones are monotonic. Logs split
into subkey-sized segments and compact without changing the merged state.

## Crypto ports

`Signer` and `Verifier` are ports: `cdht` never holds a secret key. In the vault, `cvlt`
adapts `ckmg` (VLD0: Ed25519ph with context `VLD0_SIGN`); the tests use an ed25519-dalek
double with the same semantics. This also keeps `cdht` free of private dependencies, so
its CI runs on hosted runners.

## Boundaries

No policy (which records exist and who writes them is `cvlt`'s lineage rules), no secret
keys, no network code, no recovery.

## Open points / TODO

- Mesh/Tor and Veilid adapter integration (above).
- Group membership without a server (MLS commit arbitration) is a separate design topic
  (`cgrp`), not part of `cdht`.
- A removed device still holds the old owner key and could write a competing successor
  link into the old record; readers should prefer the chain the vault confirms (see
  `cvlt`). Open question recorded there.
- Per-subkey writes of log segments rewrite whole segments; incremental segment updates
  are an optimisation for later.

## License

Copyright 2026 Julian Y. Richard Corbet. Licensed under
[LGPL-3.0-only](LICENSES/LGPL-3.0-only.txt)
[WITH LGPL-3.0-linking-exception](LICENSES/LGPL-3.0-linking-exception.txt).
See [LICENSE.md](LICENSE.md).

## Continuous verification

Dependency updates follow main and are tested against one CI-resolved lockfile.
Line and branch coverage target 100%; failures remain blocking. See
[the coverage contract](docs/COVERAGE.md) for measurement and exclusions.

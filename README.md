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
| Schema | owner subkeys + writers with their own subkey ranges | SMPL schema, byte-identical compiled form |
| Descriptor | owner signs the compiled schema | `SignedValueDescriptor` |
| Record key | BLAKE3(`VLD0` ‖ owner ‖ schema), text `VLD0:<base64url>` | opaque record key, identical |
| Value | sequence number + data + writer + writer signature; higher seq wins | `SignedValueData` (semantics; see below) |
| Limits | 32 KiB per subkey, 1 MiB per record, 1024 subkeys, 256 writers | same constants |
| Encryption | optional per-record key, XChaCha20-Poly1305 bound to record and subkey | encrypted records |

`cdht` is slightly stricter than Veilid: owner subkey 0 always holds the record
**header** (epoch, predecessor, successor), writers are unique, differ from the owner and
own at least one subkey.

The value signature covers our own byte layout, not Veilid's Cap'n Proto blob. The Veilid
filling writes through `veilid-core`, which signs with the delegated writer key itself;
keys, schemas, subkeys and sequence numbers are identical, so switching fillings needs no
data migration.

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

## Fillings (`Backend` port)

- `LocalBackend`: in memory, complete; validates like a DHT node; clones share one
  network; can simulate going offline. For tests and debugging.
- Client DHT over Tor — **TODO**: provided through `cmsh`'s DHT capability (members'
  clients store encrypted records for each other; the operator stores nothing).
- Veilid DHT — **TODO**: provided through `cmsh`'s DHT capability, which reaches the one
  `veilid-core` in `cvln` (`create_dht_record` with SMPL + delegated owner key,
  `set_dht_value` with the delegated writer key, `watch_dht_values`).

`cdht` never reaches a network itself (no layer skipping).

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

- Remote fillings (above).
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

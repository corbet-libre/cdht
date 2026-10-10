# Records contract

Records is a device DHT library under Vault, used by offline Delivery. It follows
Veilid DFLT/SMPL, typed VLD0 keys, signed descriptors and values. It holds no Keys
secret and makes no network connection. `Signer`, `Verifier`, `RecordCipher`,
`Backend` and `Network` are injected capabilities.

## Custody and bytes

`queue_create` and `queue_set` run synchronously inside the authorized key-owner
callback. Persist `ClientState`, release the callback and call `flush` without a
signer. `get_signed` retrieves signed bytes; `open_value` checks them before the
scoped cipher opens them. The production path never exports the private root,
raw signing keys or record cipher keys. Independent `EncryptionKey` codecs serve
Veilid interoperability and are not a Keys export API.

`queue_original` stages an already signed descriptor/value pair through original
validation without a signer, cipher or network call. Original raw ValueData,
ciphertext, nonce and signatures remain unchanged. The enclosing Vault still
authorizes this exact publication; a valid record signature is not current
member authority. Cached observations and outstanding same-slot obligations
both fence the generation. Equal-sequence differences, including another valid
signature or fresh encryption of the same plaintext, refuse without changing
the original state. No nonidentical signed value can supersede an outstanding
same-slot obligation, even at a higher generation; the original obligation must
first be reconciled. Existing descriptor bytes must also match exactly.

Persist the original `ClientState` through the authenticated owner transaction
before `flush`; staging alone is never durable success. Reopening revalidates
signed state while preserving the original queued obligation separately from
newer cached observations. The enclosing owner must match its exact retained
obligation against that restored queue. Repeated identical staging preserves
the entire queued snapshot and ordering. Unknown network completion keeps the original
bytes for reconciliation/retransmission, never new signing or encryption.
Written owner scenarios cover original RPC bytes through queue, serde, reopen,
offline flush, lost reply, cancellation, independent cached/queued conflicts and
malformed inputs. They have not executed in this tranche. This staging API does
not supply the unavailable native Veilid exact-import bridge or establish Tor,
native/browser, distribution or complete creation/recovery readiness.

`observe_original` records only a validated original signed observation and its
sequence floor, preserving every pending publication unchanged. Invalid or older
values refuse before mutation; equal-sequence conflicts remain independent cache
observations. It performs no network call and cannot attest freshness, agreement
or member authority. Owners using explicit network read reports must retain and
check that original evidence separately; `Backend::get` may return a partial
signed result and does not imply the original three-holder read target.

Transport preserves original descriptor/value blobs, signatures, sequence numbers
and nonces. An unchanged encrypted value retains its original ciphertext. The
RPC codec uses unchanged upstream generated Cap'n Proto types and the original
Operation bytes covered by the upstream signature. Mesh may carry these as opaque
messages. A message-format vector alone is not a live Tor DHT result.

## Record lifecycle

A schema fixes the owner and each writer's subkey range. Creation reserves no
application header. All input, persisted state and backend responses are validated.
Offline writes remain signed in the local queue; flushing reports conflicts and
remaining work. The owner rehydrates existing signed values on open. Watch events
are hints to fetch and validate values, not authoritative contents.

Device stores are capacity bounded: native 128 records/256 MiB and browser
64 records/128 MiB for others' data, LRU eviction, no record expiry. The operator
stores no DHT records. The device retains its own local copy. Reads lacking the
required evidence stay unavailable; they cannot erase local state or initialize
an apparently empty restored vault.

Application sync, epoch chains, clocks, keep-both and tombstones belong to each
data-owning library. That library compresses and pads before Records encrypts.
Changing a writer set requires a new schema/record; its application references
and authorization belong to the owner, not a generic Records protocol.

## Evidence and incomplete ports

[CONFORMANCE](CONFORMANCE.md) records D1–D10 against upstream. Independent native
and Wasm fixtures plus the actual upstream encode oracle test formats. Network
contracts exercise independent capacity-bounded node stores. Production Tor node
discovery, record RPC runtime, durable peer store, upstream watch/inspect routing
and native Veilid import remain incomplete. Reviewed bootstrap nodes may discover
peers, but are community-independent and store no records.

[CHURN](CHURN.md) contains failed active-member restore evidence. No arbitrary
replication/quorum/expiry/retention change may cover that failure. Full acceptance
requires real Tor create/get/set/watch/offline queue/owner rehydration with
independent participants, no operator store or direct peer sockets; separate native
Veilid rehydration; and measured active-device-loss recovery. Expensive churn/load
runs belong on Crow. Private Tor/browser and public transport evidence stay distinct.


The equal-passkey restore boundary belongs to Keys/Vault: a random common root,
separate PRF-wrapped copies in member DHT records, no privileged first passkey or
operator copy. Losing every device copy and all recoverable DHT copies loses
identity and data. Records cannot infer irreversible loss from a network outage,
or construct a replacement identity. The active-device-loss restore requirement
still needs measured end-to-end owner integration.

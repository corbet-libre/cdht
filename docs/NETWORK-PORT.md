# Mesh adapter contract

`cdht::Network` is the network boundary. `NetworkBackend<N, V>` owns record
fanout; `Dht` owns the local signed cache and pending writes. Neither opens a
socket. Mesh supplies peer discovery, authenticated node RPCs, deadlines, clock
and connection lifecycle over Tor; a future Veilid adapter supplies the same
capability from its one Veilid instance.

The historical high-level Mesh DHT interface cannot fill this port. Its `DhtKeyPair` accepts private signing keys and its `DhtValue`
contains only sequence, writer and payload. It drops the nonce and signature;
its `set(data, writer)` assigns/signs a new value. Wrapping that API cannot
preserve a signed record byte for byte. No compatibility shim is provided.

Vault/sync owners should pack data into as few records as possible: compress
and Padmé-pad through cprz, then encrypt with VLD0. cdht treats those padded bytes
as opaque and adds no compression format or padding rule of its own. The node
count limit still applies independently of compressed byte size.

## What crosses the port

- A `RecordKey` is the public `VLD0:<base64url>` locator. A full read capability
  also carries the encryption secret; it must never reach storage peers.
- A `Descriptor` contains owner public key, compiled DFLT/SMPL schema and owner
  signature. Check both its signature and its derived locator on arrival.
- A `SignedValue` contains sequence, writer public key, ciphertext, optional
  24-byte nonce and signature. `raw_blob()` exports the exact unpacked Veilid
  ValueData bytes. `from_blob` preserves received bytes; `validate` authenticates
  them against the descriptor and subkey before they enter any store.
- An adapter MUST NOT assign a sequence, re-encrypt, re-sign, drop a signature,
  substitute an AEAD wrapper, or synthesize an acknowledgment. A full-record
  JSON snapshot is a local persistence format, not a Veilid RPC envelope.

`closest` supplies independently authenticated node coordinates from network
routing. The engine deduplicates, sorts by XOR distance and bounds the candidate
set. `set` acts on one named node, returning `Accepted` only after that node has
retained the validated value. Five distinct acknowledgments complete a write.
Fewer leave it pending, even if some nodes accepted it. Returning the existing
signed value on a stale/equal-conflicting write restarts convergence with that
value. No new sequence is invented to settle a conflict.

Reads seek three identical values. Exhaustion can return fewer, as upstream
does; `ReadReport::has_consensus()` is the explicit distinction. `None` means no
value was found in the responding record stores, never proven global absence.
Failure to reach any valid responder is `Unavailable`. Signed old values are
not proof of freshness; the local cache retains a higher sequence.

## Storage and lifecycle

Each node has its own store. Clone a `LocalBackend` only when referring to the
same node; construct a new one for every simulated node. The native default is
128 remote records / 256 MiB, browser 64 / 128 MiB. Own cached records live in
`ClientState`, outside remote LRU eviction. Peers learn no read secret.

A production adapter persists its remote store and the caller persists
`ClientState` through protected storage. Validate restored descriptors and
values. Whole-store rollback requires a freshness floor held outside that
snapshot. Record loss is observable; there is no operator recovery copy or TTL.

Open inspects replication and republishes cached signed values when needed.
At least one node must answer that inspection; silence alone never triggers a
repair. A reachable node without the requested record/subkey returns `Ok(None)`
from `Network::get`, while an unreachable node returns `Unavailable`.
Failed rehydration checks are retried on the next open, without manufacturing
new pending writes. Explicitly queued writes retain their independent retry duty.
Drive `flush()` when connectivity returns and during network maintenance.
The engine is executor independent and has no autonomous timer thread.

The adapter must drive the node's monotonic watch clock, keep live leases renewed,
and return an error for a lost lease/node. Notifications are hints: read and
validate changed subkeys. A client must refresh after a watch gap. Public local
watches coalesce changes by subkey, cap each record at 32 watches and each lease
at ten minutes. The fuller upstream watch reconciliation/identity facilities
are listed as open deviations in [CONFORMANCE](CONFORMANCE.md).

## Adoption gate

Implement the port in Mesh/Tor and test two actual devices, including offline
flush, watch loss/recovery and restart. For Veilid, prove importing existing
signed local records and invoking upstream owner rehydration; the public
`set_dht_value` alone is not a byte-preserving import API. The byte oracle proves
format compatibility, not a completed runtime adapter or public-network retention.

## Scoped signing and durable local staging

`Dht::queue_create` and `queue_set` are synchronous. A higher adapter can invoke
them inside `ckmg::Keys::with_vld0_signer` without exporting key material or
blocking a browser executor. They create only signed local state. Persist
`ClientState` through the vault's protected transaction before driving `flush`.
`flush` requires no signer and forwards the exact queued descriptor, original
ValueData blob, signature and nonce; it cannot mint replacement signatures.
A queued sequence is never an acknowledgement. Existing async convenience APIs
remain for callers whose signer custody allows them; scoped Keys callers use
the synchronous staging port.

## Upstream record answers

`rpc::Answer` encodes the original GetValueA/SetValueA/WatchValueA schema and echoes the
authenticated request ID. `Question::answer` accepts only the matching ID and
operation kind and validates returned record signatures against the requested
locator/subkey and owner-signed descriptor. Authenticate the answer's
`SignedOperation` against the expected node identity before calling it.

PeerInfo hints retain their original NodeInfo message and signature bytes as
`UnverifiedPeerInfoBytes`; they do not establish an authenticated node coordinate
or onion endpoint. The routing owner must apply upstream PeerInfo validation.
WatchValueQ preserves upstream ranges, duration in microseconds, remaining count
and the node-scoped lease identifier. Accepted WatchValueA responses retain the requested nonzero lease identifier;
an active accepted lease cannot return identifier zero. These are the upstream
rpc_call_watch_value checks. A response is not proof of notification delivery or
automatic renewal. The request signer is the upstream watcher capability (a
schema member or runtime anonymous watcher), distinct from transport node identity;
the eventual handler must not grant member quotas from an unverified key claim. The actual watch transport and owner lease scheduler remain unfinished.
This codec adds no discovery format, handler acknowledgment or storage adapter. The public byte boundary is not real Tor DHT restore evidence.


`RecordCipher` supplies the matching scoped encryption boundary. `queue_set`
accepts the capability synchronously and generates a fresh 24-byte nonce for a
new value. Fetch with `get_signed`, then call synchronous `open_value` inside
`Keys::with_vld0_record_cipher`; it validates descriptor, writer, subkey and the
original signature before invoking the cipher. A closure adapter can map the
owner's coarse errors without copying its secret or retaining its capability.
The standalone `EncryptionKey` codec is for independent Veilid interoperability;
production device paths must not export a Keys secret to construct it.

`rpc::Statement::value_changed` and `rpc::value_changed` preserve upstream
ValueChanged bytes, including an optional original signed value. Shape decoding
never authorizes a local watch: match record, authenticated storage node, watch ID
and requested ranges first. Follow upstream inspection for multi-subkey hints;
do not treat an included value as a transaction commit or delivery receipt.

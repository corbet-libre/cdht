// SPDX-License-Identifier: MPL-2.0
// Portions of Veilid, Copyright Veilid contributors.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. https://mozilla.org/MPL/2.0/
// Port of dd8e2cdd72b5bf817172ac31c20872b168c5c8fc storage_manager/
// record_store/{inbound_watch.rs,record_store_inner/inbound_watches_interface.rs,
// record_store_inner/inbound_watches/{inbound_watch,inbound_watch_id_allocator}.rs}.
//! Authenticated inbound watch state. Routing owns the original authenticated
//! node target and actual clock; record storage owns eviction and value changes.
use crate::{
    Descriptor, Error, NodeId, RecordKey, Schema, Verifier,
    crypto::PublicKey,
    rpc::{ChangeHint, Query, SubkeyRanges, envelope::AuthenticatedOperation, query},
};
use std::{collections::BTreeMap, num::NonZeroUsize};

/// Original configurable upstream watch limits and a caller-selected memory bound.
#[derive(Clone, Copy)]
pub struct WatchLimits {
    /// Original RPC timeout, in microseconds: minimum accepted watch lifetime.
    pub min_duration_us: u64,
    /// Original configured maximum watch lifetime, in microseconds.
    pub max_duration_us: u64,
    /// Original maximum simultaneous watches per schema member per record.
    pub member_per_record: NonZeroUsize,
    /// Original maximum anonymous watches per record, across anonymous signers.
    pub public_per_record: NonZeroUsize,
    /// Maximum active watches retained by this bounded storage process.
    pub capacity: NonZeroUsize,
}
impl WatchLimits {
    /// Maintained defaults: eight per member, 32 anonymous, ten-minute maximum.
    /// The caller supplies its actual configured RPC timeout and memory bound.
    pub fn native(rpc_timeout_us: u64, capacity: NonZeroUsize) -> Self {
        Self {
            min_duration_us: rpc_timeout_us,
            max_duration_us: 600_000_000,
            member_per_record: NonZeroUsize::new(8).unwrap(),
            public_per_record: NonZeroUsize::new(32).unwrap(),
            capacity,
        }
    }
}
struct Watch {
    key: RecordKey,
    watcher: PublicKey,
    target: NodeId,
    subkeys: SubkeyRanges,
    changed: SubkeyRanges,
    expiration: u64,
    count: u32,
}
/// Storage decision used to construct the original WatchValueA, never an ACK.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WatchLease {
    /// Existing or newly allocated original nonzero ID; zero if new watch rejected.
    pub id: u64,
    /// Remaining duration; zero means cancelled/rejected, as in upstream.
    pub duration_us: u64,
}
/// A change to send to its authenticated node using original ValueChanged bytes.
pub struct WatchNotification {
    /// Original authenticated notification target, never the watcher signing key.
    pub target: NodeId,
    /// Original key/ranges/count/watch ID; storage may attach a validated value.
    pub hint: ChangeHint,
}
/// Bounded node-local watch table. No arbitrary endpoint, key membership assertion
/// or synthetic clock is accepted from the RPC payload. No secret keys are stored.
pub struct InboundWatches {
    watches: BTreeMap<u64, Watch>,
    limits: WatchLimits,
    last_time: u64,
}
impl InboundWatches {
    /// Construct an empty table with the actual runtime's configured limits.
    pub fn new(limits: WatchLimits) -> Result<Self, Error> {
        if limits.min_duration_us == 0
            || limits.max_duration_us < limits.min_duration_us.saturating_mul(2)
        {
            return Err(Error::Encoding);
        }
        Ok(Self {
            watches: BTreeMap::new(),
            limits,
            last_time: 0,
        })
    }
    /// Expire leases using actual nondecreasing runtime time, never record TTL.
    pub fn advance(&mut self, now_us: u64) -> Result<(), Error> {
        if now_us < self.last_time {
            return Err(Error::Unavailable);
        }
        self.last_time = now_us;
        self.watches.retain(|_, watch| {
            watch.count != 0 && watch.expiration > now_us && !watch.subkeys.is_empty()
        });
        Ok(())
    }
    /// Process an original authenticated WatchValueQ for this stored descriptor.
    /// Member status comes only from the owner-signed schema, independently of
    /// ENV0's node signer. Routing must already validate the sender's dial info.
    pub fn apply(
        &mut self,
        request: &AuthenticatedOperation,
        descriptor: &Descriptor,
        now_us: u64,
        verifier: &impl Verifier,
    ) -> Result<WatchLease, Error> {
        self.advance(now_us)?;
        let (
            _,
            Query::Watch {
                key,
                subkeys,
                duration_us,
                count,
                watch_id,
            },
        ) = query(request.operation())?
        else {
            return Err(Error::Encoding);
        };
        let schema = descriptor.validate_for(&key, verifier)?;
        // This binds the target to the authenticated outer node, while the inner
        // signature supplies the independent original watcher/member identity.
        let sender = request.sender_peer(verifier)?;
        let watcher = *request.operation().signer();
        let target = *sender.node_id();
        let rejected = WatchLease {
            id: watch_id,
            duration_us: 0,
        };
        if watch_id != 0 {
            let Some(previous) = self.watches.get(&watch_id) else {
                return Ok(rejected);
            };
            // Cancellation keeps the same authenticated owner check as renewal.
            // Upstream's inner cancel helper only checks record+ID; this RPC
            // boundary additionally prevents another signer using a leaked ID.
            if previous.key != key || previous.watcher != watcher {
                return Ok(rejected);
            }
        }
        if count == 0 || (duration_us != 0 && duration_us < self.limits.min_duration_us) {
            if watch_id != 0 {
                self.watches.remove(&watch_id);
            }
            return Ok(rejected);
        }
        let duration_us = if duration_us == 0 {
            self.limits.max_duration_us
        } else {
            duration_us.min(self.limits.max_duration_us)
        };
        let expiration = now_us.checked_add(duration_us).ok_or(Error::Encoding)?;
        if watch_id != 0 {
            let previous = self.watches.get_mut(&watch_id).ok_or(Error::UnknownWatch)?;
            previous.target = target;
            previous.subkeys = subkeys;
            previous.expiration = expiration;
            previous.count = count;
            // Original pending ranges survive parameter updates.
            return Ok(WatchLease {
                id: watch_id,
                duration_us,
            });
        }
        let member = is_member(&schema, &descriptor.owner, &watcher);
        let matching = self.watches.values().filter(|w| w.key == key).filter(|w| {
            if member {
                w.watcher == watcher
            } else {
                !is_member(&schema, &descriptor.owner, &w.watcher)
            }
        });
        let mut total = 0;
        for previous in matching {
            total += 1;
            if previous.target == target {
                return Ok(rejected);
            }
        }
        let limit = if member {
            self.limits.member_per_record
        } else {
            self.limits.public_per_record
        };
        if total >= limit.get() || self.watches.len() >= self.limits.capacity.get() {
            return Ok(rejected);
        }
        let id = self.allocate_id()?;
        self.watches.insert(
            id,
            Watch {
                key,
                watcher,
                target,
                subkeys,
                expiration,
                count,
                changed: SubkeyRanges::new(),
            },
        );
        Ok(WatchLease { id, duration_us })
    }
    fn allocate_id(&self) -> Result<u64, Error> {
        let mut bytes = [0; 8];
        let mut id = 0;
        while id == 0 {
            getrandom::fill(&mut bytes).map_err(|_| Error::Randomness)?;
            id = u64::from_ne_bytes(bytes);
        }
        let first = id;
        while self.watches.contains_key(&id) {
            let (next, wrapped) = id.overflowing_add(1);
            id = next + u64::from(wrapped);
            if id == first {
                return Err(Error::Unavailable);
            }
        }
        Ok(id)
    }
    /// Accumulate actual committed changes. A transaction overlapping the watched
    /// range contributes all its changed subkeys, matching upstream semantics.
    /// Suppress the originating node target when it already knows its own write.
    pub fn changed(&mut self, key: &RecordKey, subkeys: &SubkeyRanges, exclude: Option<&NodeId>) {
        for watch in self.watches.values_mut().filter(|watch| &watch.key == key) {
            if Some(&watch.target) != exclude && !watch.subkeys.is_disjoint(subkeys) {
                watch.changed |= subkeys;
            }
        }
    }
    /// Take coalesced original notifications. Count decrements once per emitted
    /// notification, not once per subkey or write. Expired watches emit no receipt.
    pub fn take_changes(&mut self, now_us: u64) -> Result<Vec<WatchNotification>, Error> {
        self.advance(now_us)?;
        let mut out = Vec::new();
        for (id, watch) in &mut self.watches {
            if watch.changed.is_empty() {
                continue;
            }
            watch.count = watch.count.saturating_sub(1);
            out.push(WatchNotification {
                target: watch.target,
                hint: ChangeHint {
                    key: watch.key,
                    subkeys: std::mem::take(&mut watch.changed),
                    count: watch.count,
                    watch_id: *id,
                    value: None,
                },
            });
        }
        self.watches.retain(|_, watch| watch.count != 0);
        Ok(out)
    }
    /// Eviction removes the record's watches; it never claims remote deletion.
    pub fn remove_record(&mut self, key: &RecordKey) {
        self.watches.retain(|_, watch| &watch.key != key);
    }
}
fn is_member(schema: &Schema, owner: &PublicKey, watcher: &PublicKey) -> bool {
    owner == watcher
        || schema
            .members()
            .iter()
            .any(|member| &member.writer == watcher)
}

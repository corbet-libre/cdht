//! Sync rules for the member's private state across their own devices.
//!
//! No CRDT library (decided 2026-09-25). Instead, the VeilidChat approach:
//!
//! 1. Every device appends to its **own signed log** (its own subkeys of the member's
//!    state record), entries ordered by a **hybrid logical clock** ([`Clock`]), which stays
//!    monotonic even when device clocks are wrong. Total order: (time, author, id).
//! 2. Every edit names the versions it was based on ([`Entry::base`]). An entry named in
//!    another entry's base is superseded. One remaining version is the value; several
//!    concurrent versions are a conflict: **keep both** and let the member choose
//!    ([`ItemState::Conflict`]); an edit based on all of them resolves it. Nothing is
//!    merged and nothing is lost.
//! 3. **Tombstones are monotonic**: once any device deletes an item, it stays deleted;
//!    concurrent edits do not resurrect it. Re-creating means a new item id.
//!
//! This module is pure: no I/O, no keys. Logs are stored in record subkeys with
//! [`encode_segments`] / [`decode_segments`]; the record's writer check already proves
//! which device wrote each segment.

use crate::Error;
use crate::crypto::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Hybrid logical clock time: wall-clock milliseconds plus a logical counter.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Timestamp {
    /// Milliseconds since the Unix epoch (as far as the clock knows).
    pub wall: u64,
    /// Logical counter within the same `wall`.
    pub counter: u32,
}

/// A hybrid logical clock. Local events [`tick`](Clock::tick); timestamps seen from other
/// devices are [`observe`](Clock::observe)d, so later local events order after them.
#[derive(Clone, Debug)]
pub struct Clock {
    last: Timestamp,
    max_drift_ms: u64,
}

impl Clock {
    /// A clock that rejects remote times more than `max_drift_ms` ahead of local time.
    pub fn new(max_drift_ms: u64) -> Self {
        Self::resume(Timestamp::default(), max_drift_ms)
    }

    /// A clock continuing after `last` (persisted by the caller).
    pub fn resume(last: Timestamp, max_drift_ms: u64) -> Self {
        Self { last, max_drift_ms }
    }

    /// The latest time issued or observed.
    pub fn last(&self) -> Timestamp {
        self.last
    }

    /// A new timestamp for a local event, strictly after every earlier one.
    pub fn tick(&mut self, now_ms: u64) -> Result<Timestamp, Error> {
        let next = if now_ms > self.last.wall {
            Timestamp {
                wall: now_ms,
                counter: 0,
            }
        } else {
            Timestamp {
                wall: self.last.wall,
                counter: self
                    .last
                    .counter
                    .checked_add(1)
                    .ok_or(Error::ClockOverflow)?,
            }
        };
        self.last = next;
        Ok(next)
    }

    /// Take a remote timestamp into account. Fails for times implausibly far ahead of
    /// `now_ms` (a wrong or hostile clock must not drag ours into the future).
    pub fn observe(&mut self, remote: Timestamp, now_ms: u64) -> Result<(), Error> {
        if remote.wall > now_ms.saturating_add(self.max_drift_ms) {
            return Err(Error::ClockDrift);
        }
        if remote > self.last {
            self.last = remote;
        }
        Ok(())
    }
}

/// A version identifier: time, author, random id. Totally ordered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Stamp {
    /// When.
    pub time: Timestamp,
    /// Who (the writing device's key).
    #[serde(with = "crate::b64")]
    pub author: PublicKey,
    /// Random tiebreaker.
    #[serde(with = "crate::b64")]
    pub id: [u8; 16],
}

/// What an entry does to an item.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "op")]
pub enum Op {
    /// Set the item's value.
    Put {
        /// The new value.
        #[serde(with = "crate::b64")]
        value: Vec<u8>,
    },
    /// Delete the item for good.
    Delete,
}

/// One log entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Entry {
    /// This version.
    pub stamp: Stamp,
    /// The item (contact, block, setting, message, ...).
    pub item: String,
    /// The versions this edit was based on (the item's heads when it was made).
    pub base: Vec<Stamp>,
    /// The change.
    pub op: Op,
}

/// The current state of an item after merging all logs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ItemState {
    /// One current version.
    Value {
        /// Its stamp (use as the base of the next edit).
        stamp: Stamp,
        /// Its value.
        value: Vec<u8>,
    },
    /// Concurrent versions, oldest first: keep both, the member chooses.
    Conflict(Vec<(Stamp, Vec<u8>)>),
    /// Deleted (monotonic).
    Deleted {
        /// The earliest tombstone.
        stamp: Stamp,
    },
}

impl ItemState {
    /// The stamps an edit of this item must name as its base.
    pub fn heads(&self) -> Vec<Stamp> {
        match self {
            ItemState::Value { stamp, .. } => vec![*stamp],
            ItemState::Conflict(versions) => versions.iter().map(|(stamp, _)| *stamp).collect(),
            ItemState::Deleted { stamp } => vec![*stamp],
        }
    }
}

/// One device's log. Its entries are strictly increasing in time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceLog {
    /// The writing device.
    #[serde(with = "crate::b64")]
    pub author: PublicKey,
    /// Entries, oldest first.
    pub entries: Vec<Entry>,
}

/// Maximum item id length in bytes.
pub const MAX_ITEM_BYTES: usize = 256;

impl DeviceLog {
    /// An empty log for `author`.
    pub fn new(author: PublicKey) -> Self {
        Self {
            author,
            entries: Vec::new(),
        }
    }

    /// Append an entry stamped by `clock` at `now_ms`.
    pub fn append(
        &mut self,
        clock: &mut Clock,
        now_ms: u64,
        item: &str,
        base: Vec<Stamp>,
        op: Op,
    ) -> Result<Stamp, Error> {
        if item.is_empty() || item.len() > MAX_ITEM_BYTES {
            return Err(Error::Encoding);
        }
        if let Some(last) = self.entries.last() {
            clock.observe(last.stamp.time, now_ms.max(last.stamp.time.wall))?;
        }
        let mut id = [0u8; 16];
        getrandom::fill(&mut id).map_err(|_| Error::Randomness)?;
        let stamp = Stamp {
            time: clock.tick(now_ms)?,
            author: self.author,
            id,
        };
        self.entries.push(Entry {
            stamp,
            item: item.to_owned(),
            base,
            op,
        });
        Ok(stamp)
    }

    /// Check authorship and strictly increasing times.
    pub fn validate(&self) -> Result<(), Error> {
        let mut previous: Option<Timestamp> = None;
        for entry in &self.entries {
            if entry.stamp.author != self.author
                || entry.item.is_empty()
                || entry.item.len() > MAX_ITEM_BYTES
                || previous.is_some_and(|p| entry.stamp.time <= p)
            {
                return Err(Error::InvalidLog);
            }
            previous = Some(entry.stamp.time);
        }
        Ok(())
    }

    /// Drop this device's entries that no longer matter given all logs (this one
    /// included): superseded puts and puts of deleted items. Tombstones stay.
    pub fn compact(&self, all: &[DeviceLog]) -> DeviceLog {
        let superseded: BTreeSet<Stamp> = all
            .iter()
            .flat_map(|log| log.entries.iter())
            .flat_map(|entry| entry.base.iter().copied())
            .collect();
        let deleted: BTreeSet<&str> = all
            .iter()
            .flat_map(|log| log.entries.iter())
            .filter(|entry| entry.op == Op::Delete)
            .map(|entry| entry.item.as_str())
            .collect();
        DeviceLog {
            author: self.author,
            entries: self
                .entries
                .iter()
                .filter(|entry| match entry.op {
                    Op::Delete => true,
                    Op::Put { .. } => {
                        !superseded.contains(&entry.stamp) && !deleted.contains(entry.item.as_str())
                    }
                })
                .cloned()
                .collect(),
        }
    }
}

/// Merge all devices' logs into the current state of every item.
pub fn merge(logs: &[DeviceLog]) -> Result<BTreeMap<String, ItemState>, Error> {
    let mut authors = BTreeSet::new();
    for log in logs {
        log.validate()?;
        if !authors.insert(log.author) {
            return Err(Error::InvalidLog);
        }
    }
    let entries: Vec<&Entry> = logs.iter().flat_map(|log| log.entries.iter()).collect();
    let superseded: BTreeSet<Stamp> = entries
        .iter()
        .flat_map(|entry| entry.base.iter().copied())
        .collect();
    let mut by_item: BTreeMap<&str, Vec<&Entry>> = BTreeMap::new();
    for &entry in &entries {
        by_item.entry(entry.item.as_str()).or_default().push(entry);
    }
    let mut state = BTreeMap::new();
    for (item, mut versions) in by_item {
        versions.sort_by_key(|entry| entry.stamp);
        let item_state =
            if let Some(tombstone) = versions.iter().find(|entry| entry.op == Op::Delete) {
                ItemState::Deleted {
                    stamp: tombstone.stamp,
                }
            } else {
                let mut heads: Vec<(Stamp, Vec<u8>)> = versions
                    .iter()
                    .filter(|entry| !superseded.contains(&entry.stamp))
                    .filter_map(|entry| match &entry.op {
                        Op::Put { value } => Some((entry.stamp, value.clone())),
                        Op::Delete => None,
                    })
                    .collect();
                match heads.len() {
                    // Every version superseded by an entry for another item cannot happen with
                    // honest clients; treat the newest as current.
                    0 => match versions.last().map(|entry| &entry.op) {
                        Some(Op::Put { value }) => ItemState::Value {
                            stamp: versions[versions.len() - 1].stamp,
                            value: value.clone(),
                        },
                        _ => continue,
                    },
                    1 => {
                        let (stamp, value) = heads.remove(0);
                        ItemState::Value { stamp, value }
                    }
                    _ => ItemState::Conflict(heads),
                }
            };
        state.insert(item.to_owned(), item_state);
    }
    Ok(state)
}

/// Split a log into segments of at most `max_segment_len` bytes, one per subkey of the
/// device's range, at most `max_segments`. [`Error::LogFull`] means: compact first.
pub fn encode_segments(
    log: &DeviceLog,
    max_segment_len: usize,
    max_segments: usize,
) -> Result<Vec<Vec<u8>>, Error> {
    let mut segments = Vec::new();
    let mut current: Vec<Entry> = Vec::new();
    let encode = |entries: &[Entry]| {
        serde_json::to_vec(&DeviceLog {
            author: log.author,
            entries: entries.to_vec(),
        })
        .map_err(|_| Error::Encoding)
    };
    for entry in &log.entries {
        current.push(entry.clone());
        if encode(&current)?.len() > max_segment_len {
            let overflow = current.pop().ok_or(Error::Encoding)?;
            if current.is_empty() {
                return Err(Error::ValueTooLarge);
            }
            segments.push(encode(&current)?);
            current = vec![overflow];
            if encode(&current)?.len() > max_segment_len {
                return Err(Error::ValueTooLarge);
            }
        }
    }
    if !current.is_empty() || segments.is_empty() {
        segments.push(encode(&current)?);
    }
    if segments.len() > max_segments {
        return Err(Error::LogFull);
    }
    Ok(segments)
}

/// Reassemble a log from its segments (in subkey order; `None` for unwritten subkeys)
/// and check that it is `author`'s.
pub fn decode_segments(
    author: &PublicKey,
    segments: &[Option<Vec<u8>>],
) -> Result<DeviceLog, Error> {
    let mut log = DeviceLog::new(*author);
    for segment in segments.iter().flatten() {
        let part: DeviceLog = serde_json::from_slice(segment).map_err(|_| Error::Encoding)?;
        if part.author != *author {
            return Err(Error::InvalidLog);
        }
        log.entries.extend(part.entries);
    }
    log.validate()?;
    Ok(log)
}

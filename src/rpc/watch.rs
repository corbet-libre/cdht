// SPDX-License-Identifier: MPL-2.0
// Portions of Veilid, Copyright Veilid contributors.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. https://mozilla.org/MPL/2.0/
// Upstream dd8e2cdd72b5bf817172ac31c20872b168c5c8fc:
// rpc_processor/coders/operations/operation_watch_value.rs.
//! Original upstream watch fields. Lease policy belongs to the storage owner.
use super::*;
/// Maintained inclusive range collection used by upstream ValueSubkeyRangeSet.
/// This is the same range-set implementation, not a second range algorithm.
pub type SubkeyRanges = range_set_blaze::RangeSetBlaze<u32>;
pub(super) const MAX_RANGES: usize = 512;
pub(super) fn encode(
    key: &crate::RecordKey,
    subkeys: &SubkeyRanges,
    duration_us: u64,
    count: u32,
    watch_id: u64,
    mut builder: wire::operation_watch_value_q::Builder<'_>,
) -> Result<(), Error> {
    if subkeys.ranges_len() > MAX_RANGES || (count == 0 && watch_id == 0) {
        return Err(Error::Encoding);
    }
    key_encode(key, builder.reborrow().init_key());
    ranges_encode(
        subkeys,
        builder.reborrow().init_subkeys(subkeys.ranges_len() as u32),
    );
    builder.set_duration(duration_us);
    builder.set_count(count);
    builder.set_watch_id(watch_id);
    Ok(())
}
pub(super) fn decode(reader: wire::operation_watch_value_q::Reader<'_>) -> Result<Query, Error> {
    if !reader.has_key() || !reader.has_subkeys() {
        return Err(Error::Encoding);
    }
    let key = key_decode(reader.get_key().map_err(|_| Error::Encoding)?)?;
    let subkeys = ranges_decode(reader.get_subkeys().map_err(|_| Error::Encoding)?)?;
    let count = reader.get_count();
    let watch_id = reader.get_watch_id();
    if count == 0 && watch_id == 0 {
        return Err(Error::Encoding);
    }
    Ok(Query::Watch {
        key,
        subkeys,
        duration_us: reader.get_duration(),
        count,
        watch_id,
    })
}

pub(super) fn ranges_encode(
    subkeys: &SubkeyRanges,
    mut ranges: capnp::struct_list::Builder<'_, wire::subkey_range::Owned>,
) {
    for (index, range) in subkeys.ranges().enumerate() {
        let mut entry = ranges.reborrow().get(index as u32);
        entry.set_start(*range.start());
        entry.set_end(*range.end());
    }
}
pub(super) fn ranges_decode(
    ranges: capnp::struct_list::Reader<'_, wire::subkey_range::Owned>,
) -> Result<SubkeyRanges, Error> {
    if ranges.len() as usize > MAX_RANGES {
        return Err(Error::Encoding);
    }
    let mut subkeys = SubkeyRanges::new();
    for range in ranges {
        let (start, end) = (range.get_start(), range.get_end());
        if start > end || subkeys.last().is_some_and(|last| last >= start) {
            return Err(Error::Encoding);
        }
        subkeys.ranges_insert(start..=end);
    }
    Ok(subkeys)
}

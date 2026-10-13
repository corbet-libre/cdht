// SPDX-License-Identifier: MPL-2.0
// Portions of Veilid, Copyright Veilid contributors.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. https://mozilla.org/MPL/2.0/
// Upstream dd8e2cdd72b5bf817172ac31c20872b168c5c8fc:
// rpc_processor/coders/operations/operation_value_changed.rs.
//! Original change hints. Decoding does not authorize a local watch update.
use super::*;
/// Original ValueChanged fields, not a delivery receipt or a freshness proof.
/// The watch owner must match record, node, watch ID and requested ranges before
/// reporting; validate any included value against the owner-signed descriptor.
/// Upstream schedules inspection for multi-subkey hints rather than committing
/// their optional value directly. This codec deliberately retains original bytes.
pub struct ChangeHint {
    /// Public record locator.
    pub key: crate::RecordKey,
    /// Reported changed subkey ranges; empty may signal remote cancellation.
    pub subkeys: SubkeyRanges,
    /// Remaining notifications at the remote watch.
    pub count: u32,
    /// Nonzero, node-scoped watch identifier.
    pub watch_id: u64,
    /// Original signed value for the first reported subkey, still requiring validation.
    pub value: Option<Box<SignedValue>>,
}
impl ChangeHint {
    fn check(&self) -> Result<(), Error> {
        if self.subkeys.ranges_len() > watch::MAX_RANGES
            || self.watch_id == 0
            || (self.subkeys.is_empty() && self.value.is_some())
        {
            return Err(Error::Encoding);
        }
        Ok(())
    }
}
/// Original upstream Operation containing one ValueChanged statement.
pub struct Statement(pub(super) Vec<u8>);
impl Statement {
    /// Encode a bounded change hint with a random operation identifier.
    pub fn value_changed(hint: &ChangeHint) -> Result<Self, Error> {
        Self::encode(hint, random_id()?)
    }
    pub(super) fn encode(hint: &ChangeHint, id: u64) -> Result<Self, Error> {
        hint.check()?;
        let mut message = Builder::new_default();
        let mut operation = message.init_root::<wire::operation::Builder>();
        operation.set_op_id(id);
        let mut statement = operation
            .get_kind()
            .init_statement()
            .get_detail()
            .init_value_changed();
        key_encode(&hint.key, statement.reborrow().init_key());
        watch::ranges_encode(
            &hint.subkeys,
            statement
                .reborrow()
                .init_subkeys(hint.subkeys.ranges_len() as u32),
        );
        statement.set_count(hint.count);
        statement.set_watch_id(hint.watch_id);
        if let Some(value) = &hint.value {
            value_encode(value, statement.init_value())?;
        }
        Ok(Self(bytes(message)?))
    }
    /// Original Operation bytes; no record or nonce is reconstructed in transit.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// Bind original bytes to the destination inside the signing owner's callback.
    pub fn sign(
        &self,
        destination: &PublicKey,
        signer: &impl Signer,
    ) -> Result<SignedOperation, Error> {
        SignedOperation::sign(self.0.clone(), destination, signer)
    }
}
/// Decode an authenticated node statement, preserving its original signed value.
/// This checks wire shape, not active lease authority. Never dispatch a hint by
/// watch ID alone; the watch owner must also authenticate the node and record.
pub fn value_changed(operation: &SignedOperation) -> Result<(u64, ChangeHint), Error> {
    let message = read(operation.operation())?;
    let root = message
        .get_root::<wire::operation::Reader>()
        .expect("operation root checked at construction");
    let wire::operation::kind::Statement(statement) = root
        .get_kind()
        .which()
        .expect("operation kind checked at construction")
    else {
        return Err(Error::Encoding);
    };
    let wire::statement::detail::ValueChanged(changed) = statement
        .map_err(|_| Error::Encoding)?
        .get_detail()
        .which()
        .map_err(|_| Error::Encoding)?
    else {
        return Err(Error::Encoding);
    };
    let changed = changed.map_err(|_| Error::Encoding)?;
    if !changed.has_key() || !changed.has_subkeys() {
        return Err(Error::Encoding);
    }
    let hint = ChangeHint {
        key: key_decode(changed.get_key().map_err(|_| Error::Encoding)?)?,
        subkeys: watch::ranges_decode(changed.get_subkeys().map_err(|_| Error::Encoding)?)?,
        count: changed.get_count(),
        watch_id: changed.get_watch_id(),
        value: if changed.has_value() {
            Some(Box::new(value_decode(
                changed.get_value().map_err(|_| Error::Encoding)?,
            )?))
        } else {
            None
        },
    };
    hint.check()?;
    Ok((root.get_op_id(), hint))
}

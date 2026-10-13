// SPDX-License-Identifier: MPL-2.0
// Portions of Veilid, Copyright Veilid contributors.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. https://mozilla.org/MPL/2.0/
// Upstream dd8e2cdd72b5bf817172ac31c20872b168c5c8fc:
// rpc_processor/coders/operations/operation_inspect_value.rs.
//! Original InspectValue RPCs. Sequence reports are hints from one node, never
//! authenticated record content or evidence of network-wide absence.
use super::*;

/// Original inspection parameters. Empty ranges request the complete record.
pub struct Inspection {
    /// Public record locator.
    pub key: crate::RecordKey,
    /// Original inclusive subkey range set.
    pub subkeys: SubkeyRanges,
    /// Request the original owner-signed descriptor.
    pub want_descriptor: bool,
}
impl Inspection {
    /// Encode the original request using a fresh operation ID.
    pub fn question(&self) -> Result<Question, Error> {
        self.encode(random_id()?)
    }
    fn encode(&self, id: u64) -> Result<Question, Error> {
        if self.subkeys.ranges_len() > watch::MAX_RANGES {
            return Err(Error::Encoding);
        }
        let mut message = Builder::new_default();
        let mut operation = message.init_root::<wire::operation::Builder>();
        operation.set_op_id(id);
        let mut question = operation.get_kind().init_question();
        question.reborrow().get_respond_to().set_sender(());
        let mut inspect = question.get_detail().init_inspect_value_q();
        key_encode(&self.key, inspect.reborrow().init_key());
        watch::ranges_encode(
            &self.subkeys,
            inspect
                .reborrow()
                .init_subkeys(self.subkeys.ranges_len() as u32),
        );
        inspect.set_want_descriptor(self.want_descriptor);
        Ok(Question {
            id,
            bytes: bytes(message)?,
        })
    }
}
/// Decode an already authenticated original inspection question.
pub fn inspection(operation: &SignedOperation) -> Result<(u64, Inspection), Error> {
    decode(operation.operation())
}
fn decode(operation: &[u8]) -> Result<(u64, Inspection), Error> {
    let message = read(operation)?;
    let operation = message
        .get_root::<wire::operation::Reader>()
        .map_err(|_| Error::Encoding)?;
    let wire::operation::kind::Question(question) =
        operation.get_kind().which().map_err(|_| Error::Encoding)?
    else {
        return Err(Error::Encoding);
    };
    let question = question.map_err(|_| Error::Encoding)?;
    if !matches!(
        question
            .get_respond_to()
            .which()
            .map_err(|_| Error::Encoding)?,
        wire::question::respond_to::Sender(())
    ) {
        return Err(Error::Encoding);
    }
    let wire::question::detail::InspectValueQ(inspect) =
        question.get_detail().which().map_err(|_| Error::Encoding)?
    else {
        return Err(Error::Encoding);
    };
    let inspect = inspect.map_err(|_| Error::Encoding)?;
    if !inspect.has_key() || !inspect.has_subkeys() {
        return Err(Error::Encoding);
    }
    Ok((
        operation.get_op_id(),
        Inspection {
            key: key_decode(inspect.get_key().map_err(|_| Error::Encoding)?)?,
            subkeys: watch::ranges_decode(inspect.get_subkeys().map_err(|_| Error::Encoding)?)?,
            want_descriptor: inspect.get_want_descriptor(),
        },
    ))
}
/// Original inspection response. Every sequence requires an authenticated Get
/// before producing content; `u32::MAX` is upstream's absent-value sentinel.
pub struct InspectionResponse {
    /// Whether this node accepts responsibility for the key.
    pub accepted: bool,
    /// Sequences for the requested, schema-clipped subkeys in ascending order.
    pub seqs: Vec<u32>,
    /// Independently signed routing hints, not authority delegated by this node.
    pub peers: Vec<UnverifiedPeerInfoBytes>,
    /// Original signed descriptor, when requested and present.
    pub descriptor: Option<Descriptor>,
}
impl Answer {
    /// Encode an original InspectValueA bound to its authenticated question.
    pub fn inspection(
        question: &SignedOperation,
        response: &InspectionResponse,
    ) -> Result<Self, Error> {
        let (id, _) = inspection(question)?;
        if response.seqs.len() > crate::MAX_SUBKEY_COUNT || response.peers.len() > 20 {
            return Err(Error::Encoding);
        }
        let mut message = Builder::new_default();
        let mut operation = message.init_root::<wire::operation::Builder>();
        operation.set_op_id(id);
        let mut answer = operation
            .get_kind()
            .init_answer()
            .get_detail()
            .init_inspect_value_a();
        answer.set_accepted(response.accepted);
        let mut seqs = answer.reborrow().init_seqs(response.seqs.len() as u32);
        for (index, seq) in response.seqs.iter().enumerate() {
            seqs.set(index as u32, *seq);
        }
        answer::peers_encode(
            &response.peers,
            answer.reborrow().init_peers(response.peers.len() as u32),
        )?;
        if let Some(descriptor) = &response.descriptor {
            descriptor_encode(descriptor, answer.init_descriptor());
        }
        Ok(Self(bytes(message)?))
    }
}
impl Question {
    /// Validate exact question correlation and the original schema/sequence bounds.
    /// This does not turn a remote sequence report into authenticated value data.
    pub fn inspection_answer(
        &self,
        operation: &SignedOperation,
        known_descriptor: Option<&Descriptor>,
        verifier: &impl Verifier,
    ) -> Result<InspectionResponse, Error> {
        let (_, request) = decode(&self.bytes)?;
        let message = read(operation.operation())?;
        let root = message
            .get_root::<wire::operation::Reader>()
            .map_err(|_| Error::Encoding)?;
        if root.get_op_id() != self.id {
            return Err(Error::Encoding);
        }
        let wire::operation::kind::Answer(answer) =
            root.get_kind().which().map_err(|_| Error::Encoding)?
        else {
            return Err(Error::Encoding);
        };
        let wire::answer::detail::InspectValueA(answer) = answer
            .map_err(|_| Error::Encoding)?
            .get_detail()
            .which()
            .map_err(|_| Error::Encoding)?
        else {
            return Err(Error::Encoding);
        };
        let answer = answer.map_err(|_| Error::Encoding)?;
        if !answer.has_seqs() || !answer.has_peers() {
            return Err(Error::Encoding);
        }
        let seqs = answer.get_seqs().map_err(|_| Error::Encoding)?;
        let maximum = if request.subkeys.is_empty() {
            crate::MAX_SUBKEY_COUNT as u64
        } else {
            request.subkeys.len().min(crate::MAX_SUBKEY_COUNT as u64)
        };
        if u64::from(seqs.len()) > maximum {
            return Err(Error::Encoding);
        }
        let descriptor = if answer.has_descriptor() {
            Some(descriptor_decode(
                answer.get_descriptor().map_err(|_| Error::Encoding)?,
            )?)
        } else {
            None
        };
        for descriptor in [descriptor.as_ref(), known_descriptor]
            .into_iter()
            .flatten()
        {
            descriptor.validate_for(&request.key, verifier)?;
        }
        if let (Some(current), Some(previous)) = (&descriptor, known_descriptor)
            && (current.owner != previous.owner || current.schema != previous.schema)
        {
            return Err(Error::WrongRecord);
        }
        Ok(InspectionResponse {
            accepted: answer.get_accepted(),
            seqs: seqs.iter().collect(),
            peers: answer::peers_decode(answer.get_peers().map_err(|_| Error::Encoding)?)?,
            descriptor,
        })
    }
}

#[cfg(test)]
#[path = "../../tests/support/inspect.rs"]
mod tests;

// SPDX-License-Identifier: MPL-2.0
// Portions of Veilid, Copyright Veilid contributors.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. https://mozilla.org/MPL/2.0/
// Upstream dd8e2cdd72b5bf817172ac31c20872b168c5c8fc:
// rpc_processor/coders/operations/operation_{get,set,watch}_value.rs, peer_info.rs,
// and rpc_processor/rpc_watch_value.rs.
//! Original upstream answers and question-bound record validation.
use super::*;
const MAX_PEERS: usize = 20;
// Upstream crypto::MAX_CRYPTO_KINDS, also enforced by decode_peer_info.
const MAX_PEER_SIGNATURES: u32 = 3;

/// Opaque upstream PeerInfo. Its original NodeInfo message and signatures are
/// retained, but MUST be authenticated by the routing owner before use. Records
/// does not assign endpoint formats, trust a supplied coordinate, or choose peers.
pub struct UnverifiedPeerInfoBytes(Vec<u8>);
impl UnverifiedPeerInfoBytes {
    /// Check bounded wire shape only. This does not authenticate a network node.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, Error> {
        let message = read(&bytes)?;
        let peer = message
            .get_root::<wire::peer_info::Reader>()
            .map_err(|_| Error::Encoding)?;
        if !peer.has_node_info_message() || !peer.has_signatures() {
            return Err(Error::Encoding);
        }
        peer.get_node_info_message().map_err(|_| Error::Encoding)?;
        let signatures = peer.get_signatures().map_err(|_| Error::Encoding)?;
        if signatures.len() > MAX_PEER_SIGNATURES {
            return Err(Error::Encoding);
        }
        for signature in signatures {
            signature.get_value().map_err(|_| Error::Encoding)?;
        }
        Ok(Self(bytes))
    }
    /// Standalone PeerInfo wire bytes for the routing owner's upstream validator.
    /// Extracting an embedded hint preserves its signed body and signatures.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
pub(super) fn peers_encode(
    peers: &[UnverifiedPeerInfoBytes],
    mut list: capnp::struct_list::Builder<'_, wire::peer_info::Owned>,
) -> Result<(), Error> {
    for (index, peer) in peers.iter().enumerate() {
        let message = read(peer.as_bytes())?;
        let peer = message
            .get_root::<wire::peer_info::Reader>()
            .expect("immutable PeerInfo root checked at construction");
        let mut builder = list.reborrow().get(index as u32);
        builder.set_node_info_message(peer.get_node_info_message().map_err(|_| Error::Encoding)?);
        builder
            .set_signatures(peer.get_signatures().map_err(|_| Error::Encoding)?)
            .map_err(|_| Error::Encoding)?;
    }
    Ok(())
}
pub(super) fn peers_decode(
    list: capnp::struct_list::Reader<'_, wire::peer_info::Owned>,
) -> Result<Vec<UnverifiedPeerInfoBytes>, Error> {
    if list.len() as usize > MAX_PEERS {
        return Err(Error::Encoding);
    }
    list.iter()
        .map(|peer| {
            let mut message = Builder::new_default();
            message.set_root(peer).map_err(|_| Error::Encoding)?;
            UnverifiedPeerInfoBytes::from_bytes(bytes(message)?)
        })
        .collect()
}
/// Supported upstream record answers. Routing hints remain explicitly unverified;
/// an authenticated answering node cannot vouch for another node's endpoint.
pub enum Response {
    /// WatchValueA. The storage handler alone decides the accepted lease.
    Watch {
        /// Whether this node accepts responsibility for the requested record key.
        accepted: bool,
        /// Returned lease duration in upstream TimestampDuration microseconds.
        duration_us: u64,
        /// Zero means no lease; a nonzero identifier is bound to this storage node.
        watch_id: u64,
        /// Routing hints requiring independent validation.
        peers: Vec<UnverifiedPeerInfoBytes>,
    },
    /// GetValueA, including the original descriptor and value when present.
    Get {
        /// The answering node reports accepting responsibility for this key.
        accepted: bool,
        /// Original signed value, or absence at this answering node only.
        value: Option<Box<SignedValue>>,
        /// Unmodified signed descriptor if supplied.
        descriptor: Option<Descriptor>,
        /// Bounded upstream routing hints, requiring independent validation.
        peers: Vec<UnverifiedPeerInfoBytes>,
    },
    /// SetValueA. A conflicting value remains its original signed value.
    Set {
        /// The answering node reports being close enough to handle this key.
        /// This flag alone is not retention: inspect need_descriptor and value.
        accepted: bool,
        /// Upstream request to include the descriptor on a subsequent question.
        need_descriptor: bool,
        /// Existing signed value returned by the answering node.
        value: Option<Box<SignedValue>>,
        /// Bounded upstream routing hints, requiring independent validation.
        peers: Vec<UnverifiedPeerInfoBytes>,
    },
}
/// An original upstream answer Operation, correlated to an authenticated question.
/// Construction encodes the handler's result; it never performs storage or
/// manufactures an acknowledgment on behalf of a storage node.
pub struct Answer(pub(super) Vec<u8>);
impl Answer {
    /// Encode the matching GetValueA or SetValueA with the original request ID.
    pub fn new(question: &SignedOperation, response: &Response) -> Result<Self, Error> {
        let (id, query) = query(question)?;
        let mut message = Builder::new_default();
        let mut operation = message.init_root::<wire::operation::Builder>();
        operation.set_op_id(id);
        let detail = operation.get_kind().init_answer().get_detail();
        match (query, response) {
            (
                Query::Watch { .. },
                Response::Watch {
                    accepted,
                    duration_us,
                    watch_id,
                    peers,
                },
            ) => {
                if peers.len() > MAX_PEERS {
                    return Err(Error::Encoding);
                }
                let mut answer = detail.init_watch_value_a();
                answer.set_accepted(*accepted);
                answer.set_duration(*duration_us);
                answer.set_watch_id(*watch_id);
                peers_encode(peers, answer.init_peers(peers.len() as u32))?;
            }
            (
                Query::Get { .. },
                Response::Get {
                    accepted,
                    value,
                    descriptor,
                    peers,
                },
            ) => {
                if peers.len() > MAX_PEERS {
                    return Err(Error::Encoding);
                }
                let mut answer = detail.init_get_value_a();
                answer.set_accepted(*accepted);
                if let Some(value) = value {
                    value_encode(value, answer.reborrow().init_value())?;
                }
                peers_encode(peers, answer.reborrow().init_peers(peers.len() as u32))?;
                if let Some(descriptor) = descriptor {
                    descriptor_encode(descriptor, answer.init_descriptor());
                }
            }
            (
                Query::Set { .. },
                Response::Set {
                    accepted,
                    need_descriptor,
                    value,
                    peers,
                },
            ) => {
                if peers.len() > MAX_PEERS {
                    return Err(Error::Encoding);
                }
                let mut answer = detail.init_set_value_a();
                answer.set_accepted(*accepted);
                answer.set_need_descriptor(*need_descriptor);
                if let Some(value) = value {
                    value_encode(value, answer.reborrow().init_value())?;
                }
                peers_encode(peers, answer.init_peers(peers.len() as u32))?;
            }
            _ => return Err(Error::Encoding),
        }
        Ok(Self(bytes(message)?))
    }
    /// Original answer Operation bytes for upstream interoperability checks.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// Sign inside the node key owner's synchronous capability callback.
    pub fn sign(
        &self,
        destination: &PublicKey,
        signer: &impl Signer,
    ) -> Result<SignedOperation, Error> {
        SignedOperation::sign(self.0.clone(), destination, signer)
    }
}
impl Question {
    /// Validate an authenticated answer against this exact request ID, kind,
    /// locator, subkey and optional previously authenticated descriptor. Missing
    /// data means absence at this responder, never proof of network-wide loss.
    pub fn answer(
        &self,
        operation: &SignedOperation,
        known_descriptor: Option<&Descriptor>,
        verifier: &impl Verifier,
    ) -> Result<Response, Error> {
        let (_, query) = decode_query(&self.bytes)?;
        let message = read(operation.operation())?;
        let root = message
            .get_root::<wire::operation::Reader>()
            .expect("operation root checked at construction");
        if root.get_op_id() != self.id {
            return Err(Error::Encoding);
        }
        let wire::operation::kind::Answer(answer) = root
            .get_kind()
            .which()
            .expect("operation kind checked at construction")
        else {
            return Err(Error::Encoding);
        };
        let detail = answer
            .map_err(|_| Error::Encoding)?
            .get_detail()
            .which()
            .map_err(|_| Error::Encoding)?;
        match (query, detail) {
            (
                Query::Watch {
                    watch_id: requested,
                    ..
                },
                wire::answer::detail::WatchValueA(answer),
            ) => {
                let answer = answer.map_err(|_| Error::Encoding)?;
                let accepted = answer.get_accepted();
                let duration_us = answer.get_duration();
                let watch_id = answer.get_watch_id();
                // Match upstream rpc_call_watch_value's accepted-answer checks.
                // Peers, route pinning and latency-adjusted expiration belong to
                // the routing/runtime owner, not this bounded record codec.
                if accepted
                    && ((requested != 0 && requested != watch_id)
                        || (duration_us != 0 && watch_id == 0))
                {
                    return Err(Error::Encoding);
                }
                Ok(Response::Watch {
                    accepted,
                    duration_us,
                    watch_id,
                    peers: peers_decode(answer.get_peers().map_err(|_| Error::Encoding)?)?,
                })
            }
            (Query::Get { key, subkey, .. }, wire::answer::detail::GetValueA(answer)) => {
                let answer = answer.map_err(|_| Error::Encoding)?;
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
                    descriptor.validate_for(&key, verifier)?;
                }
                if let (Some(current), Some(previous)) = (&descriptor, known_descriptor)
                    && (current.owner != previous.owner || current.schema != previous.schema)
                {
                    return Err(Error::WrongRecord);
                }
                let value = if answer.has_value() {
                    Some(Box::new(value_decode(
                        answer.get_value().map_err(|_| Error::Encoding)?,
                    )?))
                } else {
                    None
                };
                validate_value(
                    &key,
                    subkey,
                    value.as_deref(),
                    descriptor.as_ref().or(known_descriptor),
                    verifier,
                )?;
                Ok(Response::Get {
                    accepted: answer.get_accepted(),
                    value,
                    descriptor,
                    peers: peers_decode(answer.get_peers().map_err(|_| Error::Encoding)?)?,
                })
            }
            (
                Query::Set {
                    key,
                    subkey,
                    descriptor,
                    ..
                },
                wire::answer::detail::SetValueA(answer),
            ) => {
                let answer = answer.map_err(|_| Error::Encoding)?;
                let descriptor = descriptor
                    .as_ref()
                    .or(known_descriptor)
                    .ok_or(Error::UnknownRecord)?;
                descriptor.validate_for(&key, verifier)?;
                let value = if answer.has_value() {
                    Some(Box::new(value_decode(
                        answer.get_value().map_err(|_| Error::Encoding)?,
                    )?))
                } else {
                    None
                };
                validate_value(&key, subkey, value.as_deref(), Some(descriptor), verifier)?;
                Ok(Response::Set {
                    accepted: answer.get_accepted(),
                    need_descriptor: answer.get_need_descriptor(),
                    value,
                    peers: peers_decode(answer.get_peers().map_err(|_| Error::Encoding)?)?,
                })
            }
            _ => Err(Error::Encoding),
        }
    }
}
fn validate_value(
    key: &crate::RecordKey,
    subkey: u32,
    value: Option<&SignedValue>,
    descriptor: Option<&Descriptor>,
    verifier: &impl Verifier,
) -> Result<(), Error> {
    if let Some(value) = value {
        let descriptor = descriptor.ok_or(Error::UnknownRecord)?;
        let schema = descriptor.validate_for(key, verifier)?;
        value.validate(key, &descriptor.owner, &schema, subkey, verifier)?;
    }
    Ok(())
}

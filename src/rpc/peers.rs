// SPDX-License-Identifier: MPL-2.0
// Portions of Veilid, Copyright Veilid contributors.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. https://mozilla.org/MPL/2.0/
// Upstream dd8e2cdd72b5bf817172ac31c20872b168c5c8fc:
// rpc_processor/coders/{node_info,peer_info,crypto_info,dial_info_detail}.rs;
// routing_table/types/peer_info.rs. Only Data-valued transport extensions here.
//! Authenticate original PeerInfo bytes before the transport interprets an endpoint.
//! No peer directory, socket code or alternate signature transcript.
use super::*;
use std::collections::BTreeSet;

/// Existing upstream directly reachable class. A transport interprets its endpoint;
/// this does not imply an IP connection when the registered protocol is Tor.
pub const DIRECT: u32 = u32::from_be_bytes(*b"dicD");
/// Existing upstream record-storage capability. Operator bootstrap omits it.
pub const DHTV: u32 = u32::from_be_bytes(*b"DHTV");
const ENV0: u32 = u32::from_be_bytes(*b"ENV0");

/// A signed transport-extension payload, still requiring its transport's decoder.
#[derive(Clone, PartialEq, Eq)]
pub struct ExtensionDialInfo {
    /// Upstream dial-info class.
    pub class: u32,
    /// Registered protocol identifier.
    pub protocol: u32,
    /// Exact Data value in DialInfo.detail, interpreted only by the transport leaf.
    pub detail: Vec<u8>,
}
/// NodeInfo fields for a direct Data-valued transport extension. The publisher
/// must obtain its endpoint from a live listener, not mark caller state ready.
#[derive(Clone, PartialEq, Eq)]
pub struct Advertisement {
    /// Monotonic publication timestamp in Unix microseconds, owned by runtime.
    pub timestamp_us: u64,
    /// Original upstream capability identifiers; bootstrap omits DHTV.
    pub capabilities: Vec<u32>,
    /// Outbound protocol identifiers understood by this transport.
    pub outbound_protocols: Vec<u32>,
    /// Address type identifiers understood by this transport.
    pub address_types: Vec<u32>,
    /// Original transport extension entries. No dummy socket address.
    pub dial_info: Vec<ExtensionDialInfo>,
}
impl Advertisement {
    fn validate(&self) -> Result<(), Error> {
        if self.capabilities.len() > 64
            || self.outbound_protocols.is_empty()
            || self.outbound_protocols.len() > 16
            || self.address_types.is_empty()
            || self.address_types.len() > 16
            || self.dial_info.is_empty()
            || self.dial_info.len() > 16
        {
            return Err(Error::Encoding);
        }
        for list in [
            &self.capabilities,
            &self.outbound_protocols,
            &self.address_types,
        ] {
            if list.iter().collect::<BTreeSet<_>>().len() != list.len() {
                return Err(Error::Encoding);
            }
        }
        for dial in &self.dial_info {
            if dial.class != DIRECT
                || dial.detail.is_empty()
                || dial.detail.len() > 4096
                || !self.outbound_protocols.contains(&dial.protocol)
            {
                return Err(Error::Encoding);
            }
        }
        Ok(())
    }
}

/// A node identity bound to the ORIGINAL NodeInfo by a maintained VLD0 verifier.
/// Transport endpoint validation remains mandatory before entering a route table.
/// No constructor, deserializer or caller-provided validation flag exists.
pub struct VerifiedExtensionPeer {
    node: PublicKey,
    advertisement: Advertisement,
    original: UnverifiedPeerInfoBytes,
}
impl VerifiedExtensionPeer {
    /// VLD0 node coordinate is its 32-byte signing public key, as upstream.
    pub fn node_id(&self) -> &PublicKey {
        &self.node
    }
    /// Signed metadata; endpoint semantics are owned by the transport leaf.
    pub fn advertisement(&self) -> &Advertisement {
        &self.advertisement
    }
    /// Preserve original signed bytes when returning closer-peer hints.
    pub fn original(&self) -> &UnverifiedPeerInfoBytes {
        &self.original
    }
}

impl UnverifiedPeerInfoBytes {
    /// Publish a purpose-scoped node's original upstream PeerInfo. Signing is
    /// synchronous inside Keys' callback; no node secret crosses an async boundary.
    pub fn sign_extension(
        advertisement: Advertisement,
        signer: &impl Signer,
    ) -> Result<Self, Error> {
        advertisement.validate()?;
        let mut message = Builder::new_default();
        let mut node = message.init_root::<wire::node_info::Builder>();
        node.set_timestamp(advertisement.timestamp_us);
        node.reborrow().init_envelope_support(1).set(0, ENV0);
        let mut list = node.reborrow().init_crypto_info_list(1);
        let mut crypto = list.reborrow().get(0);
        crypto.set_crypto_kind(KIND);
        crypto
            .init_detail()
            .init_as::<wire::crypto_info_v_l_d0::Builder>()
            .set_public_key(&signer.public_key());
        let mut caps = node
            .reborrow()
            .init_capabilities(advertisement.capabilities.len() as u32);
        for (i, value) in advertisement.capabilities.iter().enumerate() {
            caps.set(i as u32, *value);
        }
        let mut protocols = node
            .reborrow()
            .init_outbound_protocols(advertisement.outbound_protocols.len() as u32);
        for (i, value) in advertisement.outbound_protocols.iter().enumerate() {
            protocols.set(i as u32, *value);
        }
        let mut addresses = node
            .reborrow()
            .init_address_types(advertisement.address_types.len() as u32);
        for (i, value) in advertisement.address_types.iter().enumerate() {
            addresses.set(i as u32, *value);
        }
        let mut dials = node
            .reborrow()
            .init_dial_info_detail_list(advertisement.dial_info.len() as u32);
        for (i, value) in advertisement.dial_info.iter().enumerate() {
            let mut entry = dials.reborrow().get(i as u32);
            entry.set_class(value.class);
            let mut dial = entry.init_dial_info();
            dial.set_protocol_type(value.protocol);
            dial.init_detail()
                .set_as::<capnp::data::Owned>(&value.detail[..])
                .map_err(|_| Error::Encoding)?;
        }
        node.init_relay_info_list(0);
        // Upstream signs the packed NodeInfo message exactly; it does not sign an
        // extracted endpoint or a reserialized public-key/address tuple.
        let signed = packed(message)?;
        let signature = signer.sign(&signed)?;
        let mut outer = Builder::new_default();
        let mut peer = outer.init_root::<wire::peer_info::Builder>();
        peer.set_node_info_message(&signed);
        let mut signatures = peer.init_signatures(1);
        let mut signature_builder = signatures.reborrow().get(0);
        signature_builder.set_kind(KIND);
        signature_builder.set_value(&signature);
        Self::from_bytes(bytes(outer)?)
    }

    /// Check the original VLD0 signature and structural bounds. Unknown crypto,
    /// relays or non-Data transport encodings are refused by this narrow adapter.
    /// This never claims another peer's endpoint is reachable or storage is durable.
    pub fn verify_extension(
        &self,
        verifier: &impl Verifier,
    ) -> Result<VerifiedExtensionPeer, Error> {
        let outer = read(self.as_bytes())?;
        let peer = outer
            .get_root::<wire::peer_info::Reader>()
            .map_err(|_| Error::Encoding)?;
        let signed = peer.get_node_info_message().map_err(|_| Error::Encoding)?;
        let message = read_packed(signed)?;
        let node = message
            .get_root::<wire::node_info::Reader>()
            .map_err(|_| Error::Encoding)?;
        let crypto = node.get_crypto_info_list().map_err(|_| Error::Encoding)?;
        let signatures = peer.get_signatures().map_err(|_| Error::Encoding)?;
        if crypto.len() != 1 || signatures.len() != 1 {
            return Err(Error::Encoding);
        }
        let crypto = crypto.get(0);
        if crypto.get_crypto_kind() != KIND {
            return Err(Error::Encoding);
        }
        let vld0 = crypto
            .get_detail()
            .get_as::<wire::crypto_info_v_l_d0::Reader>()
            .map_err(|_| Error::Encoding)?;
        let public: [u8; 32] = vld0
            .get_public_key()
            .map_err(|_| Error::Encoding)?
            .try_into()
            .map_err(|_| Error::Encoding)?;
        let signature = signatures.get(0);
        let signature: Signature = typed(signature.get_kind(), signature.get_value())?;
        if !verifier.verify(&public, signed, &signature) {
            return Err(Error::BadSignature);
        }
        let envelopes = node.get_envelope_support().map_err(|_| Error::Encoding)?;
        if envelopes.len() != 1 || envelopes.get(0) != ENV0 {
            return Err(Error::Encoding);
        }
        if !node.has_capabilities()
            || !node.has_outbound_protocols()
            || !node.has_address_types()
            || !node.has_dial_info_detail_list()
            || !node.has_relay_info_list()
            || !node
                .get_relay_info_list()
                .map_err(|_| Error::Encoding)?
                .is_empty()
        {
            return Err(Error::Encoding);
        }
        let caps = node.get_capabilities().map_err(|_| Error::Encoding)?;
        let protocols = node.get_outbound_protocols().map_err(|_| Error::Encoding)?;
        let addresses = node.get_address_types().map_err(|_| Error::Encoding)?;
        let dials = node
            .get_dial_info_detail_list()
            .map_err(|_| Error::Encoding)?;
        if caps.len() > 64 || protocols.len() > 16 || addresses.len() > 16 || dials.len() > 16 {
            return Err(Error::Encoding);
        }
        let mut dial_info = Vec::with_capacity(dials.len() as usize);
        for entry in dials {
            if !entry.has_dial_info() {
                return Err(Error::Encoding);
            }
            let dial = entry.get_dial_info().map_err(|_| Error::Encoding)?;
            let data = dial
                .get_detail()
                .get_as::<capnp::data::Reader>()
                .map_err(|_| Error::Encoding)?;
            if data.len() > 4096 {
                return Err(Error::Encoding);
            }
            dial_info.push(ExtensionDialInfo {
                class: entry.get_class(),
                protocol: dial.get_protocol_type(),
                detail: data.to_vec(),
            });
        }
        let advertisement = Advertisement {
            timestamp_us: node.get_timestamp(),
            capabilities: caps.iter().collect(),
            outbound_protocols: protocols.iter().collect(),
            address_types: addresses.iter().collect(),
            dial_info,
        };
        advertisement.validate()?;
        Ok(VerifiedExtensionPeer {
            node: public,
            advertisement,
            original: Self::from_bytes(self.as_bytes().to_vec())?,
        })
    }
}

/// Original FindNodeQ, signed through the existing question capability. This asks
/// bootstrap/routing nodes for peers; it neither reads nor stores record data.
pub fn find_node(coordinate: &PublicKey, capabilities: &[u32]) -> Result<Question, Error> {
    if capabilities.len() > 64 {
        return Err(Error::Encoding);
    }
    let id = random_id()?;
    let mut message = Builder::new_default();
    let mut operation = message.init_root::<wire::operation::Builder>();
    operation.set_op_id(id);
    let mut question = operation.get_kind().init_question();
    question.reborrow().get_respond_to().set_sender(());
    let mut find = question.get_detail().init_find_node_q();
    let mut node = find.reborrow().init_node_id();
    node.set_kind(KIND);
    node.set_value(coordinate);
    let mut caps = find.init_capabilities(capabilities.len() as u32);
    for (i, cap) in capabilities.iter().enumerate() {
        caps.set(i as u32, *cap);
    }
    Ok(Question {
        id,
        bytes: bytes(message)?,
    })
}
/// Decode an authenticated FindNodeQ. The requester's NodeInfo must independently
/// bind its signed-operation key before a transport response is dispatched.
pub fn find_query(operation: &SignedOperation) -> Result<(u64, PublicKey, Vec<u32>), Error> {
    let message = read(operation.operation())?;
    let root = message
        .get_root::<wire::operation::Reader>()
        .map_err(|_| Error::Encoding)?;
    let wire::operation::kind::Question(q) =
        root.get_kind().which().map_err(|_| Error::Encoding)?
    else {
        return Err(Error::Encoding);
    };
    let q = q.map_err(|_| Error::Encoding)?;
    if !matches!(
        q.get_respond_to().which().map_err(|_| Error::Encoding)?,
        wire::question::respond_to::Sender(())
    ) {
        return Err(Error::Encoding);
    }
    let wire::question::detail::FindNodeQ(find) =
        q.get_detail().which().map_err(|_| Error::Encoding)?
    else {
        return Err(Error::Encoding);
    };
    let find = find.map_err(|_| Error::Encoding)?;
    if !find.has_node_id() || !find.has_capabilities() {
        return Err(Error::Encoding);
    }
    let node = find.get_node_id().map_err(|_| Error::Encoding)?;
    let coordinate = typed(node.get_kind(), node.get_value())?;
    let caps = find.get_capabilities().map_err(|_| Error::Encoding)?;
    if caps.len() > 64 {
        return Err(Error::Encoding);
    }
    Ok((root.get_op_id(), coordinate, caps.iter().collect()))
}
/// An original FindNodeA, with no new wire envelope or discovery authority.
pub struct FindAnswer(Vec<u8>);
impl FindAnswer {
    /// Original encoded operation for exact comparison before transmission.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// Return bounded original signed peer hints for this exact question.
    pub fn new(
        question: &SignedOperation,
        peers: &[UnverifiedPeerInfoBytes],
    ) -> Result<Self, Error> {
        let (id, _, _) = find_query(question)?;
        if peers.len() > 20 {
            return Err(Error::Encoding);
        }
        let mut message = Builder::new_default();
        let mut root = message.init_root::<wire::operation::Builder>();
        root.set_op_id(id);
        let list = root
            .get_kind()
            .init_answer()
            .get_detail()
            .init_find_node_a()
            .init_peers(peers.len() as u32);
        super::answer::peers_encode(peers, list)?;
        Ok(Self(bytes(message)?))
    }
    /// Sign once under the scoped node identity, for the exact requester's key.
    pub fn sign(
        &self,
        destination: &PublicKey,
        signer: &impl Signer,
    ) -> Result<SignedOperation, Error> {
        SignedOperation::sign(self.0.clone(), destination, signer)
    }
}
/// Correlate a node-authenticated FindNodeA and independently verify every returned
/// original PeerInfo and requested capability. Bootstrap cannot vouch for peers.
pub fn find_response(
    question: &SignedOperation,
    answer: &SignedOperation,
    verifier: &impl Verifier,
) -> Result<Vec<VerifiedExtensionPeer>, Error> {
    let (id, _, capabilities) = find_query(question)?;
    let message = read(answer.operation())?;
    let root = message
        .get_root::<wire::operation::Reader>()
        .map_err(|_| Error::Encoding)?;
    if root.get_op_id() != id {
        return Err(Error::Encoding);
    }
    let wire::operation::kind::Answer(a) = root.get_kind().which().map_err(|_| Error::Encoding)?
    else {
        return Err(Error::Encoding);
    };
    let a = a.map_err(|_| Error::Encoding)?;
    let wire::answer::detail::FindNodeA(find) =
        a.get_detail().which().map_err(|_| Error::Encoding)?
    else {
        return Err(Error::Encoding);
    };
    let find = find.map_err(|_| Error::Encoding)?;
    if !find.has_peers() {
        return Err(Error::Encoding);
    }
    super::answer::peers_decode(find.get_peers().map_err(|_| Error::Encoding)?)?
        .into_iter()
        .map(|peer| {
            let verified = peer.verify_extension(verifier)?;
            if capabilities
                .iter()
                .any(|cap| !verified.advertisement.capabilities.contains(cap))
            {
                return Err(Error::Encoding);
            }
            Ok(verified)
        })
        .collect()
}

impl Question {
    /// Include the node's original signed advertisement in the existing Operation
    /// field before signing the question. No extra discovery envelope is introduced.
    pub fn with_sender(mut self, peer: &UnverifiedPeerInfoBytes) -> Result<Self, Error> {
        let original = read(&self.bytes)?;
        let root = original
            .get_root::<wire::operation::Reader>()
            .map_err(|_| Error::Encoding)?;
        let mut message = Builder::new_default();
        message.set_root(root).map_err(|_| Error::Encoding)?;
        let mut root = message
            .get_root::<wire::operation::Builder>()
            .map_err(|_| Error::Encoding)?;
        let peer_message = read(peer.as_bytes())?;
        root.set_sender_peer_info(
            peer_message
                .get_root::<wire::peer_info::Reader>()
                .map_err(|_| Error::Encoding)?,
        )
        .map_err(|_| Error::Encoding)?;
        self.bytes = bytes(message)?;
        Ok(self)
    }
}
impl SignedOperation {
    /// Verify a previously unknown caller's own packet signature for this exact
    /// destination. This grants no role, schema quota or routing identity: discovery
    /// must also call `sender_peer`, and stored values retain independent validation.
    pub fn verify_sender(
        bytes: Vec<u8>,
        destination: &PublicKey,
        verifier: &impl Verifier,
    ) -> Result<Self, Error> {
        let message = read_packed(&bytes)?;
        let root = message
            .get_root::<wire::signed_operation::Reader>()
            .map_err(|_| Error::Encoding)?;
        let signer = root.get_signer().map_err(|_| Error::Encoding)?;
        let public = typed(signer.get_kind(), signer.get_value())?;
        Self::verify(bytes, destination, &public, verifier)
    }
    /// Bind the actual packet signer to its independently signed original NodeInfo.
    /// Replaying another node's advertisement with a different signer is refused.
    pub fn sender_peer(&self, verifier: &impl Verifier) -> Result<VerifiedExtensionPeer, Error> {
        self.sender_peer_as(self.signer(), verifier)
    }
    pub(crate) fn sender_peer_as(
        &self,
        sender: &PublicKey,
        verifier: &impl Verifier,
    ) -> Result<VerifiedExtensionPeer, Error> {
        self.sender_peer_optional_as(sender, verifier)?
            .ok_or(Error::Encoding)
    }
    /// As `sender_peer`, but a question that carries no sender PeerInfo (Veilid's optional
    /// `sender_peer_info`, sent by a dial-only client that has no listener to advertise) is
    /// `None` instead of an error. A present but invalid or replayed PeerInfo still fails.
    pub fn sender_peer_optional(
        &self,
        verifier: &impl Verifier,
    ) -> Result<Option<VerifiedExtensionPeer>, Error> {
        self.sender_peer_optional_as(self.signer(), verifier)
    }
    pub(crate) fn sender_peer_optional_as(
        &self,
        sender: &PublicKey,
        verifier: &impl Verifier,
    ) -> Result<Option<VerifiedExtensionPeer>, Error> {
        let message = read(self.operation())?;
        let root = message
            .get_root::<wire::operation::Reader>()
            .map_err(|_| Error::Encoding)?;
        if !root.has_sender_peer_info() {
            return Ok(None);
        }
        let peer = root.get_sender_peer_info().map_err(|_| Error::Encoding)?;
        let mut standalone = Builder::new_default();
        standalone.set_root(peer).map_err(|_| Error::Encoding)?;
        let peer =
            UnverifiedPeerInfoBytes::from_bytes(bytes(standalone)?)?.verify_extension(verifier)?;
        if peer.node_id() != sender {
            return Err(Error::BadSignature);
        }
        Ok(Some(peer))
    }
}

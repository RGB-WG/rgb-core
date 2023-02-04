// RGB Core Library: a reference implementation of RGB smart contract standards.
// Written in 2019-2022 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the MIT License along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

use std::collections::{BTreeMap, BTreeSet};
use std::num::ParseIntError;
use std::str::FromStr;

use amplify::{AsAny, Wrapper};
use bitcoin_hashes::{sha256, sha256t, Hash};
use bp::seals::txout::TxoSeal;
use bp::{Outpoint, Txid};
use commit_verify::mpc::ProtocolId;
use commit_verify::{CommitVerify, UntaggedProtocol};
use once_cell::sync::Lazy;

use super::{
    ConcealSeals, ConcealState, OwnedRights, OwnedRightsInner, ParentOwnedRights,
    ParentPublicRights, PublicRights, PublicRightsInner, TypedAssignments,
};
use crate::reveal::{self, MergeReveal};
use crate::schema::{
    ExtensionType, FieldType, NodeSubtype, NodeType, OwnedRightType, TransitionType,
};
use crate::temp::Chain;
use crate::{
    outpoint, schema, seal, txid, ConfidentialDataError, Metadata, PublicRightType, SchemaId,
};

static EMPTY_OWNED_RIGHTS: Lazy<ParentOwnedRights> = Lazy::new(ParentOwnedRights::default);
static EMPTY_PUBLIC_RIGHTS: Lazy<ParentPublicRights> = Lazy::new(ParentPublicRights::default);

/// Midstate for a tagged hash engine. Equals to a single SHA256 hash of
/// the value of two concatenated SHA256 hashes for `rgb:node` prefix string.
static MIDSTATE_NODE_ID: [u8; 32] = [
    0x90, 0xd0, 0xc4, 0x9b, 0xa6, 0xb8, 0xa, 0x5b, 0xbc, 0xba, 0x19, 0x9, 0xdc, 0xbd, 0x5a, 0x58,
    0x55, 0x6a, 0xe2, 0x16, 0xa5, 0xee, 0xb7, 0x3c, 0x1, 0xe0, 0x86, 0x91, 0x22, 0x43, 0x12, 0x9f,
];

pub const RGB_CONTRACT_ID_HRP: &str = "rgb";

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[display("{node_id}/{ty}/{no}")]
/// RGB contract node output pointer, defined by the node ID and output
/// number.
pub struct NodeOutpoint {
    pub node_id: NodeId,
    pub ty: OwnedRightType,
    pub no: u16,
}

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(inner)]
pub enum OutpointParseError {
    #[from]
    InvalidNodeId(bitcoin_hashes::hex::Error),

    InvalidType(ParseIntError),

    InvalidOutputNo(ParseIntError),

    /// invalid node outpoint format ('{0}')
    #[display(doc_comments)]
    WrongFormat(String),
}

impl FromStr for NodeOutpoint {
    type Err = OutpointParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split('/');
        match (split.next(), split.next(), split.next(), split.next()) {
            (Some(node_id), Some(ty), Some(no), None) => Ok(NodeOutpoint {
                node_id: node_id.parse()?,
                ty: ty.parse().map_err(OutpointParseError::InvalidType)?,
                no: no.parse().map_err(OutpointParseError::InvalidOutputNo)?,
            }),
            _ => Err(OutpointParseError::WrongFormat(s.to_owned())),
        }
    }
}

/// Tag used for [`NodeId`] and [`ContractId`] hash types
pub struct NodeIdTag;

impl sha256t::Tag for NodeIdTag {
    #[inline]
    fn engine() -> sha256::HashEngine {
        let midstate = sha256::Midstate::from_inner(MIDSTATE_NODE_ID);
        sha256::HashEngine::from_midstate(midstate, 64)
    }
}

impl NodeOutpoint {
    pub fn new(node_id: NodeId, ty: u16, no: u16) -> NodeOutpoint {
        NodeOutpoint { node_id, ty, no }
    }
}

/// Unique node (genesis, extensions & state transition) identifier equivalent
/// to the commitment hash
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
#[derive(Wrapper, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, From)]
#[wrapper(Debug, Display, BorrowSlice)]
pub struct NodeId(sha256t::Hash<NodeIdTag>);

impl<Msg> CommitVerify<Msg, UntaggedProtocol> for NodeId
where Msg: AsRef<[u8]>
{
    #[inline]
    fn commit(msg: &Msg) -> NodeId { NodeId::hash(msg) }
}

impl commit_encode::Strategy for NodeId {
    type Strategy = commit_encode::strategies::UsingStrict;
}

impl FromStr for NodeId {
    type Err = bitcoin_hashes::hex::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> { Ok(NodeId::from_inner(s.parse()?)) }
}

/// Unique contract identifier equivalent to the contract genesis commitment
#[derive(Wrapper, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, From)]
#[wrapper(Debug, BorrowSlice)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct ContractId(sha256t::Hash<NodeIdTag>);

impl From<ContractId> for ProtocolId {
    fn from(contract_id: ContractId) -> Self {
        ProtocolId::from_inner(contract_id.into_inner().into_inner())
    }
}

impl From<ProtocolId> for ContractId {
    fn from(protocol_id: ProtocolId) -> Self {
        ContractId::from_inner(<ContractId as Wrapper>::Inner::from_inner(
            protocol_id.into_inner(),
        ))
    }
}

impl commit_encode::Strategy for ContractId {
    type Strategy = commit_encode::strategies::UsingStrict;
}

/// RGB contract node API, defined as trait
///
/// Implemented by all contract node types (see [`NodeType`]):
/// - Genesis ([`Genesis`])
/// - State transitions ([`Transitions`])
/// - Public state extensions ([`Extensions`])
pub trait Node: AsAny {
    /// Returns type of the node (see [`NodeType`]). Unfortunately, this can't
    /// be just a const, since it will break our ability to convert concrete
    /// `Node` types into `&dyn Node` (entities implementing traits with const
    /// definitions can't be made into objects)
    fn node_type(&self) -> NodeType;

    /// Returns full contract node type information
    fn subtype(&self) -> NodeSubtype;

    /// Returns [`NodeId`], which is a hash of this node commitment
    /// serialization
    fn node_id(&self) -> NodeId;

    /// Returns [`Option::Some`]`(`[`ContractId`]`)`, which is a hash of
    /// genesis.
    /// - For genesis node, this hash is byte-equal to [`NodeId`] (however
    ///   displayed in a reverse manner, to introduce semantical distinction)
    /// - For extension node function returns id of the genesis, to which this
    ///   node commits to
    /// - For state transition function returns [`Option::None`], since they do
    ///   not keep this information; it must be deduced through state transition
    ///   graph
    fn contract_id(&self) -> Option<ContractId>;

    /// Returns [`Option::Some`]`(`[`TransitionType`]`)` for transitions or
    /// [`Option::None`] for genesis and extension node types
    fn transition_type(&self) -> Option<TransitionType>;

    /// Returns [`Option::Some`]`(`[`ExtensionType`]`)` for extension nodes or
    /// [`Option::None`] for genesis and trate transitions
    fn extension_type(&self) -> Option<ExtensionType>;

    /// Returns reference to a full set of metadata (in form of [`Metadata`]
    /// wrapper structure) for the contract node.
    fn metadata(&self) -> &Metadata;

    /// Returns reference to information about the owned rights in form of
    /// [`ParentOwnedRights`] wrapper structure which this node updates with
    /// state transition ("parent owned rights").
    ///
    /// This is always an empty `Vec` for [`Genesis`] and [`Extension`] node
    /// types.
    fn parent_owned_rights(&self) -> &ParentOwnedRights;

    /// Returns reference to information about the public rights (in form of
    /// [`ParentPublicRights`] wrapper structure), defined with "parent" state
    /// extensions (i.e. those finalized with the current state transition) or
    /// referenced by another state extension, which this node updates
    /// ("parent public rights").
    ///
    /// This is always an empty `Vec` for [`Genesis`].
    fn parent_public_rights(&self) -> &ParentPublicRights;
    fn owned_rights(&self) -> &OwnedRights;
    fn owned_rights_mut(&mut self) -> &mut OwnedRights;
    fn public_rights(&self) -> &PublicRights;
    fn public_rights_mut(&mut self) -> &mut PublicRights;

    #[inline]
    fn field_types(&self) -> Vec<FieldType> { self.metadata().keys().copied().collect() }

    #[inline]
    fn parent_public_right_types(&self) -> Vec<PublicRightType> {
        self.parent_public_rights()
            .values()
            .flat_map(BTreeSet::iter)
            .copied()
            .collect()
    }

    #[inline]
    fn parent_by_public_right_type(&self, t: PublicRightType) -> Vec<NodeId> {
        self.parent_public_rights()
            .iter()
            .filter(|(_, t2)| t2.contains(&t))
            .map(|(node_id, _)| *node_id)
            .collect()
    }

    /// For genesis and public state extensions always returns an empty list.
    /// While public state extension do have parent nodes, they do not contain
    /// indexed rights.
    #[inline]
    fn parent_outputs(&self) -> Vec<NodeOutpoint> {
        self.parent_owned_rights()
            .iter()
            .flat_map(|(node_id, map)| {
                let node_id = *node_id;
                map.iter()
                    .flat_map(|(ty, vec)| vec.iter().map(|no| (*ty, *no)))
                    .map(move |(ty, no)| NodeOutpoint { node_id, ty, no })
            })
            .collect()
    }

    #[inline]
    fn parent_outputs_by_type(&self, t: OwnedRightType) -> Vec<NodeOutpoint> {
        self.parent_outputs_by_types(&[t])
    }

    fn parent_outputs_by_types(&self, types: &[OwnedRightType]) -> Vec<NodeOutpoint> {
        self.parent_owned_rights()
            .iter()
            .flat_map(|(node_id, map)| {
                let node_id = *node_id;
                map.iter()
                    .filter(|(t, _)| types.contains(*t))
                    .flat_map(|(ty, vec)| vec.iter().map(|no| (*ty, *no)))
                    .map(move |(ty, no)| NodeOutpoint { node_id, ty, no })
            })
            .collect()
    }

    #[inline]
    fn parent_owned_right_types(&self) -> Vec<OwnedRightType> {
        self.parent_owned_rights()
            .values()
            .flat_map(BTreeMap::keys)
            .copied()
            .collect()
    }

    #[inline]
    fn owned_right_types(&self) -> BTreeSet<OwnedRightType> {
        self.owned_rights().keys().cloned().collect()
    }

    #[inline]
    fn owned_rights_by_type(&self, t: OwnedRightType) -> Option<&TypedAssignments> {
        self.owned_rights()
            .iter()
            .find_map(|(t2, a)| if *t2 == t { Some(a) } else { None })
    }

    #[inline]
    fn to_confiential_seals(&self) -> Vec<seal::Confidential> {
        self.owned_rights()
            .iter()
            .flat_map(|(_, assignment)| assignment.to_confidential_seals())
            .collect()
    }

    #[inline]
    fn revealed_seals(&self) -> Result<Vec<seal::Revealed>, ConfidentialDataError> {
        let unfiltered = self
            .owned_rights()
            .iter()
            .map(|(_, assignment)| assignment.revealed_seals())
            .collect::<Vec<_>>();
        if unfiltered.contains(&Err(ConfidentialDataError)) {
            return Err(ConfidentialDataError);
        }
        Ok(unfiltered
            .into_iter()
            .filter_map(Result::ok)
            .flat_map(Vec::into_iter)
            .collect())
    }

    #[inline]
    fn revealed_seals_by_type(
        &self,
        assignment_type: OwnedRightType,
    ) -> Result<Vec<seal::Revealed>, ConfidentialDataError> {
        Ok(self
            .owned_rights_by_type(assignment_type)
            .map(TypedAssignments::revealed_seals)
            .transpose()?
            .unwrap_or_default())
    }

    #[inline]
    fn filter_revealed_seals(&self) -> Vec<seal::Revealed> {
        self.owned_rights()
            .iter()
            .flat_map(|(_, assignment)| assignment.filter_revealed_seals())
            .collect()
    }

    #[inline]
    fn filter_revealed_seals_by_type(
        &self,
        assignment_type: OwnedRightType,
    ) -> Vec<seal::Revealed> {
        self.owned_rights_by_type(assignment_type)
            .map(TypedAssignments::filter_revealed_seals)
            .unwrap_or_else(Vec::new)
    }

    fn node_outputs(&self, witness_txid: Txid) -> BTreeMap<NodeOutpoint, Outpoint> {
        let node_id = self.node_id();
        let mut res: BTreeMap<NodeOutpoint, Outpoint> = bmap! {};
        for (ty, assignments) in self.owned_rights() {
            for (seal, node_output) in assignments.revealed_seal_outputs() {
                let outpoint = seal.outpoint_or(txid!(witness_txid));
                let node_outpoint = NodeOutpoint::new(node_id, *ty, node_output);
                res.insert(node_outpoint, outpoint!(outpoint));
            }
        }
        res
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default, AsAny)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct Genesis {
    schema_id: SchemaId,
    chain: Chain,
    metadata: Metadata,
    owned_rights: OwnedRights,
    public_rights: PublicRights,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default, AsAny)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct Extension {
    extension_type: ExtensionType,
    contract_id: ContractId,
    metadata: Metadata,
    owned_rights: OwnedRights,
    parent_public_rights: ParentPublicRights,
    public_rights: PublicRights,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default, AsAny)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct Transition {
    transition_type: TransitionType,
    metadata: Metadata,
    parent_owned_rights: ParentOwnedRights,
    owned_rights: OwnedRights,
    parent_public_rights: ParentPublicRights,
    public_rights: PublicRights,
}

impl ConcealState for Genesis {
    fn conceal_state_except(&mut self, seals: &[seal::Confidential]) -> usize {
        let mut count = 0;
        for (_, assignment) in self.owned_rights_mut().iter_mut() {
            count += assignment.conceal_state_except(seals);
        }
        count
    }
}

impl ConcealState for Extension {
    fn conceal_state_except(&mut self, seals: &[seal::Confidential]) -> usize {
        let mut count = 0;
        for (_, assignment) in self.owned_rights_mut().iter_mut() {
            count += assignment.conceal_state_except(seals);
        }
        count
    }
}

impl ConcealState for Transition {
    fn conceal_state_except(&mut self, seals: &[seal::Confidential]) -> usize {
        let mut count = 0;
        for (_, assignment) in self.owned_rights_mut().iter_mut() {
            count += assignment.conceal_state_except(seals);
        }
        count
    }
}

impl ConcealSeals for Transition {
    fn conceal_seals(&mut self, seals: &[seal::Confidential]) -> usize {
        let mut count = 0;
        for (_, assignment) in self.owned_rights_mut().iter_mut() {
            count += assignment.conceal_seals(seals);
        }
        count
    }
}

impl MergeReveal for Genesis {
    fn merge_reveal(mut self, other: Self) -> Result<Self, reveal::Error> {
        if self.consensus_commit() != other.consensus_commit() {
            return Err(reveal::Error::NodeMismatch(NodeType::Genesis));
        }
        self.owned_rights = self.owned_rights.merge_reveal(other.owned_rights)?;
        Ok(self)
    }
}

impl MergeReveal for Transition {
    fn merge_reveal(mut self, other: Self) -> Result<Self, reveal::Error> {
        if self.consensus_commit() != other.consensus_commit() {
            return Err(reveal::Error::NodeMismatch(NodeType::StateTransition));
        }
        self.owned_rights = self.owned_rights.merge_reveal(other.owned_rights)?;
        Ok(self)
    }
}

impl MergeReveal for Extension {
    fn merge_reveal(mut self, other: Self) -> Result<Self, reveal::Error> {
        if self.consensus_commit() != other.consensus_commit() {
            return Err(reveal::Error::NodeMismatch(NodeType::StateExtension));
        }
        self.owned_rights = self.owned_rights.merge_reveal(other.owned_rights)?;
        Ok(self)
    }
}

impl Node for Genesis {
    #[inline]
    fn node_type(&self) -> NodeType { NodeType::Genesis }

    #[inline]
    fn subtype(&self) -> NodeSubtype { NodeSubtype::Genesis }

    #[inline]
    fn node_id(&self) -> NodeId { self.clone().consensus_commit() }

    #[inline]
    fn contract_id(&self) -> Option<ContractId> {
        Some(ContractId::from_inner(self.node_id().into_inner()))
    }

    #[inline]
    fn transition_type(&self) -> Option<TransitionType> { None }

    #[inline]
    fn extension_type(&self) -> Option<ExtensionType> { None }

    #[inline]
    fn parent_owned_rights(&self) -> &ParentOwnedRights { &EMPTY_OWNED_RIGHTS }

    #[inline]
    fn parent_public_rights(&self) -> &ParentPublicRights { &EMPTY_PUBLIC_RIGHTS }

    #[inline]
    fn metadata(&self) -> &Metadata { &self.metadata }

    #[inline]
    fn owned_rights(&self) -> &OwnedRights { &self.owned_rights }

    #[inline]
    fn owned_rights_mut(&mut self) -> &mut OwnedRights { &mut self.owned_rights }

    #[inline]
    fn public_rights(&self) -> &PublicRights { &self.public_rights }

    #[inline]
    fn public_rights_mut(&mut self) -> &mut PublicRights { &mut self.public_rights }
}

impl Node for Extension {
    #[inline]
    fn node_type(&self) -> NodeType { NodeType::StateExtension }

    #[inline]
    fn subtype(&self) -> NodeSubtype { NodeSubtype::StateExtension(self.extension_type) }

    #[inline]
    fn node_id(&self) -> NodeId { self.clone().consensus_commit() }

    #[inline]
    fn contract_id(&self) -> Option<ContractId> { Some(self.contract_id) }

    #[inline]
    fn transition_type(&self) -> Option<TransitionType> { None }

    #[inline]
    fn extension_type(&self) -> Option<ExtensionType> { Some(self.extension_type) }

    #[inline]
    fn parent_owned_rights(&self) -> &ParentOwnedRights { &EMPTY_OWNED_RIGHTS }

    #[inline]
    fn parent_public_rights(&self) -> &ParentPublicRights { &self.parent_public_rights }

    #[inline]
    fn metadata(&self) -> &Metadata { &self.metadata }

    #[inline]
    fn owned_rights(&self) -> &OwnedRights { &self.owned_rights }

    #[inline]
    fn owned_rights_mut(&mut self) -> &mut OwnedRights { &mut self.owned_rights }

    #[inline]
    fn public_rights(&self) -> &PublicRights { &self.public_rights }

    #[inline]
    fn public_rights_mut(&mut self) -> &mut PublicRights { &mut self.public_rights }
}

impl Node for Transition {
    #[inline]
    fn node_type(&self) -> NodeType { NodeType::StateTransition }

    #[inline]
    fn subtype(&self) -> NodeSubtype { NodeSubtype::StateTransition(self.transition_type) }

    #[inline]
    fn node_id(&self) -> NodeId { self.clone().consensus_commit() }

    #[inline]
    fn contract_id(&self) -> Option<ContractId> { None }

    #[inline]
    fn transition_type(&self) -> Option<TransitionType> { Some(self.transition_type) }

    #[inline]
    fn extension_type(&self) -> Option<ExtensionType> { None }

    #[inline]
    fn parent_owned_rights(&self) -> &ParentOwnedRights { &self.parent_owned_rights }

    #[inline]
    fn parent_public_rights(&self) -> &ParentPublicRights { &self.parent_public_rights }

    #[inline]
    fn metadata(&self) -> &Metadata { &self.metadata }

    #[inline]
    fn owned_rights(&self) -> &OwnedRights { &self.owned_rights }

    #[inline]
    fn owned_rights_mut(&mut self) -> &mut OwnedRights { &mut self.owned_rights }

    #[inline]
    fn public_rights(&self) -> &PublicRights { &self.public_rights }

    #[inline]
    fn public_rights_mut(&mut self) -> &mut PublicRights { &mut self.public_rights }
}

impl Genesis {
    pub fn with(
        schema_id: SchemaId,
        chain: Chain,
        metadata: Metadata,
        owned_rights: OwnedRightsInner,
        public_rights: PublicRightsInner,
    ) -> Self {
        Self {
            schema_id,
            chain,
            metadata,
            owned_rights: owned_rights.into(),
            public_rights: public_rights.into(),
        }
    }

    #[inline]
    pub fn contract_id(&self) -> ContractId { ContractId::from_inner(self.node_id().into_inner()) }

    #[inline]
    pub fn schema_id(&self) -> SchemaId { self.schema_id }

    #[inline]
    pub fn chain(&self) -> &Chain { &self.chain }
}

impl Extension {
    pub fn with(
        extension_type: ExtensionType,
        contract_id: ContractId,
        metadata: Metadata,
        owned_rights: OwnedRights,
        parent_public_rights: ParentPublicRights,
        public_rights: PublicRights,
    ) -> Self {
        Self {
            extension_type,
            contract_id,
            metadata,
            parent_public_rights,
            owned_rights,
            public_rights,
        }
    }
}

impl Transition {
    pub fn with(
        transition_type: impl Into<schema::TransitionType>,
        metadata: Metadata,
        parent_public_rights: ParentPublicRights,
        owned_rights: OwnedRights,
        public_rights: PublicRights,
        parent_owned_rights: ParentOwnedRights,
    ) -> Self {
        Self {
            transition_type: transition_type.into(),
            metadata,
            parent_public_rights,
            parent_owned_rights,
            owned_rights,
            public_rights,
        }
    }

    pub fn transition_type(&self) -> schema::TransitionType { self.transition_type }
}

#[cfg(test)]
mod test {
    use std::io::Write;

    use bitcoin_hashes::hex::ToHex;
    use commit_verify::{tagged_hash, CommitConceal, TaggedHash};
    use lnpbp::chain::{Chain, GENESIS_HASH_MAINNET};
    use strict_encoding::{strict_serialize, StrictDecode, StrictEncode};
    use strict_encoding_test::test_vec_decoding_roundtrip;

    use super::*;

    #[test]
    fn test_node_id_midstate() {
        let midstate = tagged_hash::Midstate::with(b"rgb:node");
        assert_eq!(midstate.into_inner().into_inner(), MIDSTATE_NODE_ID);
    }

    #[test]
    #[ignore]
    fn test_transition_node_id() {
        fn conceal_transition(transition: &mut Transition) {
            for (_, assignments) in transition.owned_rights_mut().iter_mut() {
                match assignments {
                    TypedAssignments::Void(set) => {
                        for assignment in set {
                            *assignment = assignment.commit_conceal();
                        }
                    }
                    TypedAssignments::Value(set) => {
                        for assignment in set {
                            *assignment = assignment.commit_conceal();
                        }
                    }
                    TypedAssignments::Data(set) => {
                        for assignment in set {
                            *assignment = assignment.commit_conceal();
                        }
                    }
                    TypedAssignments::Attachment(set) => {
                        for assignment in set {
                            *assignment = assignment.commit_conceal();
                        }
                    }
                }
            }
        }

        let transition = Transition::strict_decode(&TRANSITION[..]).unwrap();
        let mut concealed_transition = transition.clone();
        conceal_transition(&mut concealed_transition);

        assert_eq!(transition.node_id(), concealed_transition.node_id());
    }

    #[test]
    #[ignore]
    fn test_node_attributes() {
        let genesis = Genesis::strict_decode(&GENESIS[..]).unwrap();
        let transition = Transition::strict_decode(&TRANSITION[..]).unwrap();

        // Typeid/Nodeid test
        assert_eq!(
            genesis.node_id().to_hex(),
            "977e9d7344aec3f01aca1a05b3f328fe91aa252481433e7cd87b22dbb48cd01c"
        );
        assert_eq!(
            transition.node_id().to_hex(),
            "52776d37dfce78a3d075f8c79c2c40ed6d95d271c74f7aea910c17218255aa68"
        );

        assert_eq!(genesis.transition_type(), None);
        assert_eq!(transition.transition_type(), 10);

        // Ancestor test

        assert_eq!(genesis.parent_owned_rights(), &ParentOwnedRights::default());

        let ancestor_trn = transition.parent_owned_rights();
        let assignments = ancestor_trn
            .get(
                &NodeId::from_hex(
                    "060ef58d940a75e43d139d55a5e4d3264dc9eb4f773bffc5729019e47ed27ef5",
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(
            assignments.get(&1u16).unwrap(),
            &[1u16, 2u16, 3u16, 4u16, 5u16].to_vec()
        );
        assert_eq!(
            assignments.get(&2u16).unwrap(),
            &[10u16, 20u16, 30u16, 40u16, 50u16].to_vec()
        );
        assert_eq!(
            assignments.get(&3u16).unwrap(),
            &[100u16, 200u16, 300u16, 400u16, 500u16].to_vec()
        );

        // Metadata test

        let gen_meta = genesis.metadata();

        let tran_meta = transition.metadata();

        assert_eq!(gen_meta, tran_meta);

        let u8_from_gen = gen_meta.u8(13 as schema::FieldType);

        assert_eq!(u8_from_gen, [2u8, 3u8].to_vec());

        let string_from_tran = tran_meta.unicode_string(13 as schema::FieldType);

        assert_eq!(string_from_tran[0], "One Random String".to_string());

        // Assignments test

        let gen_assignments = genesis.owned_rights();
        let tran_assingmnets = transition.owned_rights();

        assert_eq!(gen_assignments, tran_assingmnets);

        assert!(gen_assignments.get(&1u16).unwrap().is_declarative());
        assert!(gen_assignments.get(&2u16).unwrap().has_value());
        assert!(tran_assingmnets.get(&3u16).unwrap().has_data());

        let seal1 = gen_assignments
            .get(&2u16)
            .unwrap()
            .revealed_seal_at(1)
            .unwrap()
            .unwrap();

        let txid = seal1.txid.unwrap();

        assert_eq!(
            txid.to_hex(),
            "201fdd1e2b62d7b6938271295118ee181f1bac5e57d9f4528925650d36d3af8e".to_string()
        );

        let seal2 = tran_assingmnets
            .get(&3u16)
            .unwrap()
            .revealed_seal_at(1)
            .unwrap()
            .unwrap();

        let txid = seal2.txid.unwrap();

        assert_eq!(
            txid.to_hex(),
            "f57ed27ee4199072c5ff3b774febc94d26d3e4a5559d133de4750a948df50e06".to_string()
        );

        // Field Types
        let gen_fields = genesis.field_types();
        let tran_fields = transition.field_types();

        assert_eq!(gen_fields, tran_fields);

        assert_eq!(gen_fields, vec![13u16]);

        // Assignment types
        let gen_ass_types = genesis.owned_right_types();
        let tran_ass_types = transition.owned_right_types();

        assert_eq!(gen_ass_types, tran_ass_types);

        assert_eq!(gen_ass_types, bset![1u16, 2, 3]);

        // assignment by types
        let assignment_gen = genesis.owned_rights_by_type(3).unwrap();
        let assignment_tran = transition.owned_rights_by_type(1).unwrap();

        assert!(assignment_gen.has_data());
        assert!(assignment_tran.is_declarative());

        // All seal confidentials
        let gen_seals = genesis.to_confiential_seals();
        let tran_seals = transition.to_confiential_seals();

        assert_eq!(gen_seals, tran_seals);

        assert_eq!(
            gen_seals[0].to_hex(),
            "6b3c1bee0bd431f53e6c099890fdaf51b8556a6dcd61c6150ca055d0e1d4a524".to_string()
        );
        assert_eq!(
            tran_seals[3].to_hex(),
            "58f3ea4817a12aa6f1007d5b3d24dd2940ce40f8498029e05f1dc6465b3d65b4".to_string()
        );

        // Known seals
        let known_gen_seals = genesis.filter_revealed_seals();
        let known_seals_tran = transition.filter_revealed_seals();

        assert_eq!(known_gen_seals, known_seals_tran);

        let txid1 = known_gen_seals[2].txid.unwrap();

        let txid2 = known_gen_seals[3].txid.unwrap();

        assert_eq!(
            txid1.to_hex(),
            "f57ed27ee4199072c5ff3b774febc94d26d3e4a5559d133de4750a948df50e06".to_string()
        );
        assert_eq!(
            txid2.to_hex(),
            "201fdd1e2b62d7b6938271295118ee181f1bac5e57d9f4528925650d36d3af8e".to_string()
        );

        // Known seals by type
        let dec_gen_seals = genesis.filter_revealed_seals_by_type(1);
        let hash_tran_seals = transition.filter_revealed_seals_by_type(3);

        let txid1 = dec_gen_seals[0].txid.unwrap();

        assert_eq!(
            txid1.to_hex(),
            "f57ed27ee4199072c5ff3b774febc94d26d3e4a5559d133de4750a948df50e06".to_string()
        );

        let txid2 = hash_tran_seals[1].txid.unwrap();

        assert_eq!(
            txid2.to_hex(),
            "201fdd1e2b62d7b6938271295118ee181f1bac5e57d9f4528925650d36d3af8e".to_string()
        );
    }

    #[test]
    #[ignore]
    fn test_autoconceal_node() {
        let mut genesis = Genesis::strict_decode(&GENESIS[..]).unwrap();
        let mut transition = Transition::strict_decode(&TRANSITION[..]).unwrap();

        assert_eq!(
            genesis.clone().consensus_commit(),
            NodeId::from_hex("977e9d7344aec3f01aca1a05b3f328fe91aa252481433e7cd87b22dbb48cd01c")
                .unwrap()
        );
        assert_eq!(
            transition.clone().consensus_commit(),
            NodeId::from_hex("52776d37dfce78a3d075f8c79c2c40ed6d95d271c74f7aea910c17218255aa68")
                .unwrap()
        );

        genesis.conceal_state();
        transition.conceal_state();

        assert_eq!(
            genesis.clone().consensus_commit(),
            NodeId::from_hex("977e9d7344aec3f01aca1a05b3f328fe91aa252481433e7cd87b22dbb48cd01c")
                .unwrap()
        );
        assert_eq!(
            transition.clone().consensus_commit(),
            NodeId::from_hex("52776d37dfce78a3d075f8c79c2c40ed6d95d271c74f7aea910c17218255aa68")
                .unwrap()
        );
    }

    #[test]
    #[ignore]
    #[cfg(feature = "serde")]
    fn test_id_serde() {
        let genesis: Genesis = Genesis::strict_decode(&GENESIS[..]).unwrap();
        let contract_id = genesis.contract_id();
        assert_eq!(
            contract_id.to_string(),
            "rgb1rnggedxmyfaaslp7gwqjgfd2j8lz3uanq5dv5xhscwhyguua06tskhgfdg"
        );
        assert_eq!(
            serde_json::to_string(&contract_id).unwrap(),
            "\"rgb1rnggedxmyfaaslp7gwqjgfd2j8lz3uanq5dv5xhscwhyguua06tskhgfdg\""
        );
    }

    #[test]
    #[ignore]
    fn test_genesis_impl() {
        let genesis: Genesis = Genesis::strict_decode(&GENESIS[..]).unwrap();

        let contractid = genesis.contract_id();
        let schemaid = genesis.schema_id();
        let chain = genesis.chain();

        assert_eq!(
            contractid,
            ContractId::from_hex(
                "977e9d7344aec3f01aca1a05b3f328fe91aa252481433e7cd87b22dbb48cd01c"
            )
            .unwrap()
        );
        assert_eq!(
            schemaid,
            SchemaId::from_hex("8eafd3360d65258952f4d9575eac1b1f18ee185129718293b6d7622b1edd1f20")
                .unwrap()
        );
        assert_eq!(chain, &Chain::Mainnet);
    }
}

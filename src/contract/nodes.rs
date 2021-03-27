// LNP/BP Rust Library
// Written in 2020 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the MIT License
// along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

use std::collections::{BTreeMap, BTreeSet};
use std::io;

use amplify::{AsAny, Wrapper};
use bitcoin::hashes::{sha256, sha256t, Hash};

use lnpbp::client_side_validation::{
    commit_strategy, CommitEncode, CommitEncodeWithStrategy, ConsensusCommit,
    ToMerkleSource,
};
use lnpbp::commit_verify::CommitVerify;
use lnpbp::lnpbp4::ProtocolId;
use lnpbp::{Chain, TaggedHash};

use super::{
    AssignmentVec, ConcealSeals, ConcealState, OwnedRights, OwnedRightsInner,
    ParentOwnedRights, ParentPublicRights, ParentPublicRightsInner,
    PublicRights, PublicRightsInner,
};
use crate::contract::assignments::NodeOutput;
use crate::reveal::{self, RevealedByMerge};
use crate::schema::{
    ExtensionType, FieldType, NodeType, OwnedRightType, TransitionType,
};
#[cfg(feature = "serde")]
use crate::Bech32;
use crate::{
    schema, seal, ConfidentialDataError, Metadata, PublicRightType, SchemaId,
    ToBech32,
};

/// Midstate for a tagged hash engine. Equals to a single SHA256 hash of
/// the value of two concatenated SHA256 hashes for `rgb:node` prefix string.
static MIDSTATE_NODE_ID: [u8; 32] = [
    0x90, 0xd0, 0xc4, 0x9b, 0xa6, 0xb8, 0xa, 0x5b, 0xbc, 0xba, 0x19, 0x9, 0xdc,
    0xbd, 0x5a, 0x58, 0x55, 0x6a, 0xe2, 0x16, 0xa5, 0xee, 0xb7, 0x3c, 0x1,
    0xe0, 0x86, 0x91, 0x22, 0x43, 0x12, 0x9f,
];

/// Tag used for [`NodeId`] and [`ContractId`] hash types
pub struct NodeIdTag;

impl sha256t::Tag for NodeIdTag {
    #[inline]
    fn engine() -> sha256::HashEngine {
        let midstate = sha256::Midstate::from_inner(MIDSTATE_NODE_ID);
        sha256::HashEngine::from_midstate(midstate, 64)
    }
}

// TODO #48: Refactor all ids into a single style after `ConsignmentId`
/// Unique node (genesis, extensions & state transition) identifier equivalent
/// to the commitment hash
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(
    Wrapper, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, From,
)]
#[wrapper(
    Debug, Display, LowerHex, Index, IndexRange, IndexFrom, IndexTo, IndexFull
)]
pub struct NodeId(sha256t::Hash<NodeIdTag>);

impl<MSG> CommitVerify<MSG> for NodeId
where
    MSG: AsRef<[u8]>,
{
    #[inline]
    fn commit(msg: &MSG) -> NodeId {
        NodeId::hash(msg)
    }
}

impl CommitEncodeWithStrategy for NodeId {
    type Strategy = commit_strategy::UsingStrict;
}

/// Unique contract identifier equivalent to the contract genesis commitment
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", try_from = "Bech32", into = "Bech32")
)]
#[derive(
    Wrapper,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    Display,
    From,
)]
#[wrapper(Debug, LowerHex, Index, IndexRange, IndexFrom, IndexTo, IndexFull)]
#[display(ContractId::to_bech32_string)]
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

impl From<ContractId> for lnpbp::chain::AssetId {
    fn from(id: ContractId) -> Self {
        Self::from_inner(id.into_inner().into_inner())
    }
}

impl CommitEncodeWithStrategy for ContractId {
    type Strategy = commit_strategy::UsingStrict;
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
    fn field_types(&self) -> Vec<FieldType> {
        self.metadata().keys().copied().collect()
    }

    #[inline]
    fn parent_public_right_types(&self) -> Vec<PublicRightType> {
        self.parent_public_rights()
            .values()
            .map(BTreeSet::iter)
            .flatten()
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
    fn parent_outputs(&self) -> Vec<NodeOutput> {
        self.parent_owned_rights()
            .iter()
            .map(|(node_id, map)| {
                let node_id = *node_id;
                map.values()
                    .flatten()
                    .copied()
                    .map(move |output_no| NodeOutput { node_id, output_no })
            })
            .flatten()
            .collect()
    }

    #[inline]
    fn parent_outputs_by_type(&self, t: OwnedRightType) -> Vec<NodeOutput> {
        self.parent_outputs_by_types(&[t])
    }

    fn parent_outputs_by_types(
        &self,
        types: &[OwnedRightType],
    ) -> Vec<NodeOutput> {
        self.parent_owned_rights()
            .iter()
            .map(|(node_id, map)| {
                let node_id = *node_id;
                map.iter()
                    .filter(|(t, _)| types.contains(*t))
                    .map(|(_, outputs)| outputs)
                    .flatten()
                    .copied()
                    .map(move |output_no| NodeOutput { node_id, output_no })
            })
            .flatten()
            .collect()
    }

    #[inline]
    fn parent_owned_right_types(&self) -> Vec<OwnedRightType> {
        self.parent_owned_rights()
            .values()
            .map(BTreeMap::keys)
            .flatten()
            .copied()
            .collect()
    }

    #[inline]
    fn owned_right_types(&self) -> BTreeSet<OwnedRightType> {
        self.owned_rights().keys().cloned().collect()
    }

    #[inline]
    fn owned_rights_by_type(
        &self,
        t: OwnedRightType,
    ) -> Option<&AssignmentVec> {
        self.owned_rights().iter().find_map(|(t2, a)| {
            if *t2 == t {
                Some(a)
            } else {
                None
            }
        })
    }

    #[inline]
    fn to_confiential_seals(&self) -> Vec<seal::Confidential> {
        self.owned_rights()
            .iter()
            .flat_map(|(_, assignment)| assignment.to_confidential_seals())
            .collect()
    }

    #[inline]
    fn revealed_seals(
        &self,
    ) -> Result<Vec<seal::Revealed>, ConfidentialDataError> {
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
            .map(Vec::into_iter)
            .flatten()
            .collect())
    }

    #[inline]
    fn revealed_seals_by_type(
        &self,
        assignment_type: OwnedRightType,
    ) -> Result<Vec<seal::Revealed>, ConfidentialDataError> {
        Ok(self
            .owned_rights_by_type(assignment_type)
            .map(AssignmentVec::revealed_seals)
            .transpose()?
            .unwrap_or(vec![]))
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
            .map(AssignmentVec::filter_revealed_seals)
            .unwrap_or(vec![])
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Default, AsAny)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub struct Genesis {
    schema_id: SchemaId,
    chain: Chain,
    metadata: Metadata,
    owned_rights: OwnedRights,
    public_rights: PublicRights,
}

#[derive(
    Clone, PartialEq, Eq, Debug, Default, StrictEncode, StrictDecode, AsAny,
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub struct Extension {
    extension_type: ExtensionType,
    contract_id: ContractId,
    metadata: Metadata,
    parent_public_rights: ParentPublicRights,
    owned_rights: OwnedRights,
    public_rights: PublicRights,
}

#[derive(
    Clone, PartialEq, Eq, Debug, Default, StrictEncode, StrictDecode, AsAny,
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub struct Transition {
    transition_type: TransitionType,
    metadata: Metadata,
    parent_owned_rights: ParentOwnedRights,
    owned_rights: OwnedRights,
    public_rights: PublicRights,
}

impl ConsensusCommit for Genesis {
    type Commitment = NodeId;
}

impl ConsensusCommit for Extension {
    type Commitment = NodeId;
}

impl ConsensusCommit for Transition {
    type Commitment = NodeId;
}

impl CommitEncode for Extension {
    fn commit_encode<E: io::Write>(&self, mut e: E) -> usize {
        let mut len = self.extension_type.commit_encode(&mut e);
        len += self.contract_id.commit_encode(&mut e);
        len += self
            .metadata
            .to_merkle_source()
            .consensus_commit()
            .commit_encode(&mut e);
        len += self
            .parent_public_rights
            .to_merkle_source()
            .consensus_commit()
            .commit_encode(&mut e);
        len += self
            .owned_rights
            .to_merkle_source()
            .consensus_commit()
            .commit_encode(&mut e);
        len += self
            .public_rights
            .to_merkle_source()
            .consensus_commit()
            .commit_encode(&mut e);
        len
    }
}

impl CommitEncode for Transition {
    fn commit_encode<E: io::Write>(&self, mut e: E) -> usize {
        let mut len = self.transition_type.commit_encode(&mut e);
        len += self
            .metadata
            .to_merkle_source()
            .consensus_commit()
            .commit_encode(&mut e);
        len += self
            .parent_owned_rights
            .to_merkle_source()
            .consensus_commit()
            .commit_encode(&mut e);
        len += self
            .owned_rights
            .to_merkle_source()
            .consensus_commit()
            .commit_encode(&mut e);
        len += self
            .public_rights
            .to_merkle_source()
            .consensus_commit()
            .commit_encode(&mut e);
        len
    }
}

impl ConcealState for Genesis {
    fn conceal_state_except(
        &mut self,
        seals: &Vec<seal::Confidential>,
    ) -> usize {
        let mut count = 0;
        for (_, assignment) in self.owned_rights_mut().iter_mut() {
            count += assignment.conceal_state_except(seals);
        }
        count
    }
}

impl ConcealState for Extension {
    fn conceal_state_except(
        &mut self,
        seals: &Vec<seal::Confidential>,
    ) -> usize {
        let mut count = 0;
        for (_, assignment) in self.owned_rights_mut().iter_mut() {
            count += assignment.conceal_state_except(seals);
        }
        count
    }
}

impl ConcealState for Transition {
    fn conceal_state_except(
        &mut self,
        seals: &Vec<seal::Confidential>,
    ) -> usize {
        let mut count = 0;
        for (_, assignment) in self.owned_rights_mut().iter_mut() {
            count += assignment.conceal_state_except(seals);
        }
        count
    }
}

impl ConcealSeals for Transition {
    fn conceal_seals(&mut self, seals: &Vec<seal::Confidential>) -> usize {
        let mut count = 0;
        for (_, assignment) in self.owned_rights_mut().iter_mut() {
            count += assignment.conceal_seals(seals);
        }
        count
    }
}

impl RevealedByMerge for Genesis {
    fn revealed_by_merge(mut self, other: Self) -> Result<Self, reveal::Error> {
        if self.consensus_commit() != other.consensus_commit() {
            return Err(reveal::Error::NodeMismatch(NodeType::Genesis));
        }
        self.owned_rights =
            self.owned_rights.revealed_by_merge(other.owned_rights)?;
        Ok(self)
    }
}

impl RevealedByMerge for Transition {
    fn revealed_by_merge(mut self, other: Self) -> Result<Self, reveal::Error> {
        if self.consensus_commit() != other.consensus_commit() {
            return Err(reveal::Error::NodeMismatch(NodeType::StateTransition));
        }
        self.owned_rights =
            self.owned_rights.revealed_by_merge(other.owned_rights)?;
        Ok(self)
    }
}

impl RevealedByMerge for Extension {
    fn revealed_by_merge(mut self, other: Self) -> Result<Self, reveal::Error> {
        if self.consensus_commit() != other.consensus_commit() {
            return Err(reveal::Error::NodeMismatch(NodeType::StateExtension));
        }
        self.owned_rights =
            self.owned_rights.revealed_by_merge(other.owned_rights)?;
        Ok(self)
    }
}

impl Node for Genesis {
    #[inline]
    fn node_type(&self) -> NodeType {
        NodeType::Genesis
    }

    #[inline]
    fn node_id(&self) -> NodeId {
        self.clone().consensus_commit()
    }

    #[inline]
    fn contract_id(&self) -> Option<ContractId> {
        Some(ContractId::from_inner(self.node_id().into_inner()))
    }

    #[inline]
    fn transition_type(&self) -> Option<schema::TransitionType> {
        None
    }

    #[inline]
    fn extension_type(&self) -> Option<usize> {
        None
    }

    #[inline]
    fn parent_owned_rights(&self) -> &ParentOwnedRights {
        lazy_static! {
            static ref PARENT_EMPTY: ParentOwnedRights =
                ParentOwnedRights::default();
        }
        &PARENT_EMPTY
    }

    #[inline]
    fn parent_public_rights(&self) -> &ParentPublicRights {
        lazy_static! {
            static ref PARENT_EMPTY: ParentPublicRights =
                ParentPublicRights::default();
        }
        &PARENT_EMPTY
    }

    #[inline]
    fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    #[inline]
    fn owned_rights(&self) -> &OwnedRights {
        &self.owned_rights
    }

    #[inline]
    fn owned_rights_mut(&mut self) -> &mut OwnedRights {
        &mut self.owned_rights
    }

    #[inline]
    fn public_rights(&self) -> &PublicRights {
        &self.public_rights
    }

    #[inline]
    fn public_rights_mut(&mut self) -> &mut PublicRights {
        &mut self.public_rights
    }
}

impl Node for Extension {
    #[inline]
    fn node_type(&self) -> NodeType {
        NodeType::StateExtension
    }

    #[inline]
    fn node_id(&self) -> NodeId {
        self.clone().consensus_commit()
    }

    #[inline]
    fn contract_id(&self) -> Option<ContractId> {
        Some(self.contract_id)
    }

    #[inline]
    fn transition_type(&self) -> Option<schema::TransitionType> {
        None
    }

    #[inline]
    fn extension_type(&self) -> Option<usize> {
        Some(self.extension_type)
    }

    #[inline]
    fn parent_owned_rights(&self) -> &ParentOwnedRights {
        lazy_static! {
            static ref PARENT_EMPTY: ParentOwnedRights =
                ParentOwnedRights::default();
        }
        &PARENT_EMPTY
    }

    #[inline]
    fn parent_public_rights(&self) -> &ParentPublicRights {
        &self.parent_public_rights
    }

    #[inline]
    fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    #[inline]
    fn owned_rights(&self) -> &OwnedRights {
        &self.owned_rights
    }

    #[inline]
    fn owned_rights_mut(&mut self) -> &mut OwnedRights {
        &mut self.owned_rights
    }

    #[inline]
    fn public_rights(&self) -> &PublicRights {
        &self.public_rights
    }

    #[inline]
    fn public_rights_mut(&mut self) -> &mut PublicRights {
        &mut self.public_rights
    }
}

impl Node for Transition {
    #[inline]
    fn node_type(&self) -> NodeType {
        NodeType::StateTransition
    }

    #[inline]
    fn node_id(&self) -> NodeId {
        self.clone().consensus_commit()
    }

    #[inline]
    fn contract_id(&self) -> Option<ContractId> {
        None
    }

    #[inline]
    fn transition_type(&self) -> Option<schema::TransitionType> {
        Some(self.transition_type)
    }

    #[inline]
    fn extension_type(&self) -> Option<usize> {
        None
    }

    #[inline]
    fn parent_owned_rights(&self) -> &ParentOwnedRights {
        &self.parent_owned_rights
    }

    #[inline]
    fn parent_public_rights(&self) -> &ParentPublicRights {
        lazy_static! {
            static ref PARENT_EMPTY: ParentPublicRights =
                ParentPublicRights::default();
        }
        &PARENT_EMPTY
    }

    #[inline]
    fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    #[inline]
    fn owned_rights(&self) -> &OwnedRights {
        &self.owned_rights
    }

    #[inline]
    fn owned_rights_mut(&mut self) -> &mut OwnedRights {
        &mut self.owned_rights
    }

    #[inline]
    fn public_rights(&self) -> &PublicRights {
        &self.public_rights
    }

    #[inline]
    fn public_rights_mut(&mut self) -> &mut PublicRights {
        &mut self.public_rights
    }
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
    pub fn contract_id(&self) -> ContractId {
        ContractId::from_inner(self.node_id().into_inner())
    }

    #[inline]
    pub fn schema_id(&self) -> SchemaId {
        self.schema_id
    }

    #[inline]
    pub fn chain(&self) -> &Chain {
        &self.chain
    }
}

impl Extension {
    pub fn with(
        extension_type: ExtensionType,
        contract_id: ContractId,
        metadata: Metadata,
        parent_public_rights: ParentPublicRightsInner,
        owned_rights: OwnedRightsInner,
        public_rights: PublicRightsInner,
    ) -> Self {
        Self {
            extension_type,
            contract_id,
            metadata,
            parent_public_rights: parent_public_rights.into(),
            owned_rights: owned_rights.into(),
            public_rights: public_rights.into(),
        }
    }
}

impl Transition {
    pub fn with(
        transition_type: schema::TransitionType,
        metadata: Metadata,
        parent_owned_rights: ParentOwnedRights,
        owned_rights: OwnedRights,
        public_rights: PublicRights,
    ) -> Self {
        Self {
            transition_type,
            metadata,
            parent_owned_rights,
            owned_rights,
            public_rights,
        }
    }

    pub fn transition_type(&self) -> schema::TransitionType {
        self.transition_type
    }
}

mod _strict_encoding {
    use super::*;
    use lnpbp::strict_encoding::{
        strategies, strict_deserialize, strict_serialize, Error, Strategy,
        StrictDecode, StrictEncode,
    };
    use std::io;

    impl Strategy for NodeId {
        type Strategy = strategies::Wrapped;
    }

    impl Strategy for ContractId {
        type Strategy = strategies::Wrapped;
    }

    // ![CONSENSUS-CRITICAL]: Commit encode is different for genesis from strict
    //                        encode since we only commit to chain genesis block
    //                        hash and not all chain parameters.
    // See <https://github.com/LNP-BP/LNPBPs/issues/58> for details.
    impl CommitEncode for Genesis {
        fn commit_encode<E: io::Write>(&self, mut e: E) -> usize {
            let mut encoder = || -> Result<_, Error> {
                let mut len = self.schema_id.strict_encode(&mut e)?;
                len += self.chain.as_genesis_hash().strict_encode(&mut e)?;
                len += self
                    .metadata
                    .to_merkle_source()
                    .consensus_commit()
                    .commit_encode(&mut e);
                len += self
                    .owned_rights
                    .to_merkle_source()
                    .consensus_commit()
                    .commit_encode(&mut e);
                len += self
                    .public_rights
                    .to_merkle_source()
                    .consensus_commit()
                    .commit_encode(&mut e);
                Ok(len)
            };
            encoder().expect("Strict encoding of genesis data must not fail")
        }
    }

    impl StrictEncode for Genesis {
        fn strict_encode<E: io::Write>(
            &self,
            mut e: E,
        ) -> Result<usize, Error> {
            let chain_params = strict_serialize(&self.chain)?;
            Ok(strict_encode_list!(e;
                self.schema_id,
                // ![NETWORK-CRITICAL]: Chain params fields may update, so we
                //                      will serialize chain parameters in all
                //                      known/legacy formats for compatibility.
                //                      Thus, they are serialized as a vector
                //                      of byte strings, each one representing
                //                      a next version of chain parameters
                //                      representation.
                // <https://github.com/LNP-BP/rust-lnpbp/issues/114>
                1usize,
                chain_params,
                self.metadata,
                self.owned_rights,
                self.public_rights
            ))
        }
    }

    impl StrictDecode for Genesis {
        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
            let schema_id = SchemaId::strict_decode(&mut d)?;
            let chain_params_no = usize::strict_decode(&mut d)?;
            if chain_params_no < 1 {
                Err(Error::ValueOutOfRange(
                    "genesis must contain at least one `chain_param` data structure",
                    1u128..(core::u16::MAX as u128),
                    0,
                ))?
            }
            let chain_data = Vec::<u8>::strict_decode(&mut d)?;
            let chain = strict_deserialize(&chain_data)?;
            for _ in 1..chain_params_no {
                // Ignoring the rest of chain parameters
                let _ = Vec::<u8>::strict_decode(&mut d)?;
            }
            let metadata = Metadata::strict_decode(&mut d)?;
            let assignments = OwnedRightsInner::strict_decode(&mut d)?;
            let valencies = PublicRightsInner::strict_decode(&mut d)?;
            Ok(Self {
                schema_id,
                chain,
                metadata,
                owned_rights: assignments.into(),
                public_rights: valencies.into(),
            })
        }
    }
}

#[cfg(test)]
mod test {
    use bitcoin::hashes::hex::ToHex;
    use std::io::Write;

    use super::*;
    use lnpbp::chain::{Chain, GENESIS_HASH_MAINNET};
    use lnpbp::client_side_validation::CommitConceal;
    use lnpbp::commit_verify::CommitVerify;
    use lnpbp::strict_encoding::{
        strict_serialize, StrictDecode, StrictEncode,
    };
    use lnpbp::tagged_hash;

    static TRANSITION: [u8; 2349] = include!("../../test/transition.in");
    static GENESIS: [u8; 2447] = include!("../../test/genesis.in");

    #[test]
    fn test_node_id_midstate() {
        let midstate = tagged_hash::Midstate::with(b"rgb:node");
        assert_eq!(**midstate, MIDSTATE_NODE_ID);
    }

    // Making sure that <https://github.com/LNP-BP/LNPBPs/issues/58>
    // is fulfilled and we do not occasionally commit to all chain
    // parameters (which may vary and change with time) in RGB contract id
    #[test]
    fn test_genesis_commit_ne_strict() {
        let genesis = Genesis {
            schema_id: Default::default(),
            chain: Chain::Mainnet,
            metadata: Default::default(),
            owned_rights: Default::default(),
            public_rights: Default::default(),
        };
        assert_ne!(
            strict_serialize(&genesis).unwrap(),
            genesis.clone().consensus_commit().to_vec()
        );

        let mut encoder = vec![];
        genesis.schema_id.strict_encode(&mut encoder).unwrap();
        encoder.write_all(GENESIS_HASH_MAINNET).unwrap();
        genesis
            .metadata
            .to_merkle_source()
            .consensus_commit()
            .commit_encode(&mut encoder);
        genesis
            .owned_rights
            .to_merkle_source()
            .consensus_commit()
            .commit_encode(&mut encoder);
        genesis
            .public_rights
            .to_merkle_source()
            .consensus_commit()
            .commit_encode(&mut encoder);
        assert_eq!(genesis.consensus_commit(), NodeId::commit(&encoder));

        let transition = Transition {
            transition_type: Default::default(),
            metadata: Default::default(),
            parent_owned_rights: Default::default(),
            owned_rights: Default::default(),
            public_rights: Default::default(),
        };

        // Strict encode
        let mut encoder = vec![];
        transition
            .transition_type
            .strict_encode(&mut encoder)
            .unwrap();
        transition.metadata.strict_encode(&mut encoder).unwrap();
        transition
            .parent_owned_rights
            .strict_encode(&mut encoder)
            .unwrap();
        transition.owned_rights.strict_encode(&mut encoder).unwrap();
        transition
            .public_rights
            .strict_encode(&mut encoder)
            .unwrap();

        let mut encoder1 = vec![];
        transition.clone().strict_encode(&mut encoder1).unwrap();

        assert_eq!(encoder, encoder1);

        // Commit encode
        let transition2 = transition.clone();
        let mut encoder2 = vec![];
        transition2.transition_type.commit_encode(&mut encoder2);
        transition2
            .metadata
            .to_merkle_source()
            .consensus_commit()
            .commit_encode(&mut encoder2);
        transition2
            .parent_owned_rights
            .to_merkle_source()
            .consensus_commit()
            .commit_encode(&mut encoder2);
        transition2
            .owned_rights
            .to_merkle_source()
            .consensus_commit()
            .commit_encode(&mut encoder2);
        transition2
            .public_rights
            .to_merkle_source()
            .consensus_commit()
            .commit_encode(&mut encoder2);

        let mut encoder3 = vec![];
        transition.clone().commit_encode(&mut encoder3);

        assert_eq!(encoder2, encoder3);
    }

    #[test]
    fn test_encoding_nodes() {
        test_encode!((GENESIS, Genesis));
        test_encode!((TRANSITION, Transition));
    }

    #[test]
    fn test_transition_node_id() {
        fn conceal_transition(transition: &mut Transition) {
            for (_, assignments) in transition.owned_rights_mut().iter_mut() {
                match assignments {
                    AssignmentVec::Declarative(set) => {
                        for assignment in set {
                            *assignment = assignment.commit_conceal();
                        }
                    }
                    AssignmentVec::DiscreteFiniteField(set) => {
                        for assignment in set {
                            *assignment = assignment.commit_conceal();
                        }
                    }
                    AssignmentVec::CustomData(set) => {
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
    fn test_node_attributes() {
        let genesis = Genesis::strict_decode(&GENESIS[..]).unwrap();
        let transition = Transition::strict_decode(&TRANSITION[..]).unwrap();

        // Typeid/Nodeid test
        assert_eq!(
            genesis.node_id().to_hex(),
            "eb6791eed7d194e286c3d06f9a9437cac16568acf3cb9fdef8007790a16df34f"
        );
        assert_eq!(
            transition.node_id().to_hex(),
            "afd41355c98d349161e6dfc0b075370f12360b111c9b0305081f77f8e85d636f"
        );

        assert_eq!(genesis.transition_type(), None);
        assert_eq!(transition.transition_type(), 10);

        // Ancestor test

        assert_eq!(
            genesis.parent_owned_rights(),
            &ParentOwnedRights::default()
        );

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
            assignments.get(&1usize).unwrap(),
            &[1u16, 2u16, 3u16, 4u16, 5u16].to_vec()
        );
        assert_eq!(
            assignments.get(&2usize).unwrap(),
            &[10u16, 20u16, 30u16, 40u16, 50u16].to_vec()
        );
        assert_eq!(
            assignments.get(&3usize).unwrap(),
            &[100u16, 200u16, 300u16, 400u16, 500u16].to_vec()
        );

        // Metadata test

        let gen_meta = genesis.metadata();

        let tran_meta = transition.metadata();

        assert_eq!(gen_meta, tran_meta);

        let u8_from_gen = gen_meta.u8(13 as schema::FieldType);

        assert_eq!(u8_from_gen, [2u8, 3u8].to_vec());

        let string_from_tran = tran_meta.string(13 as schema::FieldType);

        assert_eq!(string_from_tran[0], "One Random String".to_string());

        // Assignments test

        let gen_assignments = genesis.owned_rights();
        let tran_assingmnets = transition.owned_rights();

        assert_eq!(gen_assignments, tran_assingmnets);

        assert!(gen_assignments.get(&1usize).unwrap().is_declarative());
        assert!(gen_assignments.get(&2usize).unwrap().has_value());
        assert!(tran_assingmnets.get(&3usize).unwrap().has_data());

        let seal1 = gen_assignments
            .get(&2usize)
            .unwrap()
            .revealed_seal_at(1)
            .unwrap()
            .unwrap();

        let txid = match seal1 {
            super::seal::Revealed::TxOutpoint(op) => Some(op.txid),
            _ => None,
        }
        .unwrap();

        assert_eq!(
            txid.to_hex(),
            "201fdd1e2b62d7b6938271295118ee181f1bac5e57d9f4528925650d36d3af8e"
                .to_string()
        );

        let seal2 = tran_assingmnets
            .get(&3usize)
            .unwrap()
            .revealed_seal_at(1)
            .unwrap()
            .unwrap();

        let txid = match seal2 {
            super::seal::Revealed::TxOutpoint(op) => Some(op.txid),
            _ => None,
        }
        .unwrap();

        assert_eq!(
            txid.to_hex(),
            "f57ed27ee4199072c5ff3b774febc94d26d3e4a5559d133de4750a948df50e06"
                .to_string()
        );

        // Field Types
        let gen_fields = genesis.field_types();
        let tran_fields = transition.field_types();

        assert_eq!(gen_fields, tran_fields);

        assert_eq!(gen_fields, vec![13usize]);

        // Assignment types
        let gen_ass_types = genesis.owned_right_types();
        let tran_ass_types = transition.owned_right_types();

        assert_eq!(gen_ass_types, tran_ass_types);

        assert_eq!(gen_ass_types, bset![1usize, 2, 3]);

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
            "6b3c1bee0bd431f53e6c099890fdaf51b8556a6dcd61c6150ca055d0e1d4a524"
                .to_string()
        );
        assert_eq!(
            tran_seals[3].to_hex(),
            "58f3ea4817a12aa6f1007d5b3d24dd2940ce40f8498029e05f1dc6465b3d65b4"
                .to_string()
        );

        // Known seals
        let known_gen_seals = genesis.filter_revealed_seals();
        let known_seals_tran = transition.filter_revealed_seals();

        assert_eq!(known_gen_seals, known_seals_tran);

        let txid1 = match known_gen_seals[2] {
            super::seal::Revealed::TxOutpoint(op) => Some(op.txid),
            _ => None,
        }
        .unwrap();

        let txid2 = match known_gen_seals[3] {
            super::seal::Revealed::TxOutpoint(op) => Some(op.txid),
            _ => None,
        }
        .unwrap();

        assert_eq!(
            txid1.to_hex(),
            "f57ed27ee4199072c5ff3b774febc94d26d3e4a5559d133de4750a948df50e06"
                .to_string()
        );
        assert_eq!(
            txid2.to_hex(),
            "201fdd1e2b62d7b6938271295118ee181f1bac5e57d9f4528925650d36d3af8e"
                .to_string()
        );

        // Known seals by type
        let dec_gen_seals = genesis.filter_revealed_seals_by_type(1);
        let hash_tran_seals = transition.filter_revealed_seals_by_type(3);

        let txid1 = match dec_gen_seals[0] {
            super::seal::Revealed::TxOutpoint(op) => Some(op.txid),
            _ => None,
        }
        .unwrap();

        assert_eq!(
            txid1.to_hex(),
            "f57ed27ee4199072c5ff3b774febc94d26d3e4a5559d133de4750a948df50e06"
                .to_string()
        );

        let txid2 = match hash_tran_seals[1] {
            super::seal::Revealed::TxOutpoint(op) => Some(op.txid),
            _ => None,
        }
        .unwrap();

        assert_eq!(
            txid2.to_hex(),
            "201fdd1e2b62d7b6938271295118ee181f1bac5e57d9f4528925650d36d3af8e"
                .to_string()
        );
    }

    #[test]
    fn test_autoconceal_node() {
        let mut genesis = Genesis::strict_decode(&GENESIS[..]).unwrap();
        let mut transition =
            Transition::strict_decode(&TRANSITION[..]).unwrap();

        assert_eq!(
            genesis.clone().consensus_commit(),
            NodeId::from_hex("eb6791eed7d194e286c3d06f9a9437cac16568acf3cb9fdef8007790a16df34f")
                .unwrap()
        );
        assert_eq!(
            transition.clone().consensus_commit(),
            NodeId::from_hex("afd41355c98d349161e6dfc0b075370f12360b111c9b0305081f77f8e85d636f")
                .unwrap()
        );

        genesis.conceal_state();
        transition.conceal_state();

        assert_eq!(
            genesis.clone().consensus_commit(),
            NodeId::from_hex("eb6791eed7d194e286c3d06f9a9437cac16568acf3cb9fdef8007790a16df34f")
                .unwrap()
        );
        assert_eq!(
            transition.clone().consensus_commit(),
            NodeId::from_hex("afd41355c98d349161e6dfc0b075370f12360b111c9b0305081f77f8e85d636f")
                .unwrap()
        );
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_id_serde() {
        let genesis: Genesis = Genesis::strict_decode(&GENESIS[..]).unwrap();
        let contract_id = genesis.contract_id();
        assert_eq!(
            contract_id.to_string(),
            "rgb1flekmgvswuq03h5le0e6c6r9c89r09y6dlgv8phzjnga0m53vl4smzrng6"
        );
        assert_eq!(
            serde_json::to_string(&contract_id).unwrap(),
            "\"rgb1flekmgvswuq03h5le0e6c6r9c89r09y6dlgv8phzjnga0m53vl4smzrng6\""
        );
    }

    #[test]
    fn test_genesis_impl() {
        let genesis: Genesis = Genesis::strict_decode(&GENESIS[..]).unwrap();

        let contractid = genesis.contract_id();
        let schemaid = genesis.schema_id();
        let chain = genesis.chain();

        assert_eq!(
            contractid,
            ContractId::from_hex(
                "eb6791eed7d194e286c3d06f9a9437cac16568acf3cb9fdef8007790a16df34f"
            )
            .unwrap()
        );
        assert_eq!(
            schemaid,
            SchemaId::from_hex("8eafd3360d65258952f4d9575eac1b1f18ee185129718293b6d7622b1edd1f20")
                .unwrap()
        );
        assert_eq!(chain, &lnpbp::Chain::Mainnet);
    }
}

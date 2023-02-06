// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2023 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2019-2023 Dr Maxim Orlovsky. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::cmp::Ordering;
use std::io::Write;
use std::str::FromStr;

use amplify::confinement::{TinyOrdMap, TinyOrdSet, TinyVec};
use amplify::hex::{FromHex, ToHex};
use amplify::{hex, AsAny, Bytes32, RawArray, Wrapper};
use baid58::{Baid58ParseError, FromBaid58, ToBaid58};
use bp::Chain;
use commit_verify::{mpc, CommitEncode, CommitStrategy, CommitmentId};
use strict_encoding::{StrictEncode, StrictWriter};

use super::{GlobalState, TypedState};
use crate::schema::{
    self, ExtensionType, OpFullType, OpType, OwnedStateType, SchemaId, TransitionType,
};
use crate::LIB_NAME_RGB;

/// RGB contract node output pointer, defined by the node ID and output number.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[display("{op}/{ty}/{no}")]
pub struct PrevAssignment {
    pub op: OpId,
    pub ty: OwnedStateType,
    pub no: u16,
}

impl PrevAssignment {
    pub fn new(op: OpId, ty: u16, no: u16) -> PrevAssignment { PrevAssignment { op, ty, no } }
}

pub type Valencies = TinyOrdSet<schema::ValencyType>;
pub type PrevState = TinyOrdMap<OpId, TinyOrdMap<schema::OwnedStateType, TinyVec<u16>>>;
pub type Redeemed = TinyOrdMap<OpId, TinyOrdSet<schema::ValencyType>>;

#[derive(Wrapper, Clone, PartialEq, Eq, Hash, Debug, Default, From)]
#[wrapper(Deref)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct OwnedState(TinyOrdMap<schema::OwnedStateType, TypedState>);

impl CommitEncode for OwnedState {
    fn commit_encode(&self, mut e: &mut impl Write) {
        let w = StrictWriter::with(u32::MAX as usize, &mut e);
        self.0.len_u8().strict_encode(w).ok();
        for (ty, state) in &self.0 {
            let w = StrictWriter::with(u32::MAX as usize, &mut e);
            ty.strict_encode(w).ok();
            state.commit_encode(e);
        }
    }
}

/// Unique node (genesis, extensions & state transition) identifier equivalent
/// to the commitment hash
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[display(Self::to_hex)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct OpId(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl FromStr for OpId {
    type Err = hex::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_hex(s) }
}

/// Unique contract identifier equivalent to the contract genesis commitment
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[display(Self::to_baid58)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct ContractId(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl ToBaid58<32> for ContractId {
    const HRI: &'static str = "rgb";
    fn to_baid58_payload(&self) -> [u8; 32] { self.to_raw_array() }
}
impl FromBaid58<32> for ContractId {}

impl FromStr for ContractId {
    type Err = Baid58ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_baid58_str(s) }
}

impl From<mpc::ProtocolId> for ContractId {
    fn from(id: mpc::ProtocolId) -> Self { ContractId(id.into_inner()) }
}

impl From<ContractId> for mpc::ProtocolId {
    fn from(id: ContractId) -> Self { mpc::ProtocolId::from_inner(id.into_inner()) }
}

/// RGB contract node API, defined as trait
///
/// Implemented by all contract node types (see [`OpType`]):
/// - Genesis ([`Genesis`])
/// - State transitions ([`Transitions`])
/// - Public state extensions ([`Extensions`])
pub trait Operation: AsAny {
    /// Returns type of the node (see [`OpType`]). Unfortunately, this can't
    /// be just a const, since it will break our ability to convert concrete
    /// `Node` types into `&dyn Node` (entities implementing traits with const
    /// definitions can't be made into objects)
    fn op_type(&self) -> OpType;

    /// Returns full contract node type information
    fn full_type(&self) -> OpFullType;

    /// Returns [`OpId`], which is a hash of this node commitment
    /// serialization
    fn id(&self) -> OpId;

    /// Returns [`Option::Some`]`(`[`ContractId`]`)`, which is a hash of
    /// genesis.
    /// - For genesis node, this hash is byte-equal to [`OpId`] (however
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

    /// Returns metadata associated with the operation, if any.
    fn metadata(&self) -> Option<&[u8]>;

    /// Returns reference to a full set of metadata (in form of [`GlobalState`]
    /// wrapper structure) for the contract node.
    fn global_state(&self) -> &GlobalState;

    /// Returns reference to information about the owned rights in form of
    /// [`PrevState`] wrapper structure which this node updates with
    /// state transition ("parent owned rights").
    ///
    /// This is always an empty `Vec` for [`Genesis`] and [`Extension`] node
    /// types.
    fn prev_state(&self) -> &PrevState;

    /// Returns reference to information about the public rights (in form of
    /// [`Redeemed`] wrapper structure), defined with "parent" state
    /// extensions (i.e. those finalized with the current state transition) or
    /// referenced by another state extension, which this node updates
    /// ("parent public rights").
    ///
    /// This is always an empty `Vec` for [`Genesis`].
    fn redeemed(&self) -> &Redeemed;
    fn owned_state(&self) -> &OwnedState;
    fn owned_state_mut(&mut self) -> &mut OwnedState;
    fn valencies(&self) -> &Valencies;
    fn valencies_mut(&mut self) -> &mut Valencies;

    fn owned_state_by_type(&self, t: OwnedStateType) -> Option<&TypedState> {
        self.owned_state()
            .iter()
            .find_map(|(t2, a)| if *t2 == t { Some(a) } else { None })
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, AsAny)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct Genesis {
    pub schema_id: SchemaId,
    pub chain: Chain,
    pub metadata: Option<TinyVec<u8>>,
    pub global_state: GlobalState,
    pub owned_state: OwnedState,
    pub valencies: Valencies,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, AsAny)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct Extension {
    pub extension_type: ExtensionType,
    pub contract_id: ContractId,
    pub metadata: Option<TinyVec<u8>>,
    pub global_state: GlobalState,
    pub owned_state: OwnedState,
    pub redeemed: Redeemed,
    pub valencies: Valencies,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, AsAny)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct Transition {
    pub transition_type: TransitionType,
    pub metadata: Option<TinyVec<u8>>,
    pub global_state: GlobalState,
    pub prev_state: PrevState,
    pub owned_state: OwnedState,
    pub valencies: Valencies,
}

// TODO: Remove after TransitionBundling refactoring
impl Ord for Transition {
    fn cmp(&self, other: &Self) -> Ordering { self.id().cmp(&other.id()) }
}

impl PartialOrd for Transition {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl CommitStrategy for Genesis {
    type Strategy = commit_verify::strategies::Strict;
}

impl CommitmentId for Genesis {
    const TAG: [u8; 32] = *b"urn:lnpbp:rgb:genesis:v01#202302";
    type Id = ContractId;
}

impl CommitStrategy for Transition {
    type Strategy = commit_verify::strategies::Strict;
}

impl CommitmentId for Transition {
    const TAG: [u8; 32] = *b"urn:lnpbp:rgb:transition:v01#32A";
    type Id = OpId;
}

impl CommitStrategy for Extension {
    type Strategy = commit_verify::strategies::Strict;
}

impl CommitmentId for Extension {
    const TAG: [u8; 32] = *b"urn:lnpbp:rgb:extension:v01#2023";
    type Id = OpId;
}

impl Operation for Genesis {
    #[inline]
    fn op_type(&self) -> OpType { OpType::Genesis }

    #[inline]
    fn full_type(&self) -> OpFullType { OpFullType::Genesis }

    #[inline]
    fn id(&self) -> OpId { OpId(self.commitment_id().into_inner()) }

    #[inline]
    fn contract_id(&self) -> Option<ContractId> {
        Some(ContractId::from_inner(self.id().into_inner()))
    }

    #[inline]
    fn transition_type(&self) -> Option<TransitionType> { None }

    #[inline]
    fn extension_type(&self) -> Option<ExtensionType> { None }

    #[inline]
    fn metadata(&self) -> Option<&[u8]> { self.metadata.as_ref().map(TinyVec::as_ref) }

    #[inline]
    fn global_state(&self) -> &GlobalState { &self.global_state }

    #[inline]
    fn prev_state(&self) -> &PrevState { panic!("genesis can't close previous single-use-seals") }

    #[inline]
    fn redeemed(&self) -> &Redeemed { panic!("genesis can't redeem valencies") }

    #[inline]
    fn owned_state(&self) -> &OwnedState { &self.owned_state }

    #[inline]
    fn owned_state_mut(&mut self) -> &mut OwnedState { &mut self.owned_state }

    #[inline]
    fn valencies(&self) -> &Valencies { &self.valencies }

    #[inline]
    fn valencies_mut(&mut self) -> &mut Valencies { &mut self.valencies }
}

impl Operation for Extension {
    #[inline]
    fn op_type(&self) -> OpType { OpType::StateExtension }

    #[inline]
    fn full_type(&self) -> OpFullType { OpFullType::StateExtension(self.extension_type) }

    #[inline]
    fn id(&self) -> OpId { self.commitment_id() }

    #[inline]
    fn contract_id(&self) -> Option<ContractId> { Some(self.contract_id) }

    #[inline]
    fn transition_type(&self) -> Option<TransitionType> { None }

    #[inline]
    fn extension_type(&self) -> Option<ExtensionType> { Some(self.extension_type) }

    #[inline]
    fn metadata(&self) -> Option<&[u8]> { self.metadata.as_ref().map(TinyVec::as_ref) }

    #[inline]
    fn global_state(&self) -> &GlobalState { &self.global_state }

    #[inline]
    fn prev_state(&self) -> &PrevState { panic!("extension can't close previous single-use-seals") }

    #[inline]
    fn redeemed(&self) -> &Redeemed { &self.redeemed }

    #[inline]
    fn owned_state(&self) -> &OwnedState { &self.owned_state }

    #[inline]
    fn owned_state_mut(&mut self) -> &mut OwnedState { &mut self.owned_state }

    #[inline]
    fn valencies(&self) -> &Valencies { &self.valencies }

    #[inline]
    fn valencies_mut(&mut self) -> &mut Valencies { &mut self.valencies }
}

impl Operation for Transition {
    #[inline]
    fn op_type(&self) -> OpType { OpType::StateTransition }

    #[inline]
    fn full_type(&self) -> OpFullType { OpFullType::StateTransition(self.transition_type) }

    #[inline]
    fn id(&self) -> OpId { self.commitment_id() }

    #[inline]
    fn contract_id(&self) -> Option<ContractId> { None }

    #[inline]
    fn transition_type(&self) -> Option<TransitionType> { Some(self.transition_type) }

    #[inline]
    fn extension_type(&self) -> Option<ExtensionType> { None }

    #[inline]
    fn metadata(&self) -> Option<&[u8]> { self.metadata.as_ref().map(TinyVec::as_ref) }

    #[inline]
    fn global_state(&self) -> &GlobalState { &self.global_state }

    #[inline]
    fn prev_state(&self) -> &PrevState { &self.prev_state }

    #[inline]
    fn redeemed(&self) -> &Redeemed { panic!("state transitions can't redeem valencies") }

    #[inline]
    fn owned_state(&self) -> &OwnedState { &self.owned_state }

    #[inline]
    fn owned_state_mut(&mut self) -> &mut OwnedState { &mut self.owned_state }

    #[inline]
    fn valencies(&self) -> &Valencies { &self.valencies }

    #[inline]
    fn valencies_mut(&mut self) -> &mut Valencies { &mut self.valencies }
}

impl Genesis {
    #[inline]
    pub fn contract_id(&self) -> ContractId { ContractId::from_inner(self.id().into_inner()) }
}

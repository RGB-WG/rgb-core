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

use amplify::confinement::{SmallBlob, TinyOrdMap, TinyOrdSet, TinyVec};
use amplify::hex::{FromHex, ToHex};
use amplify::{hex, AsAny, Bytes32, RawArray, Wrapper};
use baid58::{Baid58ParseError, FromBaid58, ToBaid58};
use bp::Chain;
use commit_verify::{mpc, CommitEncode, CommitStrategy, CommitmentId};
use strict_encoding::{StrictEncode, StrictWriter};

use super::{GlobalState, TypedAssigns};
use crate::schema::{
    self, ExtensionType, OpFullType, OpType, OwnedStateType, SchemaId, TransitionType,
};
use crate::{Ffv, LIB_NAME_RGB};

pub type Valencies = TinyOrdSet<schema::ValencyType>;
pub type PrevOuts = TinyOrdMap<OpId, TinyOrdMap<schema::OwnedStateType, TinyVec<u16>>>;
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
pub struct OwnedState(TinyOrdMap<schema::OwnedStateType, TypedAssigns>);

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

/// Unique operation (genesis, extensions & state transition) identifier
/// equivalent to the commitment hash
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

/// RGB contract operation API, defined as trait
///
/// Implemented by all contract operation types (see [`OpType`]):
/// - Genesis ([`Genesis`])
/// - State transitions ([`Transitions`])
/// - Public state extensions ([`Extensions`])
pub trait Operation: AsAny {
    /// Returns type of the operation (see [`OpType`]). Unfortunately, this
    /// can't be just a const, since it will break our ability to convert
    /// concrete `Node` types into `&dyn Node` (entities implementing traits
    /// with const definitions can't be made into objects)
    fn op_type(&self) -> OpType;

    /// Returns full contract operation type information
    fn full_type(&self) -> OpFullType;

    /// Returns [`OpId`], which is a hash of this operation commitment
    /// serialization
    fn id(&self) -> OpId;

    /// Returns [`Option::Some`]`(`[`TransitionType`]`)` for transitions or
    /// [`Option::None`] for genesis and extension operation types
    fn transition_type(&self) -> Option<TransitionType>;

    /// Returns [`Option::Some`]`(`[`ExtensionType`]`)` for extension nodes or
    /// [`Option::None`] for genesis and state transitions
    fn extension_type(&self) -> Option<ExtensionType>;

    /// Returns metadata associated with the operation, if any.
    fn metadata(&self) -> Option<&SmallBlob>;

    /// Returns reference to a full set of metadata (in form of [`GlobalState`]
    /// wrapper structure) for the contract operation.
    fn global_state(&self) -> &GlobalState;
    fn owned_state(&self) -> &OwnedState;
    fn valencies(&self) -> &Valencies;

    fn owned_state_by_type(&self, t: OwnedStateType) -> Option<&TypedAssigns> {
        self.owned_state()
            .iter()
            .find_map(|(t2, a)| if *t2 == t { Some(a) } else { None })
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, AsAny)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Genesis {
    pub ffv: Ffv,
    pub schema_id: SchemaId,
    pub chain: Chain,
    pub metadata: Option<SmallBlob>,
    pub global_state: GlobalState,
    pub owned_state: OwnedState,
    pub valencies: Valencies,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, AsAny)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Extension {
    pub ffv: Ffv,
    pub extension_type: ExtensionType,
    pub contract_id: ContractId,
    pub metadata: Option<SmallBlob>,
    pub global_state: GlobalState,
    pub owned_state: OwnedState,
    pub redeemed: Redeemed,
    pub valencies: Valencies,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, AsAny)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Transition {
    pub ffv: Ffv,
    pub transition_type: TransitionType,
    pub metadata: Option<SmallBlob>,
    pub global_state: GlobalState,
    pub prev_state: PrevOuts,
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

impl Genesis {
    #[inline]
    pub fn contract_id(&self) -> ContractId { ContractId::from_inner(self.id().into_inner()) }
}

impl Transition {
    /// Returns reference to information about the owned rights in form of
    /// [`PrevOuts`] wrapper structure which this operation updates with
    /// state transition ("parent owned rights").
    pub fn prev_state(&self) -> &PrevOuts { &self.prev_state }
}

impl Extension {
    #[inline]
    pub fn contract_id(&self) -> ContractId { self.contract_id }

    /// Returns reference to information about the public rights (in form of
    /// [`Redeemed`] wrapper structure), defined with "parent" state
    /// extensions (i.e. those finalized with the current state transition) or
    /// referenced by another state extension, which this operation updates
    /// ("parent public rights").
    pub fn redeemed(&self) -> &Redeemed { &self.redeemed }
}

impl Operation for Genesis {
    #[inline]
    fn op_type(&self) -> OpType { OpType::Genesis }

    #[inline]
    fn full_type(&self) -> OpFullType { OpFullType::Genesis }

    #[inline]
    fn id(&self) -> OpId { OpId(self.commitment_id().into_inner()) }

    #[inline]
    fn transition_type(&self) -> Option<TransitionType> { None }

    #[inline]
    fn extension_type(&self) -> Option<ExtensionType> { None }

    #[inline]
    fn metadata(&self) -> Option<&SmallBlob> { self.metadata.as_ref() }

    #[inline]
    fn global_state(&self) -> &GlobalState { &self.global_state }

    #[inline]
    fn owned_state(&self) -> &OwnedState { &self.owned_state }

    #[inline]
    fn valencies(&self) -> &Valencies { &self.valencies }
}

impl Operation for Extension {
    #[inline]
    fn op_type(&self) -> OpType { OpType::StateExtension }

    #[inline]
    fn full_type(&self) -> OpFullType { OpFullType::StateExtension(self.extension_type) }

    #[inline]
    fn id(&self) -> OpId { self.commitment_id() }

    #[inline]
    fn transition_type(&self) -> Option<TransitionType> { None }

    #[inline]
    fn extension_type(&self) -> Option<ExtensionType> { Some(self.extension_type) }

    #[inline]
    fn metadata(&self) -> Option<&SmallBlob> { self.metadata.as_ref() }

    #[inline]
    fn global_state(&self) -> &GlobalState { &self.global_state }

    #[inline]
    fn owned_state(&self) -> &OwnedState { &self.owned_state }

    #[inline]
    fn valencies(&self) -> &Valencies { &self.valencies }
}

impl Operation for Transition {
    #[inline]
    fn op_type(&self) -> OpType { OpType::StateTransition }

    #[inline]
    fn full_type(&self) -> OpFullType { OpFullType::StateTransition(self.transition_type) }

    #[inline]
    fn id(&self) -> OpId { self.commitment_id() }

    #[inline]
    fn transition_type(&self) -> Option<TransitionType> { Some(self.transition_type) }

    #[inline]
    fn extension_type(&self) -> Option<ExtensionType> { None }

    #[inline]
    fn metadata(&self) -> Option<&SmallBlob> { self.metadata.as_ref() }

    #[inline]
    fn global_state(&self) -> &GlobalState { &self.global_state }

    #[inline]
    fn owned_state(&self) -> &OwnedState { &self.owned_state }

    #[inline]
    fn valencies(&self) -> &Valencies { &self.valencies }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, AsAny)]
pub enum OpRef<'op> {
    Genesis(&'op Genesis),
    Transition(&'op Transition),
    Extension(&'op Extension),
}

impl<'op> Operation for OpRef<'op> {
    fn op_type(&self) -> OpType {
        match self {
            OpRef::Genesis(op) => op.op_type(),
            OpRef::Transition(op) => op.op_type(),
            OpRef::Extension(op) => op.op_type(),
        }
    }

    fn full_type(&self) -> OpFullType {
        match self {
            OpRef::Genesis(op) => op.full_type(),
            OpRef::Transition(op) => op.full_type(),
            OpRef::Extension(op) => op.full_type(),
        }
    }

    fn id(&self) -> OpId {
        match self {
            OpRef::Genesis(op) => op.id(),
            OpRef::Transition(op) => op.id(),
            OpRef::Extension(op) => op.id(),
        }
    }

    fn transition_type(&self) -> Option<TransitionType> {
        match self {
            OpRef::Genesis(op) => op.transition_type(),
            OpRef::Transition(op) => op.transition_type(),
            OpRef::Extension(op) => op.transition_type(),
        }
    }

    fn extension_type(&self) -> Option<ExtensionType> {
        match self {
            OpRef::Genesis(op) => op.extension_type(),
            OpRef::Transition(op) => op.extension_type(),
            OpRef::Extension(op) => op.extension_type(),
        }
    }

    fn metadata(&self) -> Option<&SmallBlob> {
        match self {
            OpRef::Genesis(op) => op.metadata(),
            OpRef::Transition(op) => op.metadata(),
            OpRef::Extension(op) => op.metadata(),
        }
    }

    fn global_state(&self) -> &GlobalState {
        match self {
            OpRef::Genesis(op) => op.global_state(),
            OpRef::Transition(op) => op.global_state(),
            OpRef::Extension(op) => op.global_state(),
        }
    }

    fn owned_state(&self) -> &OwnedState {
        match self {
            OpRef::Genesis(op) => op.owned_state(),
            OpRef::Transition(op) => op.owned_state(),
            OpRef::Extension(op) => op.owned_state(),
        }
    }

    fn valencies(&self) -> &Valencies {
        match self {
            OpRef::Genesis(op) => op.valencies(),
            OpRef::Transition(op) => op.valencies(),
            OpRef::Extension(op) => op.valencies(),
        }
    }
}

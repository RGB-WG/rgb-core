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
use std::str::FromStr;

use amplify::confinement::{SmallBlob, TinyOrdMap, TinyOrdSet};
use amplify::hex::{FromHex, ToHex};
use amplify::{hex, Bytes32, RawArray, Wrapper};
use baid58::{Baid58ParseError, FromBaid58, ToBaid58};
use bp::Chain;
use commit_verify::{mpc, CommitmentId, Conceal};
use strict_encoding::{StrictDeserialize, StrictEncode, StrictSerialize};

use crate::schema::{self, ExtensionType, OpFullType, OpType, SchemaId, TransitionType};
use crate::{
    AssignmentType, Assignments, AssignmentsRef, Ffv, GenesisSeal, GlobalState, GraphSeal, Opout,
    ReservedByte, TypedAssigns, LIB_NAME_RGB,
};

pub type Valencies = TinyOrdSet<schema::ValencyType>;
pub type Inputs = TinyOrdSet<Input>;
pub type Redeemed = TinyOrdMap<schema::ValencyType, OpId>;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[display("{prev_out}")]
pub struct Input {
    pub prev_out: Opout,
    reserved: ReservedByte,
}

impl Input {
    pub fn with(prev_out: Opout) -> Input {
        Input {
            prev_out,
            reserved: default!(),
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

impl OpId {
    pub fn from_slice(slice: impl AsRef<[u8]>) -> Option<Self> {
        Bytes32::from_slice(slice).map(Self)
    }
}

/// Unique contract identifier equivalent to the contract genesis commitment
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[display(Self::to_baid58_string)]
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

impl PartialEq<OpId> for ContractId {
    fn eq(&self, other: &OpId) -> bool { self.to_raw_array() == other.to_raw_array() }
}
impl PartialEq<ContractId> for OpId {
    fn eq(&self, other: &ContractId) -> bool { self.to_raw_array() == other.to_raw_array() }
}

impl ContractId {
    pub fn from_slice(slice: impl AsRef<[u8]>) -> Option<Self> {
        Bytes32::from_slice(slice).map(Self)
    }
}

impl ToBaid58<32> for ContractId {
    const HRI: &'static str = "rgb";
    fn to_baid58_payload(&self) -> [u8; 32] { self.to_raw_array() }
}
impl FromBaid58<32> for ContractId {}

impl ContractId {
    fn to_baid58_string(&self) -> String { format!("{:0}", self.to_baid58()) }
}

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
pub trait Operation {
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

    /// Returns [`ContractId`] this operation belongs to.
    fn contract_id(&self) -> ContractId;

    /// Returns [`Option::Some`]`(`[`TransitionType`]`)` for transitions or
    /// [`Option::None`] for genesis and extension operation types
    fn transition_type(&self) -> Option<TransitionType>;

    /// Returns [`Option::Some`]`(`[`ExtensionType`]`)` for extension nodes or
    /// [`Option::None`] for genesis and state transitions
    fn extension_type(&self) -> Option<ExtensionType>;

    /// Returns metadata associated with the operation, if any.
    fn metadata(&self) -> &SmallBlob;

    /// Returns reference to a full set of metadata (in form of [`GlobalState`]
    /// wrapper structure) for the contract operation.
    fn globals(&self) -> &GlobalState;
    fn valencies(&self) -> &Valencies;

    fn assignments(&self) -> AssignmentsRef;

    fn assignments_by_type(&self, t: AssignmentType) -> Option<TypedAssigns<GraphSeal>>;

    /// For genesis and public state extensions always returns an empty list.
    /// While public state extension do have parent nodes, they do not contain
    /// indexed rights.
    fn inputs(&self) -> Inputs;
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[derive(CommitEncode)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Genesis {
    pub ffv: Ffv,
    pub schema_id: SchemaId,
    pub chain: Chain,
    pub metadata: SmallBlob,
    pub globals: GlobalState,
    pub assignments: Assignments<GenesisSeal>,
    pub valencies: Valencies,
}

impl StrictSerialize for Genesis {}
impl StrictDeserialize for Genesis {}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[derive(CommitEncode)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Extension {
    pub ffv: Ffv,
    pub contract_id: ContractId,
    pub extension_type: ExtensionType,
    pub metadata: SmallBlob,
    pub globals: GlobalState,
    pub assignments: Assignments<GenesisSeal>,
    pub redeemed: Redeemed,
    pub valencies: Valencies,
}

impl StrictSerialize for Extension {}
impl StrictDeserialize for Extension {}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[derive(CommitEncode)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Transition {
    pub ffv: Ffv,
    pub contract_id: ContractId,
    pub transition_type: TransitionType,
    pub metadata: SmallBlob,
    pub globals: GlobalState,
    pub inputs: Inputs,
    pub assignments: Assignments<GraphSeal>,
    pub valencies: Valencies,
}

impl StrictSerialize for Transition {}
impl StrictDeserialize for Transition {}

// TODO: Remove after TransitionBundling refactoring
impl Ord for Transition {
    fn cmp(&self, other: &Self) -> Ordering { self.id().cmp(&other.id()) }
}

impl PartialOrd for Transition {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl Conceal for Genesis {
    type Concealed = Genesis;
    fn conceal(&self) -> Self::Concealed {
        let mut concealed = self.clone();
        concealed
            .assignments
            .keyed_values_mut()
            .for_each(|(_, a)| *a = a.conceal());
        concealed
    }
}

impl CommitmentId for Genesis {
    const TAG: [u8; 32] = *b"urn:lnpbp:rgb:genesis:v02#202304";
    type Id = ContractId;
}

impl Conceal for Transition {
    type Concealed = Transition;
    fn conceal(&self) -> Self::Concealed {
        let mut concealed = self.clone();
        concealed
            .assignments
            .keyed_values_mut()
            .for_each(|(_, a)| *a = a.conceal());
        concealed
    }
}

impl CommitmentId for Transition {
    const TAG: [u8; 32] = *b"urn:lnpbp:rgb:transition:v02#23B";
    type Id = OpId;
}

impl Conceal for Extension {
    type Concealed = Extension;
    fn conceal(&self) -> Self::Concealed {
        let mut concealed = self.clone();
        concealed
            .assignments
            .keyed_values_mut()
            .for_each(|(_, a)| *a = a.conceal());
        concealed
    }
}

impl CommitmentId for Extension {
    const TAG: [u8; 32] = *b"urn:lnpbp:rgb:extension:v02#2304";
    type Id = OpId;
}

impl Transition {
    /// Returns reference to information about the owned rights in form of
    /// [`Inputs`] wrapper structure which this operation updates with
    /// state transition ("parent owned rights").
    pub fn prev_state(&self) -> &Inputs { &self.inputs }
}

impl Extension {
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
    fn contract_id(&self) -> ContractId { ContractId::from_inner(self.id().into_inner()) }

    #[inline]
    fn transition_type(&self) -> Option<TransitionType> { None }

    #[inline]
    fn extension_type(&self) -> Option<ExtensionType> { None }

    #[inline]
    fn metadata(&self) -> &SmallBlob { &self.metadata }

    #[inline]
    fn globals(&self) -> &GlobalState { &self.globals }

    #[inline]
    fn valencies(&self) -> &Valencies { &self.valencies }

    #[inline]
    fn assignments(&self) -> AssignmentsRef { (&self.assignments).into() }

    #[inline]
    fn assignments_by_type(&self, t: AssignmentType) -> Option<TypedAssigns<GraphSeal>> {
        self.assignments
            .get(&t)
            .map(TypedAssigns::transmutate_seals)
    }

    #[inline]
    fn inputs(&self) -> Inputs { empty!() }
}

impl Operation for Extension {
    #[inline]
    fn op_type(&self) -> OpType { OpType::StateExtension }

    #[inline]
    fn full_type(&self) -> OpFullType { OpFullType::StateExtension(self.extension_type) }

    #[inline]
    fn id(&self) -> OpId { self.commitment_id() }

    #[inline]
    fn contract_id(&self) -> ContractId { self.contract_id }

    #[inline]
    fn transition_type(&self) -> Option<TransitionType> { None }

    #[inline]
    fn extension_type(&self) -> Option<ExtensionType> { Some(self.extension_type) }

    #[inline]
    fn metadata(&self) -> &SmallBlob { &self.metadata }

    #[inline]
    fn globals(&self) -> &GlobalState { &self.globals }

    #[inline]
    fn valencies(&self) -> &Valencies { &self.valencies }

    #[inline]
    fn assignments(&self) -> AssignmentsRef { (&self.assignments).into() }

    #[inline]
    fn assignments_by_type(&self, t: AssignmentType) -> Option<TypedAssigns<GraphSeal>> {
        self.assignments
            .get(&t)
            .map(TypedAssigns::transmutate_seals)
    }

    #[inline]
    fn inputs(&self) -> Inputs { empty!() }
}

impl Operation for Transition {
    #[inline]
    fn op_type(&self) -> OpType { OpType::StateTransition }

    #[inline]
    fn full_type(&self) -> OpFullType { OpFullType::StateTransition(self.transition_type) }

    #[inline]
    fn id(&self) -> OpId { self.commitment_id() }

    #[inline]
    fn contract_id(&self) -> ContractId { self.contract_id }

    #[inline]
    fn transition_type(&self) -> Option<TransitionType> { Some(self.transition_type) }

    #[inline]
    fn extension_type(&self) -> Option<ExtensionType> { None }

    #[inline]
    fn metadata(&self) -> &SmallBlob { &self.metadata }

    #[inline]
    fn globals(&self) -> &GlobalState { &self.globals }

    #[inline]
    fn valencies(&self) -> &Valencies { &self.valencies }

    #[inline]
    fn assignments(&self) -> AssignmentsRef { (&self.assignments).into() }

    #[inline]
    fn assignments_by_type(&self, t: AssignmentType) -> Option<TypedAssigns<GraphSeal>> {
        self.assignments.get(&t).cloned()
    }

    fn inputs(&self) -> Inputs { self.inputs.clone() }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, From)]
pub enum OpRef<'op> {
    #[from]
    Genesis(&'op Genesis),
    #[from]
    Transition(&'op Transition),
    #[from]
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

    fn contract_id(&self) -> ContractId {
        match self {
            OpRef::Genesis(op) => op.contract_id(),
            OpRef::Transition(op) => op.contract_id(),
            OpRef::Extension(op) => op.contract_id(),
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

    fn metadata(&self) -> &SmallBlob {
        match self {
            OpRef::Genesis(op) => op.metadata(),
            OpRef::Transition(op) => op.metadata(),
            OpRef::Extension(op) => op.metadata(),
        }
    }

    fn globals(&self) -> &GlobalState {
        match self {
            OpRef::Genesis(op) => op.globals(),
            OpRef::Transition(op) => op.globals(),
            OpRef::Extension(op) => op.globals(),
        }
    }

    fn valencies(&self) -> &Valencies {
        match self {
            OpRef::Genesis(op) => op.valencies(),
            OpRef::Transition(op) => op.valencies(),
            OpRef::Extension(op) => op.valencies(),
        }
    }

    fn assignments(&self) -> AssignmentsRef<'op> {
        match self {
            OpRef::Genesis(op) => (&op.assignments).into(),
            OpRef::Transition(op) => (&op.assignments).into(),
            OpRef::Extension(op) => (&op.assignments).into(),
        }
    }

    fn assignments_by_type(&self, t: AssignmentType) -> Option<TypedAssigns<GraphSeal>> {
        match self {
            OpRef::Genesis(op) => op.assignments_by_type(t),
            OpRef::Transition(op) => op.assignments_by_type(t),
            OpRef::Extension(op) => op.assignments_by_type(t),
        }
    }

    fn inputs(&self) -> Inputs {
        match self {
            OpRef::Genesis(op) => op.inputs(),
            OpRef::Transition(op) => op.inputs(),
            OpRef::Extension(op) => op.inputs(),
        }
    }
}

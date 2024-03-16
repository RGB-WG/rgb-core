// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2019-2024 Dr Maxim Orlovsky. All rights reserved.
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
use std::collections::{btree_map, btree_set, BTreeMap};
use std::iter;

use amplify::confinement::{Confined, SmallBlob, SmallOrdSet, TinyOrdMap, TinyOrdSet};
use amplify::Wrapper;
use commit_verify::{
    CommitEncode, CommitEngine, CommitId, Conceal, MerkleHash, MerkleLeaves, ReservedBytes,
    StrictHash,
};
use strict_encoding::{StrictDeserialize, StrictEncode, StrictSerialize};

use crate::schema::{self, ExtensionType, OpFullType, OpType, SchemaId, TransitionType};
use crate::{
    AltLayer1Set, Assign, AssignmentIndex, AssignmentType, Assignments, AssignmentsRef,
    ConcealedAttach, ConcealedData, ConcealedValue, ContractId, DiscloseHash, ExposedState, Ffv,
    GenesisSeal, GlobalState, GraphSeal, OpDisclose, OpId, Opout, SecretSeal, TypedAssigns,
    VoidState, XChain, LIB_NAME_RGB,
};

#[derive(
    Wrapper, WrapperMut, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Default, From
)]
#[display(LowerHex)]
#[wrapper(Deref, AsSlice, BorrowSlice, Hex)]
#[wrapper_mut(DerefMut)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = StrictHash)]
pub struct Metadata(SmallBlob);

#[cfg(feature = "serde")]
mod _serde {
    use amplify::hex::FromHex;
    use serde_crate::de::Error;
    use serde_crate::{Deserialize, Deserializer, Serialize, Serializer};

    use super::*;

    impl Serialize for Metadata {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer {
            serializer.serialize_str(&self.to_string())
        }
    }

    impl<'de> Deserialize<'de> for Metadata {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de> {
            let s = String::deserialize(deserializer)?;
            Self::from_hex(&s).map_err(D::Error::custom)
        }
    }
}

#[derive(Wrapper, WrapperMut, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default, From)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = StrictHash)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct Valencies(TinyOrdSet<schema::ValencyType>);

impl<'a> IntoIterator for &'a Valencies {
    type Item = schema::ValencyType;
    type IntoIter = iter::Copied<btree_set::Iter<'a, schema::ValencyType>>;

    fn into_iter(self) -> Self::IntoIter { self.0.iter().copied() }
}

#[derive(Wrapper, WrapperMut, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default, From)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = StrictHash)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct Redeemed(TinyOrdMap<schema::ValencyType, OpId>);

impl<'a> IntoIterator for &'a Redeemed {
    type Item = (&'a schema::ValencyType, &'a OpId);
    type IntoIter = btree_map::Iter<'a, schema::ValencyType, OpId>;

    fn into_iter(self) -> Self::IntoIter { self.0.iter() }
}

#[derive(Wrapper, WrapperMut, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default, From)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct Inputs(SmallOrdSet<Input>);

impl<'a> IntoIterator for &'a Inputs {
    type Item = Input;
    type IntoIter = iter::Copied<btree_set::Iter<'a, Input>>;

    fn into_iter(self) -> Self::IntoIter { self.0.iter().copied() }
}

impl MerkleLeaves for Inputs {
    type Leaf = Input;
    type LeafIter<'tmp> = <TinyOrdSet<Input> as MerkleLeaves>::LeafIter<'tmp>;

    fn merkle_leaves(&self) -> Self::LeafIter<'_> { self.0.merkle_leaves() }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = MerkleHash)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[display("{prev_out}")]
pub struct Input {
    pub prev_out: Opout,
    #[cfg_attr(feature = "serde", serde(skip))]
    reserved: ReservedBytes<2>,
}

impl Input {
    pub fn with(prev_out: Opout) -> Input {
        Input {
            prev_out,
            reserved: default!(),
        }
    }
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

    /// Provides summary about parts of the operation which are revealed.
    fn disclose(&self) -> OpDisclose {
        fn proc_seals<State: ExposedState>(
            ty: AssignmentType,
            a: &[Assign<State, GraphSeal>],
            seals: &mut BTreeMap<AssignmentIndex, XChain<SecretSeal>>,
            state: &mut BTreeMap<AssignmentIndex, State::Concealed>,
        ) {
            for (index, assignment) in a.iter().enumerate() {
                if let Some(seal) = assignment.revealed_seal() {
                    seals.insert(AssignmentIndex::new(ty, index as u16), seal.to_secret_seal());
                }
                if let Some(revealed) = assignment.as_revealed_state() {
                    state.insert(AssignmentIndex::new(ty, index as u16), revealed.conceal());
                }
            }
        }

        let mut seals: BTreeMap<AssignmentIndex, XChain<SecretSeal>> = bmap!();
        let mut void: BTreeMap<AssignmentIndex, VoidState> = bmap!();
        let mut fungible: BTreeMap<AssignmentIndex, ConcealedValue> = bmap!();
        let mut data: BTreeMap<AssignmentIndex, ConcealedData> = bmap!();
        let mut attach: BTreeMap<AssignmentIndex, ConcealedAttach> = bmap!();
        for (ty, assigns) in self.assignments().flat() {
            match assigns {
                TypedAssigns::Declarative(a) => {
                    proc_seals(ty, &a, &mut seals, &mut void);
                }
                TypedAssigns::Fungible(a) => {
                    proc_seals(ty, &a, &mut seals, &mut fungible);
                }
                TypedAssigns::Structured(a) => {
                    proc_seals(ty, &a, &mut seals, &mut data);
                }
                TypedAssigns::Attachment(a) => {
                    proc_seals(ty, &a, &mut seals, &mut attach);
                }
            }
        }

        OpDisclose {
            id: self.id(),
            seals: Confined::from_collection_unsafe(seals),
            fungible: Confined::from_iter_unsafe(
                fungible.into_iter().map(|(k, s)| (k, s.commitment)),
            ),
            data: Confined::from_collection_unsafe(data),
            attach: Confined::from_collection_unsafe(attach),
        }
    }

    fn disclose_hash(&self) -> DiscloseHash { self.disclose().commit_id() }
}

/// Issuer is a binary string which must be encoded into the issuer identity in
/// the application.
///
/// We deliberately do not define the internal structure of the identity such
/// that it can be updated without changes to the consensus level.
///
/// Contract validity doesn't assume any checks on the issuer identity; these
/// checks must be performed at the application level.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = StrictHash)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct Issuer(SmallBlob);

#[derive(Clone, PartialEq, Eq, Debug)]
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
    pub flags: ReservedBytes<1, 0>,
    pub timestamp: i64,
    pub testnet: bool,
    pub alt_layers1: AltLayer1Set,
    pub metadata: Metadata,
    pub globals: GlobalState,
    pub assignments: Assignments<GenesisSeal>,
    pub valencies: Valencies,
    pub issuer: Issuer,
    pub script: ReservedBytes<1, 0>,
}

impl StrictSerialize for Genesis {}
impl StrictDeserialize for Genesis {}

#[derive(Clone, PartialEq, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Extension {
    pub ffv: Ffv,
    pub contract_id: ContractId,
    pub extension_type: ExtensionType,
    pub metadata: Metadata,
    pub globals: GlobalState,
    pub assignments: Assignments<GenesisSeal>,
    pub redeemed: Redeemed,
    pub valencies: Valencies,
    pub witness: ReservedBytes<1, 0>,
    pub script: ReservedBytes<1, 0>,
}

impl StrictSerialize for Extension {}
impl StrictDeserialize for Extension {}

impl Ord for Extension {
    fn cmp(&self, other: &Self) -> Ordering { self.id().cmp(&other.id()) }
}

impl PartialOrd for Extension {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Transition {
    pub ffv: Ffv,
    pub contract_id: ContractId,
    pub transition_type: TransitionType,
    pub metadata: Metadata,
    pub globals: GlobalState,
    pub inputs: Inputs,
    pub assignments: Assignments<GraphSeal>,
    pub valencies: Valencies,
    pub witness: ReservedBytes<1, 0>,
    pub script: ReservedBytes<1, 0>,
}

impl StrictSerialize for Transition {}
impl StrictDeserialize for Transition {}

impl Ord for Transition {
    fn cmp(&self, other: &Self) -> Ordering { self.id().cmp(&other.id()) }
}

impl PartialOrd for Transition {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl Conceal for Genesis {
    type Concealed = Self;
    fn conceal(&self) -> Self::Concealed {
        let mut concealed = self.clone();
        concealed
            .assignments
            .keyed_values_mut()
            .for_each(|(_, a)| *a = a.conceal());
        concealed
    }
}

impl Conceal for Transition {
    type Concealed = Self;
    fn conceal(&self) -> Self::Concealed {
        let mut concealed = self.clone();
        concealed
            .assignments
            .keyed_values_mut()
            .for_each(|(_, a)| *a = a.conceal());
        concealed
    }
}

impl Conceal for Extension {
    type Concealed = Self;
    fn conceal(&self) -> Self::Concealed {
        let mut concealed = self.clone();
        concealed
            .assignments
            .keyed_values_mut()
            .for_each(|(_, a)| *a = a.conceal());
        concealed
    }
}

impl CommitEncode for Genesis {
    type CommitmentId = OpId;
    fn commit_encode(&self, e: &mut CommitEngine) { e.commit_to_serialized(&self.commit()) }
}

impl CommitEncode for Transition {
    type CommitmentId = OpId;
    fn commit_encode(&self, e: &mut CommitEngine) { e.commit_to_serialized(&self.commit()) }
}

impl CommitEncode for Extension {
    type CommitmentId = OpId;
    fn commit_encode(&self, e: &mut CommitEngine) { e.commit_to_serialized(&self.commit()) }
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
    fn id(&self) -> OpId { self.commit_id() }

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
    fn id(&self) -> OpId { self.commit_id() }

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
    fn id(&self) -> OpId { self.commit_id() }

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

#[derive(Copy, Clone, PartialEq, Eq, Debug, From)]
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

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use amplify::ByteArray;
    use baid58::ToBaid58;

    use super::*;

    #[test]
    fn contract_id_display() {
        const ID: &str = "rgb:pkXwpsb-aemTWhtSg-VDGF25hEi-jtTAnPjzh-B63ZwSehE-WvfhF9";
        let id = ContractId::from_byte_array([0x6c; 32]);
        assert_eq!(ID.len(), 58);
        assert_eq!(ID.replace('-', ""), format!("{id:#}"));
        assert_eq!(ID, id.to_string());
        assert_eq!(ID, id.to_baid58_string());
    }

    #[test]
    fn contract_id_from_str() {
        let id = ContractId::from_byte_array([0x6c; 32]);
        assert_eq!(
            Ok(id),
            ContractId::from_str("rgb:pkXwpsb-aemTWhtSg-VDGF25hEi-jtTAnPjzh-B63ZwSehE-WvfhF9")
        );
        assert_eq!(
            Ok(id),
            ContractId::from_str("pkXwpsb-aemTWhtSg-VDGF25hEi-jtTAnPjzh-B63ZwSehE-WvfhF9")
        );
        assert_eq!(
            Ok(id),
            ContractId::from_str("rgb:pkXwpsbaemTWhtSgVDGF25hEijtTAnPjzhB63ZwSehEWvfhF9")
        );
        assert_eq!(
            Ok(id),
            ContractId::from_str("pkXwpsbaemTWhtSgVDGF25hEijtTAnPjzhB63ZwSehEWvfhF9")
        );

        // Wrong separator placement
        assert!(
            ContractId::from_str("rgb:pkXwpsb-aemTWhtSg-VDGF25hEi-jtTAnPjzh-B63ZwSeh-EWvfhF9")
                .is_err()
        );
        // Wrong separator number
        assert!(
            ContractId::from_str("rgb:pkXwpsb-aemTWhtSg-VDGF25hEi-jtTAnPjzh-B63ZwSehEWvfhF9")
                .is_err()
        );
    }
}

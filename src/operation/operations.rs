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
use std::num::ParseIntError;
use std::str::FromStr;

use amplify::confinement::{Confined, SmallOrdSet, TinyOrdMap, TinyOrdSet};
use amplify::{hex, Wrapper};
use commit_verify::{
    CommitEncode, CommitEngine, CommitId, Conceal, MerkleHash, MerkleLeaves, ReservedBytes,
    StrictHash,
};
use strict_encoding::stl::AsciiPrintable;
use strict_encoding::{RString, StrictDeserialize, StrictEncode, StrictSerialize};

use crate::schema::{self, ExtensionType, OpFullType, OpType, SchemaId, TransitionType};
use crate::{
    AssetTag, Assign, AssignmentIndex, AssignmentType, Assignments, AssignmentsRef,
    ConcealedAttach, ConcealedData, ConcealedValue, ContractId, DiscloseHash, ExposedState, Ffv,
    GenesisSeal, GlobalState, GraphSeal, Layer1, Metadata, OpDisclose, OpId, SecretSeal,
    TypedAssigns, VoidState, XChain, LIB_NAME_RGB_COMMIT,
};

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[display("{op}/{ty}/{no}")]
/// RGB contract operation output pointer, defined by the operation ID and
/// output number.
pub struct Opout {
    pub op: OpId,
    pub ty: AssignmentType,
    pub no: u16,
}

impl Opout {
    pub fn new(op: OpId, ty: AssignmentType, no: u16) -> Opout { Opout { op, ty, no } }
}

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(inner)]
pub enum OpoutParseError {
    #[from]
    InvalidNodeId(hex::Error),

    InvalidType(ParseIntError),

    InvalidOutputNo(ParseIntError),

    /// invalid operation outpoint format ('{0}')
    #[display(doc_comments)]
    WrongFormat(String),
}

impl FromStr for Opout {
    type Err = OpoutParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split('/');
        match (split.next(), split.next(), split.next(), split.next()) {
            (Some(op), Some(ty), Some(no), None) => Ok(Opout {
                op: op.parse()?,
                ty: ty.parse().map_err(OpoutParseError::InvalidType)?,
                no: no.parse().map_err(OpoutParseError::InvalidOutputNo)?,
            }),
            _ => Err(OpoutParseError::WrongFormat(s.to_owned())),
        }
    }
}

#[derive(Wrapper, WrapperMut, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default, From)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = StrictHash)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct AssetTags(TinyOrdMap<AssignmentType, AssetTag>);

#[derive(Wrapper, WrapperMut, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default, From)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
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
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
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
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
// TODO: Consider requiring minimum number of inputs to be 1
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
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
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

    /// Returns nonce used in consensus ordering of state transitions and
    /// extensions.
    fn nonce(&self) -> u64;

    /// Returns [`Option::Some`]`(`[`TransitionType`]`)` for transitions or
    /// [`Option::None`] for genesis and extension operation types
    fn transition_type(&self) -> Option<TransitionType>;

    /// Returns [`Option::Some`]`(`[`ExtensionType`]`)` for extension nodes or
    /// [`Option::None`] for genesis and state transitions
    fn extension_type(&self) -> Option<ExtensionType>;

    /// Returns metadata associated with the operation, if any.
    fn metadata(&self) -> &Metadata;

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
            seals: Confined::from_checked(seals),
            fungible: Confined::from_iter_checked(
                fungible.into_iter().map(|(k, s)| (k, s.commitment)),
            ),
            data: Confined::from_checked(data),
            attach: Confined::from_checked(attach),
        }
    }

    fn disclose_hash(&self) -> DiscloseHash { self.disclose().commit_id() }
}

/// An ASCII printable string up to 4096 chars representing identity of the
/// developer.
///
/// We deliberately do not define the internal structure of the identity such
/// that it can be updated without changes to the consensus level.
///
/// Contract or schema validity doesn't assume any checks on the identity; these
/// checks must be performed at the application level.
#[derive(Wrapper, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, From, Display)]
#[wrapper(Deref, FromStr)]
#[display(inner)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = StrictHash)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct Identity(RString<AsciiPrintable, AsciiPrintable, 1, 4096>);

impl Default for Identity {
    fn default() -> Self { Self::from("ssi:anonymous") }
}

impl From<&'static str> for Identity {
    fn from(s: &'static str) -> Self { Self(RString::from(s)) }
}

impl Identity {
    pub fn is_empty(&self) -> bool { self.is_anonymous() }
    pub fn is_anonymous(&self) -> bool { self == &default!() }
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
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
    pub issuer: Identity,
    pub testnet: bool,
    pub asset_tags: AssetTags,
    pub metadata: Metadata,
    pub globals: GlobalState,
    pub assignments: Assignments<GenesisSeal>,
    pub valencies: Valencies,
    pub validator: ReservedBytes<1, 0>,
}

impl StrictSerialize for Genesis {}
impl StrictDeserialize for Genesis {}

impl Genesis {
    pub fn layer1(&self) -> Option<Layer1> {
        if let Some((_, typed_assigns)) = self.assignments.iter().next() {
            typed_assigns
                .to_confidential_seals()
                .first()
                .map(|cs| cs.layer1())
        } else {
            None
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Extension {
    pub ffv: Ffv,
    pub contract_id: ContractId,
    pub nonce: u64,
    pub extension_type: ExtensionType,
    pub metadata: Metadata,
    pub globals: GlobalState,
    pub assignments: Assignments<GenesisSeal>,
    pub redeemed: Redeemed,
    pub valencies: Valencies,
    pub validator: ReservedBytes<1, 0>,
    pub witness: ReservedBytes<2, 0>,
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
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Transition {
    pub ffv: Ffv,
    pub contract_id: ContractId,
    pub nonce: u64,
    pub transition_type: TransitionType,
    pub metadata: Metadata,
    pub globals: GlobalState,
    pub inputs: Inputs,
    pub assignments: Assignments<GraphSeal>,
    pub valencies: Valencies,
    pub validator: ReservedBytes<1, 0>,
    pub witness: ReservedBytes<2, 0>,
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
    fn nonce(&self) -> u64 { u64::MAX }

    #[inline]
    fn transition_type(&self) -> Option<TransitionType> { None }

    #[inline]
    fn extension_type(&self) -> Option<ExtensionType> { None }

    #[inline]
    fn metadata(&self) -> &Metadata { &self.metadata }

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
    fn nonce(&self) -> u64 { self.nonce }

    #[inline]
    fn transition_type(&self) -> Option<TransitionType> { None }

    #[inline]
    fn extension_type(&self) -> Option<ExtensionType> { Some(self.extension_type) }

    #[inline]
    fn metadata(&self) -> &Metadata { &self.metadata }

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
    fn nonce(&self) -> u64 { self.nonce }

    #[inline]
    fn transition_type(&self) -> Option<TransitionType> { Some(self.transition_type) }

    #[inline]
    fn extension_type(&self) -> Option<ExtensionType> { None }

    #[inline]
    fn metadata(&self) -> &Metadata { &self.metadata }

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

#[cfg(test)]
mod test {
    use amplify::ByteArray;
    use baid64::DisplayBaid64;

    use super::*;

    #[test]
    fn contract_id_display() {
        const ID: &str = "rgb:bGxsbGxs-bGxsbGx-sbGxsbG-xsbGxsb-GxsbGxs-bGxsbGw";
        let id = ContractId::from_byte_array([0x6c; 32]);
        assert_eq!(ID.len(), 52);
        assert_eq!(ID, id.to_string());
        assert_eq!(ID, id.to_baid64_string());
    }

    #[test]
    fn contract_id_from_str() {
        let id = ContractId::from_byte_array([0x6c; 32]);
        assert_eq!(
            id,
            ContractId::from_str("rgb:bGxsbGxs-bGxsbGx-sbGxsbG-xsbGxsb-GxsbGxs-bGxsbGw").unwrap()
        );
        assert_eq!(
            id,
            ContractId::from_str("bGxsbGxs-bGxsbGx-sbGxsbG-xsbGxsb-GxsbGxs-bGxsbGw").unwrap()
        );
        assert_eq!(
            id,
            ContractId::from_str("rgb:bGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGw").unwrap()
        );
        assert_eq!(
            id,
            ContractId::from_str("bGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGw").unwrap()
        );

        // Wrong separator placement
        assert!(
            ContractId::from_str("rgb:bGxsbGx-sbGxsbGx-sbGxsbG-xsbGxsb-GxsbGxs-bGxsbGw").is_ok()
        );
        // Wrong separator number
        assert!(
            ContractId::from_str("rgb:bGxs-bGxs-bGxsbGx-sbGxsbG-xsbGxsb-GxsbGxs-bGxsbGw").is_ok()
        );
    }
}

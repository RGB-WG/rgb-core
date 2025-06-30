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

use std::collections::{btree_set, BTreeMap};
use std::hash::{Hash, Hasher};
use std::iter;
use std::num::ParseIntError;
use std::str::FromStr;

use amplify::confinement::{Confined, NonEmptyOrdSet, TinyOrdSet, U16};
use amplify::{hex, Bytes64, Wrapper};
use commit_verify::{CommitEncode, CommitEngine, CommitId, MerkleHash, MerkleLeaves, StrictHash};
use strict_encoding::stl::AsciiPrintable;
use strict_encoding::{RString, StrictDeserialize, StrictEncode, StrictSerialize};

use crate::schema::{OpFullType, SchemaId, TransitionType};
use crate::{
    Assign, AssignmentIndex, AssignmentType, Assignments, AssignmentsRef, ChainNet, ContractId,
    DiscloseHash, ExposedState, Ffv, GenesisSeal, GlobalState, GraphSeal, Metadata, OpDisclose,
    OpId, RevealedData, RevealedValue, SecretSeal, TypedAssigns, VoidState, LIB_NAME_RGB_COMMIT,
};

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = MerkleHash)]
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
#[display(doc_comments)]
pub enum OpoutParseError {
    /// malformed opid. Details: {0}
    #[from]
    InvalidOpid(hex::Error),

    /// malformed assignment type. Details: {0}
    InvalidType(ParseIntError),

    /// malformed output no. Details: {0}
    InvalidOutputNo(ParseIntError),

    /// invalid operation outpoint format ('{0}')
    #[display(doc_comments)]
    WrongFormat(String),
}

impl FromStr for Opout {
    type Err = OpoutParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() != 3 {
            return Err(OpoutParseError::WrongFormat(s.to_owned()));
        }

        let op = parts[0].parse()?;
        let ty = parts[1].parse().map_err(OpoutParseError::InvalidType)?;
        let no = parts[2].parse().map_err(OpoutParseError::InvalidOutputNo)?;

        Ok(Opout { op, ty, no })
    }
}

#[cfg(feature = "serde")]
mod serde_utils {
    use serde_crate::ser::SerializeStruct;
    use serde_crate::{Deserialize, Deserializer, Serialize, Serializer};

    use super::*;

    impl Serialize for Opout {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            if serializer.is_human_readable() {
                serializer.serialize_str(&self.to_string())
            } else {
                let mut s = serializer.serialize_struct("Opout", 3)?;
                s.serialize_field("op", &self.op)?;
                s.serialize_field("ty", &self.ty)?;
                s.serialize_field("no", &self.no)?;
                s.end()
            }
        }
    }

    impl<'de> Deserialize<'de> for Opout {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            if deserializer.is_human_readable() {
                let s = String::deserialize(deserializer)?;
                s.parse::<Opout>().map_err(serde::de::Error::custom)
            } else {
                #[cfg_attr(
                    feature = "serde",
                    derive(Deserialize),
                    serde(crate = "serde_crate", rename = "Opout")
                )]
                struct OpoutData {
                    op: OpId,
                    ty: AssignmentType,
                    no: u16,
                }

                let data = OpoutData::deserialize(deserializer)?;
                Ok(Opout {
                    op: data.op,
                    ty: data.ty,
                    no: data.no,
                })
            }
        }
    }
}

#[derive(Wrapper, WrapperMut, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT, dumb = Self(NonEmptyOrdSet::with(Opout::strict_dumb())))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct Inputs(NonEmptyOrdSet<Opout, U16>);

impl<'a> IntoIterator for &'a Inputs {
    type Item = Opout;
    type IntoIter = iter::Copied<btree_set::Iter<'a, Opout>>;

    fn into_iter(self) -> Self::IntoIter { self.0.iter().copied() }
}

impl MerkleLeaves for Inputs {
    type Leaf = Opout;
    type LeafIter<'tmp> = <TinyOrdSet<Opout> as MerkleLeaves>::LeafIter<'tmp>;

    fn merkle_leaves(&self) -> Self::LeafIter<'_> { self.0.merkle_leaves() }
}

/// RGB contract operation API, defined as trait
///
/// Implemented by all contract operation types (see [`OpType`]):
/// - Genesis ([`Genesis`])
/// - State transitions ([`Transitions`])
pub trait Operation {
    /// Returns full contract operation type information
    fn full_type(&self) -> OpFullType;

    /// Returns [`OpId`], which is a hash of this operation commitment
    /// serialization
    fn id(&self) -> OpId;

    /// Returns [`ContractId`] this operation belongs to.
    fn contract_id(&self) -> ContractId;

    /// Returns nonce used in consensus ordering of state transitions
    fn nonce(&self) -> u64;

    /// Returns metadata associated with the operation, if any.
    fn metadata(&self) -> &Metadata;

    /// Returns reference to a full set of metadata (in form of [`GlobalState`]
    /// wrapper structure) for the contract operation.
    fn globals(&self) -> &GlobalState;

    fn assignments(&self) -> AssignmentsRef;

    fn assignments_by_type(&self, t: AssignmentType) -> Option<TypedAssigns<GraphSeal>>;

    /// Provides summary about parts of the operation which are revealed.
    fn disclose(&self) -> OpDisclose {
        fn proc_seals<State: ExposedState>(
            ty: AssignmentType,
            a: &[Assign<State, GraphSeal>],
            seals: &mut BTreeMap<AssignmentIndex, SecretSeal>,
            state: &mut BTreeMap<AssignmentIndex, State>,
        ) {
            for (index, assignment) in a.iter().enumerate() {
                if let Some(seal) = assignment.revealed_seal() {
                    seals.insert(AssignmentIndex::new(ty, index as u16), seal.to_secret_seal());
                }
                state.insert(
                    AssignmentIndex::new(ty, index as u16),
                    assignment.as_revealed_state().clone(),
                );
            }
        }

        let mut seals: BTreeMap<AssignmentIndex, SecretSeal> = bmap!();
        let mut void: BTreeMap<AssignmentIndex, VoidState> = bmap!();
        let mut fungible: BTreeMap<AssignmentIndex, RevealedValue> = bmap!();
        let mut data: BTreeMap<AssignmentIndex, RevealedData> = bmap!();
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
            }
        }

        OpDisclose {
            id: self.id(),
            seals: Confined::from_checked(seals),
            fungible: Confined::from_iter_checked(fungible),
            data: Confined::from_checked(data),
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

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[display(inner)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT, tags = repr, into_u8, try_from_u8)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[repr(u8)]
#[derive(Default)]
#[non_exhaustive]
pub enum SealClosingStrategy {
    #[default]
    FirstOpretOrTapret = 0,
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
    pub timestamp: i64,
    pub issuer: Identity,
    pub chain_net: ChainNet,
    pub seal_closing_strategy: SealClosingStrategy,
    pub metadata: Metadata,
    pub globals: GlobalState,
    pub assignments: Assignments<GenesisSeal>,
}

impl StrictSerialize for Genesis {}
impl StrictDeserialize for Genesis {}

#[derive(Wrapper, WrapperMut, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Signature(Bytes64);

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
    pub signature: Option<Signature>,
}

impl StrictSerialize for Transition {}
impl StrictDeserialize for Transition {}

impl Hash for Transition {
    fn hash<H: Hasher>(&self, state: &mut H) { state.write(self.id().as_slice()) }
}

impl CommitEncode for Genesis {
    type CommitmentId = OpId;
    fn commit_encode(&self, e: &mut CommitEngine) { e.commit_to_serialized(&self.commit()) }
}

impl CommitEncode for Transition {
    type CommitmentId = OpId;
    fn commit_encode(&self, e: &mut CommitEngine) { e.commit_to_serialized(&self.commit()) }
}

impl Transition {
    /// Returns reference to information about the owned rights in form of
    /// [`Inputs`] wrapper structure which this operation updates with
    /// state transition ("parent owned rights").
    pub fn inputs(&self) -> &Inputs { &self.inputs }
}

impl Operation for Genesis {
    #[inline]
    fn full_type(&self) -> OpFullType { OpFullType::Genesis }

    #[inline]
    fn id(&self) -> OpId { self.commit_id() }

    #[inline]
    fn contract_id(&self) -> ContractId { ContractId::from_inner(self.id().into_inner()) }

    #[inline]
    fn nonce(&self) -> u64 { u64::MAX }

    #[inline]
    fn metadata(&self) -> &Metadata { &self.metadata }

    #[inline]
    fn globals(&self) -> &GlobalState { &self.globals }

    #[inline]
    fn assignments(&self) -> AssignmentsRef { (&self.assignments).into() }

    #[inline]
    fn assignments_by_type(&self, t: AssignmentType) -> Option<TypedAssigns<GraphSeal>> {
        self.assignments
            .get(&t)
            .map(TypedAssigns::transmutate_seals)
    }
}

impl Operation for Transition {
    #[inline]
    fn full_type(&self) -> OpFullType { OpFullType::StateTransition(self.transition_type) }

    #[inline]
    fn id(&self) -> OpId { self.commit_id() }

    #[inline]
    fn contract_id(&self) -> ContractId { self.contract_id }

    #[inline]
    fn nonce(&self) -> u64 { self.nonce }

    #[inline]
    fn metadata(&self) -> &Metadata { &self.metadata }

    #[inline]
    fn globals(&self) -> &GlobalState { &self.globals }

    #[inline]
    fn assignments(&self) -> AssignmentsRef { (&self.assignments).into() }

    #[inline]
    fn assignments_by_type(&self, t: AssignmentType) -> Option<TypedAssigns<GraphSeal>> {
        self.assignments.get(&t).cloned()
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

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

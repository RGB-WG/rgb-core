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
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use aluvm::library::LibId;
use amplify::confinement::TinyOrdMap;
use amplify::{ByteArray, Bytes32};
use baid64::{Baid64ParseError, DisplayBaid64, FromBaid64Str};
use commit_verify::{CommitEncode, CommitEngine, CommitId, CommitmentId, DigestExt, Sha256};
use strict_encoding::{
    StrictDecode, StrictDeserialize, StrictEncode, StrictSerialize, StrictType, TypeName,
};
use strict_types::{FieldName, SemId};

use super::{AssignmentType, GenesisSchema, OwnedStateSchema, TransitionSchema};
use crate::{impl_serde_baid64, Ffv, GlobalStateSchema, StateType, LIB_NAME_RGB_COMMIT};

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From, Display)]
#[wrapper(FromStr, LowerHex, UpperHex)]
#[display("0x{0:04X}")]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct MetaType(u16);
impl MetaType {
    pub const fn with(ty: u16) -> Self { Self(ty) }
}

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From, Display)]
#[wrapper(FromStr, LowerHex, UpperHex)]
#[display("0x{0:04X}")]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct GlobalStateType(u16);
impl GlobalStateType {
    pub const fn with(ty: u16) -> Self { Self(ty) }
}

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From, Display)]
#[wrapper(FromStr, LowerHex, UpperHex)]
#[display("0x{0:04X}")]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct TransitionType(u16);
impl TransitionType {
    pub const fn with(ty: u16) -> Self { Self(ty) }
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT, tags = order)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct AssignmentDetails {
    pub owned_state_schema: OwnedStateSchema,
    pub name: FieldName,
    pub default_transition: TransitionType,
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT, tags = order)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct GlobalDetails {
    pub global_state_schema: GlobalStateSchema,
    pub name: FieldName,
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT, tags = order)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct MetaDetails {
    pub sem_id: SemId,
    pub name: FieldName,
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT, tags = order)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct TransitionDetails {
    pub transition_schema: TransitionSchema,
    pub name: FieldName,
}

/// Schema identifier.
///
/// Schema identifier commits to all the schema data.
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
pub struct SchemaId(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl SchemaId {
    pub const fn from_array(id: [u8; 32]) -> Self { SchemaId(Bytes32::from_array(id)) }
}

impl From<Sha256> for SchemaId {
    fn from(hasher: Sha256) -> Self { hasher.finish().into() }
}

impl CommitmentId for SchemaId {
    const TAG: &'static str = "urn:lnp-bp:rgb:schema#2024-02-03";
}

impl DisplayBaid64 for SchemaId {
    const HRI: &'static str = "rgb:sch";
    const CHUNKING: bool = false;
    const PREFIX: bool = true;
    const EMBED_CHECKSUM: bool = false;
    const MNEMONIC: bool = true;
    fn to_baid64_payload(&self) -> [u8; 32] { self.to_byte_array() }
}
impl FromBaid64Str for SchemaId {}
impl FromStr for SchemaId {
    type Err = Baid64ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_baid64_str(s) }
}
impl Display for SchemaId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { self.fmt_baid64(f) }
}

impl_serde_baid64!(SchemaId);

#[derive(Clone, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Schema {
    pub ffv: Ffv,

    pub name: TypeName,

    pub meta_types: TinyOrdMap<MetaType, MetaDetails>,
    pub global_types: TinyOrdMap<GlobalStateType, GlobalDetails>,
    pub owned_types: TinyOrdMap<AssignmentType, AssignmentDetails>,
    pub genesis: GenesisSchema,
    pub transitions: TinyOrdMap<TransitionType, TransitionDetails>,
}

impl CommitEncode for Schema {
    type CommitmentId = SchemaId;

    fn commit_encode(&self, e: &mut CommitEngine) {
        e.commit_to_serialized(&self.ffv);

        e.commit_to_serialized(&self.name);

        e.commit_to_map(&self.meta_types);
        e.commit_to_map(&self.global_types);
        e.commit_to_map(&self.owned_types);
        e.commit_to_serialized(&self.genesis);
        e.commit_to_map(&self.transitions);
    }
}

impl PartialEq for Schema {
    fn eq(&self, other: &Self) -> bool { self.schema_id() == other.schema_id() }
}

impl Ord for Schema {
    fn cmp(&self, other: &Self) -> Ordering { self.schema_id().cmp(&other.schema_id()) }
}

impl PartialOrd for Schema {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl StrictSerialize for Schema {}
impl StrictDeserialize for Schema {}

impl Schema {
    #[inline]
    pub fn schema_id(&self) -> SchemaId { self.commit_id() }

    pub fn types(&self) -> impl Iterator<Item = SemId> + '_ {
        self.meta_types
            .values()
            .map(|i| &i.sem_id)
            .cloned()
            .chain(
                self.global_types
                    .values()
                    .map(|i| i.global_state_schema.sem_id),
            )
            .chain(
                self.owned_types
                    .values()
                    .filter_map(|ai| OwnedStateSchema::sem_id(&ai.owned_state_schema)),
            )
    }

    pub fn libs(&self) -> impl Iterator<Item = LibId> + '_ {
        self.genesis
            .validator
            .iter()
            .copied()
            .chain(
                self.transitions
                    .values()
                    .filter_map(|i| i.transition_schema.validator),
            )
            .map(|site| site.lib)
    }

    pub fn default_transition_for_assignment(
        &self,
        assignment_type: &AssignmentType,
    ) -> TransitionType {
        self.owned_types
            .get(assignment_type)
            .expect("invalid schema")
            .default_transition
    }

    pub fn assignment(&self, name: impl Into<FieldName>) -> (&AssignmentType, &AssignmentDetails) {
        let name = name.into();
        self.owned_types
            .iter()
            .find(|(_, i)| i.name == name)
            .expect("cannot find assignment with the given name")
    }

    pub fn assignment_type(&self, name: impl Into<FieldName>) -> AssignmentType {
        *self.assignment(name).0
    }

    pub fn assignment_name(&self, type_id: AssignmentType) -> &FieldName {
        &self
            .owned_types
            .iter()
            .find(|(id, _)| *id == &type_id)
            .expect("cannot find assignment with the given type ID")
            .1
            .name
    }

    pub fn assignment_types_for_state(&self, state_type: StateType) -> Vec<&AssignmentType> {
        self.owned_types
            .iter()
            .filter_map(|(at, ai)| {
                if ai.owned_state_schema.state_type() == state_type {
                    Some(at)
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn global(&self, name: impl Into<FieldName>) -> (&GlobalStateType, &GlobalDetails) {
        let name = name.into();
        self.global_types
            .iter()
            .find(|(_, i)| i.name == name)
            .expect("cannot find global with the given name")
    }

    pub fn global_type(&self, name: impl Into<FieldName>) -> GlobalStateType {
        *self.global(name).0
    }

    pub fn meta(&self, name: impl Into<FieldName>) -> (&MetaType, &MetaDetails) {
        let name = name.into();
        self.meta_types
            .iter()
            .find(|(_, i)| i.name == name)
            .expect("cannot find meta with the given name")
    }

    pub fn meta_type(&self, name: impl Into<FieldName>) -> MetaType { *self.meta(name).0 }

    pub fn meta_name(&self, type_id: MetaType) -> &FieldName {
        &self
            .meta_types
            .iter()
            .find(|(id, _)| *id == &type_id)
            .expect("cannot find meta with the given type ID")
            .1
            .name
    }

    pub fn transition(&self, name: impl Into<FieldName>) -> (&TransitionType, &TransitionDetails) {
        let name = name.into();
        self.transitions
            .iter()
            .find(|(_, i)| i.name == name)
            .expect("cannot find transition with the given name")
    }

    pub fn transition_type(&self, name: impl Into<FieldName>) -> TransitionType {
        *self.transition(name).0
    }
}

#[cfg(test)]
mod test {
    use strict_encoding::StrictDumb;

    use super::*;

    #[test]
    fn display() {
        let dumb = SchemaId::strict_dumb();
        assert_eq!(
            dumb.to_string(),
            "rgb:sch:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA#distant-history-exotic"
        );
        assert_eq!(
            &format!("{dumb:-}"),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA#distant-history-exotic"
        );

        let less_dumb = SchemaId::from_byte_array(*b"EV4350-'4vwj'4;v-w94w'e'vFVVDhpq");
        assert_eq!(
            less_dumb.to_string(),
            "rgb:sch:RVY0MzUwLSc0dndqJzQ7di13OTR3J2UndkZWVkRocHE#lemon-diamond-cartoon"
        );
        assert_eq!(
            &format!("{less_dumb:-}"),
            "RVY0MzUwLSc0dndqJzQ7di13OTR3J2UndkZWVkRocHE#lemon-diamond-cartoon"
        );
        assert_eq!(
            &format!("{less_dumb:#}"),
            "rgb:sch:RVY0MzUwLSc0dndqJzQ7di13OTR3J2UndkZWVkRocHE"
        );
        assert_eq!(&format!("{less_dumb:-#}"), "RVY0MzUwLSc0dndqJzQ7di13OTR3J2UndkZWVkRocHE");
    }
}

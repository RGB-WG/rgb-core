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
use amplify::confinement::{TinyOrdMap, TinyOrdSet};
use amplify::{ByteArray, Bytes32};
use baid64::{Baid64ParseError, DisplayBaid64, FromBaid64Str};
use commit_verify::{
    CommitEncode, CommitEngine, CommitId, CommitmentId, DigestExt, ReservedBytes, Sha256,
};
use strict_encoding::{
    StrictDecode, StrictDeserialize, StrictEncode, StrictSerialize, StrictType, TypeName,
};
use strict_types::SemId;

use super::{
    AssignmentType, ExtensionSchema, GenesisSchema, OwnedStateSchema, TransitionSchema, ValencyType,
};
use crate::{impl_serde_baid64, Ffv, GlobalStateSchema, Identity, Occurrences, LIB_NAME_RGB};

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From, Display)]
#[wrapper(FromStr, LowerHex, UpperHex)]
#[display("0x{0:04X}")]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
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
#[strict_type(lib = LIB_NAME_RGB)]
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
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct ExtensionType(u16);
impl ExtensionType {
    pub const fn with(ty: u16) -> Self { Self(ty) }
}

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From, Display)]
#[wrapper(FromStr, LowerHex, UpperHex)]
#[display("0x{0:04X}")]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct TransitionType(u16);
impl TransitionType {
    pub const fn with(ty: u16) -> Self { Self(ty) }
}

impl TransitionType {
    pub const BLANK: Self = TransitionType(u16::MAX);
    /// Easily check if the TransitionType is blank with convention method
    pub fn is_blank(self) -> bool { self == Self::BLANK }
}

/// Schema identifier.
///
/// Schema identifier commits to all the schema data.
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
pub struct SchemaId(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

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
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Schema {
    pub ffv: Ffv,
    pub flags: ReservedBytes<1, 0>,

    pub name: TypeName,
    pub timestamp: i64,
    pub developer: Identity,

    pub meta_types: TinyOrdMap<MetaType, SemId>,
    pub global_types: TinyOrdMap<GlobalStateType, GlobalStateSchema>,
    pub owned_types: TinyOrdMap<AssignmentType, OwnedStateSchema>,
    pub valency_types: TinyOrdSet<ValencyType>,
    pub genesis: GenesisSchema,
    pub extensions: TinyOrdMap<ExtensionType, ExtensionSchema>,
    pub transitions: TinyOrdMap<TransitionType, TransitionSchema>,

    pub reserved: ReservedBytes<8, 0>,
}

impl CommitEncode for Schema {
    type CommitmentId = SchemaId;

    fn commit_encode(&self, e: &mut CommitEngine) {
        e.commit_to_serialized(&self.ffv);
        e.commit_to_serialized(&self.flags);

        e.commit_to_serialized(&self.name);
        e.commit_to_serialized(&self.timestamp);
        e.commit_to_serialized(&self.developer);

        e.commit_to_map(&self.meta_types);
        e.commit_to_map(&self.global_types);
        e.commit_to_map(&self.owned_types);
        e.commit_to_set(&self.valency_types);
        e.commit_to_serialized(&self.genesis);
        e.commit_to_map(&self.extensions);
        e.commit_to_map(&self.transitions);

        e.commit_to_serialized(&self.reserved);
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

    pub fn blank_transition(&self) -> TransitionSchema {
        let mut schema = TransitionSchema::default();
        for id in self.owned_types.keys() {
            schema.inputs.insert(*id, Occurrences::NoneOrMore).ok();
            schema.assignments.insert(*id, Occurrences::NoneOrMore).ok();
        }
        schema
    }

    pub fn types(&self) -> impl Iterator<Item = SemId> + '_ {
        self.meta_types
            .values()
            .copied()
            .chain(self.global_types.values().map(|i| i.sem_id))
            .chain(
                self.owned_types
                    .values()
                    .filter_map(OwnedStateSchema::sem_id),
            )
    }

    pub fn libs(&self) -> impl Iterator<Item = LibId> + '_ {
        self.genesis
            .validator
            .iter()
            .copied()
            .chain(self.transitions.values().filter_map(|i| i.validator))
            .chain(self.extensions.values().filter_map(|i| i.validator))
            .map(|site| site.lib)
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

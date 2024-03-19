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

use amplify::confinement::{TinyOrdMap, TinyOrdSet};
use amplify::{ByteArray, Bytes32};
use armor::StrictArmor;
use baid58::{Baid58ParseError, Chunking, FromBaid58, ToBaid58, CHUNKING_32};
use commit_verify::{
    CommitEncode, CommitEngine, CommitId, CommitmentId, DigestExt, ReservedBytes, Sha256,
};
use strict_encoding::{StrictDecode, StrictDeserialize, StrictEncode, StrictSerialize, StrictType};

use super::{
    AssignmentType, ExtensionSchema, GenesisSchema, Script, StateSchema, TransitionSchema,
    ValencyType,
};
use crate::{Ffv, GlobalStateSchema, Occurrences, Types, LIB_NAME_RGB};

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
}

/// Schema identifier.
///
/// Schema identifier commits to all the schema data.
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
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

impl ToBaid58<32> for SchemaId {
    const HRI: &'static str = "sc";
    const CHUNKING: Option<Chunking> = CHUNKING_32;
    fn to_baid58_payload(&self) -> [u8; 32] { self.to_byte_array() }
    fn to_baid58_string(&self) -> String { self.to_string() }
}
impl FromBaid58<32> for SchemaId {}
impl Display for SchemaId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if !f.alternate() {
            f.write_str("urn:lnp-bp:sc:")?;
        }
        if f.sign_minus() {
            write!(f, "{:.2}", self.to_baid58())
        } else {
            write!(f, "{:#.2}", self.to_baid58())
        }
    }
}
impl FromStr for SchemaId {
    type Err = Baid58ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_baid58_maybe_chunked_str(s.trim_start_matches("urn:lnp-bp:"), ':', '#')
    }
}
impl SchemaId {
    pub fn to_mnemonic(&self) -> String { self.to_baid58().mnemonic() }
}

pub trait SchemaRoot: Clone + Eq + StrictType + StrictEncode + StrictDecode + Default {
    fn schema_id(&self) -> SchemaId;
}
impl SchemaRoot for () {
    fn schema_id(&self) -> SchemaId { SchemaId::from_byte_array([0u8; 32]) }
}
impl SchemaRoot for RootSchema {
    fn schema_id(&self) -> SchemaId { self.schema_id() }
}
pub type RootSchema = Schema<()>;
pub type SubSchema = Schema<RootSchema>;

#[derive(Clone, Eq, Default, Debug)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Schema<Root: SchemaRoot> {
    pub ffv: Ffv,
    pub flags: ReservedBytes<1, 0>,
    pub subset_of: Option<Root>,

    pub global_types: TinyOrdMap<GlobalStateType, GlobalStateSchema>,
    pub owned_types: TinyOrdMap<AssignmentType, StateSchema>,
    pub valency_types: TinyOrdSet<ValencyType>,
    pub genesis: GenesisSchema,
    pub extensions: TinyOrdMap<ExtensionType, ExtensionSchema>,
    pub transitions: TinyOrdMap<TransitionType, TransitionSchema>,

    /// Type system
    pub types: Types,
    /// Validation code.
    pub script: Script,
}

impl<Root: SchemaRoot> CommitEncode for Schema<Root> {
    type CommitmentId = SchemaId;

    fn commit_encode(&self, e: &mut CommitEngine) {
        e.commit_to_serialized(&self.ffv);
        e.commit_to_serialized(&self.flags);
        e.commit_to_option(&self.subset_of.as_ref().map(Root::schema_id));

        e.commit_to_map(&self.global_types);
        e.commit_to_map(&self.owned_types);
        e.commit_to_set(&self.valency_types);
        e.commit_to_serialized(&self.genesis);
        e.commit_to_map(&self.extensions);
        e.commit_to_map(&self.transitions);

        e.commit_to_serialized(&self.types.id());
        e.commit_to_serialized(&self.script);
    }
}

impl<Root: SchemaRoot> PartialEq for Schema<Root> {
    fn eq(&self, other: &Self) -> bool { self.schema_id() == other.schema_id() }
}

impl<Root: SchemaRoot> Ord for Schema<Root> {
    fn cmp(&self, other: &Self) -> Ordering { self.schema_id().cmp(&other.schema_id()) }
}

impl<Root: SchemaRoot> PartialOrd for Schema<Root> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl<Root: SchemaRoot> StrictSerialize for Schema<Root> {}
impl<Root: SchemaRoot> StrictDeserialize for Schema<Root> {}

impl<Root: SchemaRoot> Schema<Root> {
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
}

impl<Root: SchemaRoot> StrictArmor for Schema<Root> {
    type Id = SchemaId;
    const PLATE_TITLE: &'static str = "RGB SCHEMA";

    fn armor_id(&self) -> Self::Id { self.schema_id() }
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
            "urn:lnp-bp:sc:111111-11111111-11111111-11111111-11#comedy-vega-mary"
        );
        assert_eq!(&format!("{dumb:-}"), "urn:lnp-bp:sc:111111-11111111-11111111-11111111-11");

        let less_dumb = SchemaId::from_byte_array(*b"EV4350-'4vwj'4;v-w94w'e'vFVVDhpq");
        assert_eq!(
            less_dumb.to_string(),
            "urn:lnp-bp:sc:5ffNUk-MTVSnWqu-PLT6xKb7-VmAxUbw8-CUNqCkUW-sZfkwz#\
             distant-thermos-arctic"
        );
        assert_eq!(
            &format!("{less_dumb:-}"),
            "urn:lnp-bp:sc:5ffNUk-MTVSnWqu-PLT6xKb7-VmAxUbw8-CUNqCkUW-sZfkwz"
        );
        assert_eq!(
            &format!("{less_dumb:#}"),
            "5ffNUk-MTVSnWqu-PLT6xKb7-VmAxUbw8-CUNqCkUW-sZfkwz#distant-thermos-arctic"
        );
        assert_eq!(&format!("{less_dumb:-#}"), "5ffNUk-MTVSnWqu-PLT6xKb7-VmAxUbw8-CUNqCkUW-sZfkwz");
    }
}

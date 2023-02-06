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
use std::io;
use std::str::FromStr;

use amplify::confinement::{MediumVec, TinyOrdMap, TinyOrdSet};
use amplify::flags::FlagVec;
use amplify::{Bytes32, RawArray};
use baid58::{Baid58ParseError, FromBaid58, ToBaid58};
use commit_verify::{CommitStrategy, CommitmentId};
use strict_encoding::{
    DecodeError, ReadTuple, StrictDecode, StrictEncode, StrictProduct, StrictTuple, StrictType,
    TypeName, TypedRead, TypedWrite, WriteTuple,
};
use strict_types::SemId;

use super::{
    ExtensionSchema, GenesisSchema, OwnedRightType, PublicRightType, Script, StateSchema,
    TransitionSchema,
};
use crate::LIB_NAME_RGB;

pub type FieldType = u16;
pub type ExtensionType = u16;
pub type TransitionType = u16;

/// Schema identifier.
///
/// Schema identifier commits to all of the schema data.
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
pub struct SchemaId(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl ToBaid58<32> for SchemaId {
    const HRI: &'static str = "sch";
    fn to_baid58_payload(&self) -> [u8; 32] { self.to_raw_array() }
}
impl FromBaid58<32> for SchemaId {}

impl FromStr for SchemaId {
    type Err = Baid58ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_baid58_str(s) }
}

#[derive(Clone, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct Schema {
    /// Feature flags control which of the available RGB features are allowed
    /// for smart contracts created under this schema.
    ///
    /// NB: This is not the same as RGB protocol versioning: feature flag set
    /// is specific to a particular RGB protocol version. The only currently
    /// defined RGB version is RGBv1; future versions may change the whole
    /// structure of Schema data, use of feature flags, re-define their meaning
    /// or do other backward-incompatible changes (RGB protocol versions are
    /// not interoperable and backward-incompatible by definitions and the
    /// nature of client-side-validation which does not allow upgrades).
    #[serde(skip)]
    pub rgb_features: SchemaFlags,
    pub subset_of: Option<SchemaId>,

    pub field_types: TinyOrdMap<FieldType, SemId>,
    pub owned_right_types: TinyOrdMap<OwnedRightType, StateSchema>,
    pub public_right_types: TinyOrdSet<PublicRightType>,
    pub genesis: GenesisSchema,
    pub extensions: TinyOrdMap<ExtensionType, ExtensionSchema>,
    pub transitions: TinyOrdMap<TransitionType, TransitionSchema>,

    /// Type system
    pub type_system: MediumVec<u8>, // TODO: TypeSystem,
    /// Validation code.
    pub script: Script,
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

impl CommitStrategy for Schema {
    type Strategy = commit_verify::strategies::Strict;
}

impl CommitmentId for Schema {
    const TAG: [u8; 32] = *b"urn:lnpbp:rgb:schema:v01#202302A";
    type Id = SchemaId;
}

impl Schema {
    #[inline]
    pub fn schema_id(&self) -> SchemaId { self.commitment_id() }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Display, Default)]
#[display(inner)]
pub struct SchemaFlags(FlagVec);

impl StrictType for SchemaFlags {
    const STRICT_LIB_NAME: &'static str = LIB_NAME_RGB;
    fn strict_name() -> Option<TypeName> { Some(tn!("SchemaFlags")) }
}
impl StrictProduct for SchemaFlags {}
impl StrictTuple for SchemaFlags {
    const FIELD_COUNT: u8 = 1;
}
impl StrictEncode for SchemaFlags {
    fn strict_encode<W: TypedWrite>(&self, writer: W) -> io::Result<W> {
        writer.write_tuple::<Self>(|w| Ok(w.write_field(&self.0.shrunk().into_inner())?.complete()))
    }
}
impl StrictDecode for SchemaFlags {
    fn strict_decode(reader: &mut impl TypedRead) -> Result<Self, DecodeError> {
        let flags =
            reader.read_tuple(|r| r.read_field().map(|vec| Self(FlagVec::from_inner(vec))))?;
        if !flags.0.is_empty() {
            Err(DecodeError::DataIntegrityError(format!(
                "unsupported schema flags potentially belonging to a future RGB version. Please \
                 update your software, or, if the problem persists, contact your vendor providing \
                 the following flag information: {flags}"
            )))
        } else {
            Ok(flags)
        }
    }
}

#[cfg(test)]
mod test {
    use strict_encoding::StrictDumb;

    use super::*;

    #[test]
    fn display() {
        let dumb = SchemaId::strict_dumb();
        assert_eq!(dumb.to_string(), "11111111111111111111111111111111");
        assert_eq!(
            &format!("{dumb::^#}"),
            "sch:11111111111111111111111111111111#dallas-liter-marco"
        );

        let less_dumb = SchemaId::from_raw_array(*b"EV4350-'4vwj'4;v-w94w'e'vFVVDhpq");
        assert_eq!(less_dumb.to_string(), "5ffNUkMTVSnWquPLT6xKb7VmAxUbw8CUNqCkUWsZfkwz");
        assert_eq!(
            &format!("{less_dumb::^#}"),
            "sch:5ffNUkMTVSnWquPLT6xKb7VmAxUbw8CUNqCkUWsZfkwz#hotel-urgent-child"
        );
    }
}

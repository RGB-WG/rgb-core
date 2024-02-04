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

use std::collections::{btree_map, BTreeMap};
use std::io;

use aluvm::data::encoding::{Decode, Encode};
use aluvm::isa::Instr;
use aluvm::library::{Lib, LibId, LibSite};
use aluvm::Program;
use amplify::confinement::{Confined, SmallBlob, SmallOrdMap, TinyOrdMap};
use amplify::Wrapper;
use strict_encoding::{
    DecodeError, ReadStruct, StrictDecode, StrictEncode, StrictProduct, StrictStruct, StrictTuple,
    StrictType, TypedRead, TypedWrite, WriteStruct,
};

use crate::vm::RgbIsa;
use crate::{AssignmentType, ExtensionType, GlobalStateType, TransitionType, LIB_NAME_RGB};

/// Maximum total number of libraries which may be used by a single program;
/// i.e. maximal number of nodes in a library dependency tree.
pub const LIBS_MAX_TOTAL: usize = 1024;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[derive(StrictDumb)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase", into = "u32", try_from = "u32")
)]
pub enum EntryPoint {
    #[strict_type(dumb)]
    ValidateGenesis,
    ValidateTransition(TransitionType),
    ValidateExtension(ExtensionType),
    ValidateGlobalState(GlobalStateType),
    ValidateOwnedState(AssignmentType),
}

impl From<EntryPoint> for u32 {
    fn from(value: EntryPoint) -> Self {
        match value {
            EntryPoint::ValidateGenesis => 0x0C35_u32 << 16,
            EntryPoint::ValidateTransition(t) => (0x186a_u32 << 16) | t.to_inner() as u32,
            EntryPoint::ValidateExtension(t) => (0x249f_u32 << 16) | t.to_inner() as u32,
            EntryPoint::ValidateGlobalState(t) => (0x8647_u32 << 16) | t.to_inner() as u32,
            EntryPoint::ValidateOwnedState(t) => (0x927c_u32 << 16) | t.to_inner() as u32,
        }
    }
}

impl TryFrom<u32> for EntryPoint {
    type Error = std::num::TryFromIntError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        let c = value >> 16;
        let t = (value & 0xFFFF) as u16;
        Ok(match c {
            0x0C35 => EntryPoint::ValidateGenesis,
            0x186a => EntryPoint::ValidateTransition(t.into()),
            0x249f => EntryPoint::ValidateExtension(t.into()),
            0x8647 => EntryPoint::ValidateGlobalState(t.into()),
            0x927c => EntryPoint::ValidateOwnedState(t.into()),
            _ => return Err(u8::try_from(0xFFFF).unwrap_err()),
        })
    }
}

impl StrictType for EntryPoint {
    const STRICT_LIB_NAME: &'static str = LIB_NAME_RGB;
}
impl StrictProduct for EntryPoint {}
impl StrictTuple for EntryPoint {
    const FIELD_COUNT: u8 = 1;
}
impl StrictEncode for EntryPoint {
    fn strict_encode<W: TypedWrite>(&self, writer: W) -> io::Result<W> {
        let mut val = [0u8; 3];
        let (ty, subty) = match self {
            EntryPoint::ValidateGenesis => (0, 0u16),
            EntryPoint::ValidateTransition(ty) => (1, ty.to_inner()),
            EntryPoint::ValidateExtension(ty) => (2, ty.to_inner()),
            EntryPoint::ValidateGlobalState(ty) => (3, ty.to_inner()),
            EntryPoint::ValidateOwnedState(ty) => (4, ty.to_inner()),
        };
        val[0] = ty;
        val[1..].copy_from_slice(&subty.to_le_bytes());
        val.strict_encode(writer)
    }
}
impl StrictDecode for EntryPoint {
    fn strict_decode(reader: &mut impl TypedRead) -> Result<Self, DecodeError> {
        let val = <[u8; 3]>::strict_decode(reader)?;
        let mut ty = [0u8; 2];
        ty.copy_from_slice(&val[1..]);
        let ty = u16::from_le_bytes(ty);
        Ok(match val[0] {
            0 => EntryPoint::ValidateGenesis,
            1 => EntryPoint::ValidateTransition(ty.into()),
            2 => EntryPoint::ValidateExtension(ty.into()),
            3 => EntryPoint::ValidateGlobalState(ty.into()),
            4 => EntryPoint::ValidateOwnedState(ty.into()),
            x => return Err(DecodeError::EnumTagNotKnown(s!("EntryPoint"), x)),
        })
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default)]
//#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
//#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct AluScript {
    /// Libraries known to the runtime, identified by their hashes.
    pub libs: Confined<BTreeMap<LibId, Lib>, 0, LIBS_MAX_TOTAL>,

    /// Set of entry points.
    pub entry_points: SmallOrdMap<EntryPoint, LibSite>,
}

// TODO: Remove this once aluvm::Lib will support strict encoding
impl StrictType for AluScript {
    const STRICT_LIB_NAME: &'static str = LIB_NAME_RGB;
}
impl StrictProduct for AluScript {}
impl StrictStruct for AluScript {
    const ALL_FIELDS: &'static [&'static str] = &["libs", "entryPoints"];
}
impl StrictEncode for AluScript {
    fn strict_encode<W: TypedWrite>(&self, writer: W) -> io::Result<W> {
        let libs = self.libs.iter().map(|(id, lib)| {
            let lib = SmallBlob::try_from(lib.serialize()).expect(
                "the RGB Core library must not be used to create AluVM library size exceeding 2^16",
            );
            (*id, lib)
        });

        writer.write_struct::<Self>(|w| {
            Ok(w.write_field(
                fname!("libs"),
                &TinyOrdMap::try_from_iter(libs).expect(
                    "the RGB Core library must not be used to create AluVM scripts with more than \
                     255 libraries",
                ),
            )?
            .write_field(fname!("entryPoints"), &self.entry_points)?
            .complete())
        })
    }
}
impl StrictDecode for AluScript {
    fn strict_decode(reader: &mut impl TypedRead) -> Result<Self, DecodeError> {
        reader.read_struct(|r| {
            let libs = r
                .read_field::<TinyOrdMap<LibId, SmallBlob>>(fname!("libs"))?
                .into_iter()
                .map(|(id, lib)| {
                    let lib = Lib::deserialize(lib)
                        .map_err(|err| DecodeError::DataIntegrityError(err.to_string()))?;
                    Ok((id, lib))
                })
                .collect::<Result<BTreeMap<_, _>, DecodeError>>()?;

            let entry_points = r.read_field(fname!("entryPoints"))?;
            Ok(AluScript {
                libs: Confined::try_from(libs).expect("strict decoder guarantees"),
                entry_points,
            })
        })
    }
}

impl Program for AluScript {
    type Isa = Instr<RgbIsa>;
    type Iter<'a> = btree_map::Values<'a, LibId, Lib> where Self: 'a;

    fn lib_count(&self) -> u16 { self.libs.len() as u16 }

    fn libs(&self) -> Self::Iter<'_> { self.libs.values() }

    fn lib(&self, id: LibId) -> Option<&Lib> { self.libs.get(&id) }

    fn entrypoint(&self) -> LibSite { panic!("AluScript doesn't have a single entry point") }
}

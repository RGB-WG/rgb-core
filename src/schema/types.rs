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

use amplify::Wrapper;

use crate::LIB_NAME_RGB_COMMIT;

#[derive(amplify::Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From, Display)]
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
    pub const fn to_u16(&self) -> u16 { self.0 }
}

#[derive(amplify::Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From, Display)]
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
    pub const fn to_u16(&self) -> u16 { self.0 }
}

#[derive(amplify::Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From, Display)]
#[wrapper(FromStr, LowerHex, UpperHex)]
#[display("0x{0:04X}")]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct ExtensionType(u16);
impl ExtensionType {
    pub const fn with(ty: u16) -> Self { Self(ty) }
    pub const fn to_u16(&self) -> u16 { self.0 }
}

#[derive(amplify::Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From, Display)]
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
    pub const fn to_u16(&self) -> u16 { self.0 }
}

impl TransitionType {
    pub const BLANK: Self = TransitionType(u16::MAX);
    /// Easily check if the TransitionType is blank with convention method
    pub fn is_blank(self) -> bool { self == Self::BLANK }
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
pub struct AssignmentType(u16);
impl AssignmentType {
    pub const fn with(ty: u16) -> Self { Self(ty) }
    pub const fn to_u16(&self) -> u16 { self.0 }
    #[inline]
    pub fn to_le_bytes(&self) -> [u8; 2] { self.0.to_le_bytes() }
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
pub struct ValencyType(u16);
impl ValencyType {
    pub const fn with(ty: u16) -> Self { Self(ty) }
    pub const fn to_u16(&self) -> u16 { self.0 }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[repr(u8)]
/// Node type: genesis, extensions and state transitions
pub enum OpType {
    /// Genesis: single operation per contract, defining contract and
    /// committing to a specific schema and underlying chain hash
    #[display("genesis")]
    Genesis = 0,

    /// Multiple points for decentralized & unowned contract extension,
    /// committing either to a genesis or some state transition via their
    /// valencies
    #[display("extension")]
    StateExtension = 1,

    /// State transition performing owned change to the state data and
    /// committing to (potentially multiple) ancestors (i.e. genesis,
    /// extensions and/or  other state transitions) via spending
    /// corresponding transaction outputs assigned some state by ancestors
    #[display("transition")]
    StateTransition = 2,
}

/// Aggregated type used to supply full contract operation type and
/// transition/state extension type information
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum OpFullType {
    /// Genesis operation (no subtypes)
    #[display("genesis")]
    Genesis,

    /// State transition contract operation, subtyped by transition type
    #[display("state transition #{0}")]
    StateTransition(TransitionType),

    /// State extension contract operation, subtyped by extension type
    #[display("state extension #{0}")]
    StateExtension(ExtensionType),
}

impl OpFullType {
    pub fn subtype(self) -> u16 {
        match self {
            OpFullType::Genesis => 0,
            OpFullType::StateTransition(ty) => ty.to_inner(),
            OpFullType::StateExtension(ty) => ty.to_inner(),
        }
    }

    pub fn is_transition(self) -> bool { matches!(self, Self::StateTransition(_)) }

    pub fn is_extension(self) -> bool { matches!(self, Self::StateExtension(_)) }
}

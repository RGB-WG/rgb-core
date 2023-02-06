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

use amplify::confinement::{TinyOrdMap, TinyOrdSet};

use super::{ExtensionType, FieldType, Occurrences, TransitionType};
use crate::LIB_NAME_RGB;

// Here we can use usize since encoding/decoding makes sure that it's u16
pub type OwnedRightType = u16;
pub type PublicRightType = u16;
pub type MetadataStructure = TinyOrdMap<FieldType, Occurrences>;
pub type PublicRightsStructure = TinyOrdSet<PublicRightType>;
pub type OwnedRightsStructure = TinyOrdMap<OwnedRightType, Occurrences>;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "snake_case")
)]
#[repr(u8)]
/// Node type: genesis, extensions and state transitions
pub enum OpType {
    /// Genesis node: single node per contract, defining contract and
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

/// Aggregated type used to supply full contract node type and transition/state
/// extension type information
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub enum OpFullType {
    /// Genesis node (no subtypes)
    Genesis,

    /// State transition contract node, subtyped by transition type
    StateTransition(TransitionType),

    /// State extension contract node, subtyped by extension type
    StateExtension(ExtensionType),
}

/// Trait defining common API for all node type schemata
pub trait NodeSchema {
    fn node_type(&self) -> OpType;
    fn metadata(&self) -> &MetadataStructure;
    fn closes(&self) -> &OwnedRightsStructure;
    fn extends(&self) -> &PublicRightsStructure;
    fn owned_rights(&self) -> &OwnedRightsStructure;
    fn public_rights(&self) -> &PublicRightsStructure;
}

#[derive(Clone, PartialEq, Eq, Debug, Default, AsAny)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct GenesisSchema {
    pub metadata: MetadataStructure,
    pub owned_rights: OwnedRightsStructure,
    pub public_rights: PublicRightsStructure,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, AsAny)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct ExtensionSchema {
    pub metadata: MetadataStructure,
    pub extends: PublicRightsStructure,
    pub owned_rights: OwnedRightsStructure,
    pub public_rights: PublicRightsStructure,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, AsAny)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct TransitionSchema {
    pub metadata: MetadataStructure,
    pub closes: OwnedRightsStructure,
    pub owned_rights: OwnedRightsStructure,
    pub public_rights: PublicRightsStructure,
}

impl NodeSchema for GenesisSchema {
    #[inline]
    fn node_type(&self) -> OpType { OpType::Genesis }
    #[inline]
    fn metadata(&self) -> &MetadataStructure { &self.metadata }
    #[inline]
    fn closes(&self) -> &OwnedRightsStructure {
        panic!("genesis can't close previous single-use-seals")
    }
    #[inline]
    fn extends(&self) -> &PublicRightsStructure { panic!("genesis can't extend previous state") }
    #[inline]
    fn owned_rights(&self) -> &OwnedRightsStructure { &self.owned_rights }
    #[inline]
    fn public_rights(&self) -> &PublicRightsStructure { &self.public_rights }
}

impl NodeSchema for ExtensionSchema {
    #[inline]
    fn node_type(&self) -> OpType { OpType::StateExtension }
    #[inline]
    fn metadata(&self) -> &MetadataStructure { &self.metadata }
    #[inline]
    fn closes(&self) -> &OwnedRightsStructure {
        panic!("extension can't close previous single-use-seals")
    }
    #[inline]
    fn extends(&self) -> &PublicRightsStructure { &self.extends }
    #[inline]
    fn owned_rights(&self) -> &OwnedRightsStructure { &self.owned_rights }
    #[inline]
    fn public_rights(&self) -> &PublicRightsStructure { &self.public_rights }
}

impl NodeSchema for TransitionSchema {
    #[inline]
    fn node_type(&self) -> OpType { OpType::StateTransition }
    #[inline]
    fn metadata(&self) -> &MetadataStructure { &self.metadata }
    #[inline]
    fn closes(&self) -> &OwnedRightsStructure { &self.closes }
    #[inline]
    fn extends(&self) -> &PublicRightsStructure {
        panic!("state transitions can't extend previous state")
    }
    #[inline]
    fn owned_rights(&self) -> &OwnedRightsStructure { &self.owned_rights }
    #[inline]
    fn public_rights(&self) -> &PublicRightsStructure { &self.public_rights }
}

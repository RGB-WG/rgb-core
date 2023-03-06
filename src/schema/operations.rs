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
use strict_types::SemId;

use super::{ExtensionType, GlobalStateType, Occurrences, TransitionType};
use crate::LIB_NAME_RGB;

// Here we can use usize since encoding/decoding makes sure that it's u16
pub type OwnedStateType = u16;
pub type ValencyType = u16;
pub type GlobalSchema = TinyOrdMap<GlobalStateType, Occurrences>;
pub type ValencySchema = TinyOrdSet<ValencyType>;
pub type AssignmentSchema = TinyOrdMap<OwnedStateType, Occurrences>;

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
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub enum OpFullType {
    /// Genesis operation (no subtypes)
    Genesis,

    /// State transition contract operation, subtyped by transition type
    StateTransition(TransitionType),

    /// State extension contract operation, subtyped by extension type
    StateExtension(ExtensionType),
}

impl OpFullType {
    pub fn subtype(self) -> u16 {
        match self {
            OpFullType::Genesis => 0,
            OpFullType::StateTransition(ty) => ty,
            OpFullType::StateExtension(ty) => ty,
        }
    }
}

/// Trait defining common API for all operation type schemata
pub trait OpSchema {
    fn op_type(&self) -> OpType;
    fn metadata(&self) -> Option<SemId>;
    fn global_state(&self) -> &GlobalSchema;
    fn closes(&self) -> &AssignmentSchema;
    fn redeems(&self) -> &ValencySchema;
    fn owned_state(&self) -> &AssignmentSchema;
    fn valencies(&self) -> &ValencySchema;
}

#[derive(Clone, PartialEq, Eq, Debug, Default, AsAny)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct GenesisSchema {
    pub metadata: Option<SemId>,
    pub global_state: GlobalSchema,
    pub owned_state: AssignmentSchema,
    pub valencies: ValencySchema,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, AsAny)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct ExtensionSchema {
    pub metadata: Option<SemId>,
    pub global_state: GlobalSchema,
    pub redeems: ValencySchema,
    pub owned_state: AssignmentSchema,
    pub valencies: ValencySchema,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, AsAny)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct TransitionSchema {
    pub metadata: Option<SemId>,
    pub global_state: GlobalSchema,
    pub closes: AssignmentSchema,
    pub owned_state: AssignmentSchema,
    pub valencies: ValencySchema,
}

impl OpSchema for GenesisSchema {
    #[inline]
    fn op_type(&self) -> OpType { OpType::Genesis }
    #[inline]
    fn metadata(&self) -> Option<SemId> { self.metadata }
    #[inline]
    fn global_state(&self) -> &GlobalSchema { &self.global_state }
    #[inline]
    fn closes(&self) -> &AssignmentSchema {
        panic!("genesis can't close previous single-use-seals")
    }
    #[inline]
    fn redeems(&self) -> &ValencySchema { panic!("genesis can't redeem valencies") }
    #[inline]
    fn owned_state(&self) -> &AssignmentSchema { &self.owned_state }
    #[inline]
    fn valencies(&self) -> &ValencySchema { &self.valencies }
}

impl OpSchema for ExtensionSchema {
    #[inline]
    fn op_type(&self) -> OpType { OpType::StateExtension }
    #[inline]
    fn metadata(&self) -> Option<SemId> { self.metadata }
    #[inline]
    fn global_state(&self) -> &GlobalSchema { &self.global_state }
    #[inline]
    fn closes(&self) -> &AssignmentSchema {
        panic!("extension can't close previous single-use-seals")
    }
    #[inline]
    fn redeems(&self) -> &ValencySchema { &self.redeems }
    #[inline]
    fn owned_state(&self) -> &AssignmentSchema { &self.owned_state }
    #[inline]
    fn valencies(&self) -> &ValencySchema { &self.valencies }
}

impl OpSchema for TransitionSchema {
    #[inline]
    fn op_type(&self) -> OpType { OpType::StateTransition }
    #[inline]
    fn metadata(&self) -> Option<SemId> { self.metadata }
    #[inline]
    fn global_state(&self) -> &GlobalSchema { &self.global_state }
    #[inline]
    fn closes(&self) -> &AssignmentSchema { &self.closes }
    #[inline]
    fn redeems(&self) -> &ValencySchema { panic!("state transitions can't redeem valencies") }
    #[inline]
    fn owned_state(&self) -> &AssignmentSchema { &self.owned_state }
    #[inline]
    fn valencies(&self) -> &ValencySchema { &self.valencies }
}

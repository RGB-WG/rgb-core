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

use core::fmt::Debug;
use core::hash::Hash;

use strict_encoding::{StrictDecode, StrictDumb, StrictEncode};

use crate::{FungibleState, StructureddData};

/// Marker trait for types of state holding explicit state data.
pub trait ExposedState:
    Debug + StrictDumb + StrictEncode + StrictDecode + Eq + Ord + Clone
{
    fn state_type(&self) -> StateType;
    fn state_data(&self) -> AnyState;
}

/// Categories of the state
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[display(lowercase)]
pub enum StateType {
    /// No state data
    Void,

    /// Value-based state
    Fungible,

    /// State defined with custom data
    Structured,
}

/// Categories of the state
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase", tag = "type")
)]
pub enum AnyState {
    Void,
    Fungible(FungibleState),
    Structured(StructureddData),
}

impl AnyState {
    pub fn state_type(&self) -> StateType {
        match self {
            AnyState::Void => StateType::Void,
            AnyState::Fungible(_) => StateType::Fungible,
            AnyState::Structured(_) => StateType::Structured,
        }
    }
}

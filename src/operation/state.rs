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

use commit_verify::Conceal;
use strict_encoding::{StrictDecode, StrictDumb, StrictEncode};

use crate::{
    ConcealedAttach, ConcealedData, ConcealedValue, RevealedAttach, RevealedData, RevealedValue,
};

/// Marker trait for types of state which are just a commitment to the actual
/// state data.
pub trait ConfidentialState: Debug + Eq + Copy {
    fn state_type(&self) -> StateType;
    fn state_commitment(&self) -> ConcealedState;
}

/// Marker trait for types of state holding explicit state data.
pub trait ExposedState:
    Debug
    + StrictDumb
    + StrictEncode
    + StrictDecode
    + Conceal<Concealed = Self::Confidential>
    + Eq
    + Ord
    + Clone
{
    type Confidential: ConfidentialState + StrictEncode + StrictDecode + StrictDumb;
    fn state_type(&self) -> StateType;
    fn state_data(&self) -> RevealedState;
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

    /// Attached data container
    Attachment,
}

/// Categories of the state
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase", tag = "type")
)]
pub enum RevealedState {
    Void,
    Fungible(RevealedValue),
    Structured(RevealedData),
    Attachment(RevealedAttach),
}

impl RevealedState {
    pub fn state_type(&self) -> StateType {
        match self {
            RevealedState::Void => StateType::Void,
            RevealedState::Fungible(_) => StateType::Fungible,
            RevealedState::Structured(_) => StateType::Structured,
            RevealedState::Attachment(_) => StateType::Attachment,
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase", tag = "type")
)]
#[allow(clippy::large_enum_variant)]
pub enum ConcealedState {
    Void,
    Fungible(ConcealedValue),
    Structured(ConcealedData),
    Attachment(ConcealedAttach),
}

impl ConfidentialState for ConcealedState {
    fn state_type(&self) -> StateType {
        match self {
            ConcealedState::Void => StateType::Void,
            ConcealedState::Fungible(_) => StateType::Fungible,
            ConcealedState::Structured(_) => StateType::Structured,
            ConcealedState::Attachment(_) => StateType::Attachment,
        }
    }
    fn state_commitment(&self) -> ConcealedState { *self }
}

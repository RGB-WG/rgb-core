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

use core::fmt::Debug;
use core::hash::Hash;

use commit_verify::Conceal;
use strict_encoding::{StrictDecode, StrictDumb, StrictEncode};

use crate::{
    ConcealedAttach, ConcealedData, ConcealedValue, RevealedAttach, RevealedData, RevealedValue,
    LIB_NAME_RGB,
};

/// Marker trait for types of state which are just a commitment to the actual
/// state data.
pub trait ConfidentialState:
    Debug + Hash + StrictDumb + StrictEncode + StrictDecode + Eq + Copy
{
    fn state_type(&self) -> StateType;
    fn state_commitment(&self) -> StateCommitment;
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
    type Confidential: ConfidentialState;
    fn state_type(&self) -> StateType;
    fn state_data(&self) -> StateData;
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

    /// Value-based state, i.e. which can be committed to with a Pedersen
    /// commitment
    Fungible,

    /// State defined with custom data
    Structured,

    /// Attached data container
    Attachment,
}

/// Categories of the state
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB, tags = custom)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum StateData {
    #[strict_type(tag = 0x00, dumb)]
    Void,
    #[strict_type(tag = 0x01)]
    Fungible(RevealedValue),
    #[strict_type(tag = 0x02)]
    Structured(RevealedData),
    #[strict_type(tag = 0xFF)]
    Attachment(RevealedAttach),
}

impl ExposedState for StateData {
    type Confidential = StateCommitment;
    fn state_type(&self) -> StateType {
        match self {
            StateData::Void => StateType::Void,
            StateData::Fungible(_) => StateType::Fungible,
            StateData::Structured(_) => StateType::Structured,
            StateData::Attachment(_) => StateType::Attachment,
        }
    }
    fn state_data(&self) -> StateData { self.clone() }
}

impl Conceal for StateData {
    type Concealed = StateCommitment;
    fn conceal(&self) -> Self::Concealed {
        match self {
            StateData::Void => StateCommitment::Void,
            StateData::Fungible(value) => StateCommitment::Fungible(value.conceal()),
            StateData::Structured(data) => StateCommitment::Structured(data.conceal()),
            StateData::Attachment(attach) => StateCommitment::Attachment(attach.conceal()),
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB, tags = custom)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum StateCommitment {
    #[strict_type(tag = 0x00, dumb)]
    Void,
    #[strict_type(tag = 0x01)]
    Fungible(ConcealedValue),
    #[strict_type(tag = 0x02)]
    Structured(ConcealedData),
    #[strict_type(tag = 0xFF)]
    Attachment(ConcealedAttach),
}

impl ConfidentialState for StateCommitment {
    fn state_type(&self) -> StateType {
        match self {
            StateCommitment::Void => StateType::Void,
            StateCommitment::Fungible(_) => StateType::Fungible,
            StateCommitment::Structured(_) => StateType::Structured,
            StateCommitment::Attachment(_) => StateType::Attachment,
        }
    }
    fn state_commitment(&self) -> StateCommitment { *self }
}

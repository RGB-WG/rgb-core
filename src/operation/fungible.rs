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

//! This mod represents **atomic rational values** (or, simply just **value**),
//! it a value representing a portion of something whole with a certain fixed
//! level of precision (atomicity). Such values are commonly used to represent
//! some coins of fungible tokens, where each coin or token consists of an
//! integer number of atomic subdivisions of the total supply (like satoshis in
//! bitcoin represent just a portion, i.e. fixed-precision rational number, of
//! the total possible bitcoin supply). Such numbers demonstrate constant
//! properties regarding their total sum and, thus, can be made confidential
//! using elliptic curve homomorphic cryptography such as Pedesen commitments.

use core::fmt::Debug;
use core::num::ParseIntError;
use core::str::FromStr;
use std::hash::Hash;

use commit_verify::Conceal;
use strict_encoding::{StrictDecode, StrictDumb, StrictEncode};

use super::{ConfidentialState, ExposedState};
use crate::{schema, ConcealedState, RevealedState, StateType, LIB_NAME_RGB_COMMIT};

/// An atom of an additive state, which thus can be monomorphically encrypted.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, From)]
#[display(inner)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT, tags = custom)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase", untagged)
)]
pub enum FungibleState {
    /// 64-bit value.
    #[from]
    #[strict_type(tag = 8)] // Matches strict types U64 primitive value
    Bits64(u64),
    // When/if adding more variants do not forget to re-write FromStr impl
}

impl Default for FungibleState {
    fn default() -> Self { FungibleState::Bits64(0) }
}

impl From<RevealedValue> for FungibleState {
    fn from(revealed: RevealedValue) -> Self { revealed.value }
}

impl FromStr for FungibleState {
    type Err = ParseIntError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { s.parse().map(FungibleState::Bits64) }
}

impl From<FungibleState> for u64 {
    fn from(value: FungibleState) -> Self {
        match value {
            FungibleState::Bits64(val) => val,
        }
    }
}

impl FungibleState {
    pub fn fungible_type(&self) -> schema::FungibleType {
        match self {
            FungibleState::Bits64(_) => schema::FungibleType::Unsigned64Bit,
        }
    }

    pub fn as_u64(&self) -> u64 { (*self).into() }
}

/// State item for a homomorphically-encryptable state.
///
/// Consists of the 64-bit value and
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT, rename = "RevealedFungible")]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct RevealedValue {
    /// Original value in smallest indivisible units
    pub value: FungibleState,
}

impl RevealedValue {
    /// Convenience constructor.
    pub fn new(value: impl Into<FungibleState>) -> Self {
        Self {
            value: value.into(),
        }
    }
}

impl ExposedState for RevealedValue {
    type Confidential = ConcealedValue;
    fn state_type(&self) -> StateType { StateType::Fungible }
    fn state_data(&self) -> RevealedState { RevealedState::Fungible(*self) }
}

impl Conceal for RevealedValue {
    type Concealed = ConcealedValue;

    fn conceal(&self) -> Self::Concealed {
        ConcealedValue {
            value: self.value,
            concealed_dummy: (),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT, rename = "ConcealedFungible")]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct ConcealedValue {
    /// Original value in smallest indivisible units
    pub value: FungibleState,
    /// Field necessary only to avoid clash with RevealedValue during yaml deserialization
    pub concealed_dummy: (),
}

impl ConfidentialState for ConcealedValue {
    fn state_type(&self) -> StateType { StateType::Fungible }
    fn state_commitment(&self) -> ConcealedState { ConcealedState::Fungible(*self) }
}

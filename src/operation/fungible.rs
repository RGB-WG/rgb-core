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
//! the total possible bitcoin supply).

use core::fmt::Debug;
use std::hash::Hash;

use strict_encoding::{StrictDecode, StrictEncode};

use crate::{ExposedState, RevealedState, StateType, LIB_NAME_RGB_COMMIT};

/// An atom of an additive state, which thus can be monomorphically encrypted.
#[derive(
    Wrapper, WrapperMut, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default, From
)]
#[wrapper(Deref, Display, UpperHex, LowerHex, Octal, FromStr)]
#[wrapper_mut(DerefMut)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct FungibleState(pub u64);

impl ExposedState for FungibleState {
    fn state_type(&self) -> StateType { StateType::Fungible }
    fn state_data(&self) -> RevealedState { RevealedState::Fungible(*self) }
}

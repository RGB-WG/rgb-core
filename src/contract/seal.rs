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

pub use bp::seals::txout::blind::{
    ChainBlindSeal as GraphSeal, ParseError, SecretSeal, SingleBlindSeal as GenesisSeal,
};
pub use bp::seals::txout::TxoSeal;
use commit_verify::Conceal;
use strict_encoding::{StrictDecode, StrictDumb, StrictEncode};

pub trait ConfidentialSeal:
    Debug + Hash + StrictDumb + StrictEncode + StrictDecode + Eq + Ord + Copy
{
}

pub trait ExposedSeal:
    Debug
    + StrictDumb
    + StrictEncode
    + StrictDecode
    + Conceal<Concealed = Self::Confidential>
    + Eq
    + Ord
    + Copy
    + TxoSeal
{
    type Confidential: ConfidentialSeal;
}

impl ExposedSeal for GraphSeal {
    type Confidential = SecretSeal;
}

impl ExposedSeal for GenesisSeal {
    type Confidential = SecretSeal;
}

impl ConfidentialSeal for SecretSeal {}

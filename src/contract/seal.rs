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
use std::hash::Hash;

pub use bp::seals::txout::blind::{
    ChainBlindSeal as GraphSeal, ParseError, SecretSeal, SingleBlindSeal as GenesisSeal,
};
pub use bp::seals::txout::TxoSeal;
use bp::Txid;
use commit_verify::{CommitEncode, Conceal};
use strict_encoding::{StrictDecode, StrictDumb, StrictEncode};

use crate::LIB_NAME_RGB;

pub trait ExposedSeal:
    Debug
    + StrictDumb
    + StrictEncode
    + StrictDecode
    + CommitEncode
    + Conceal<Concealed = SecretSeal>
    + Eq
    + Ord
    + Copy
    + Hash
    + TxoSeal
{
}

impl ExposedSeal for GraphSeal {}

impl ExposedSeal for GenesisSeal {}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB, tags = custom, dumb = SealWitness::Genesis)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum SealWitness {
    #[strict_type(tag = 0)]
    #[display("~")]
    Genesis,

    #[strict_type(tag = 1)]
    #[display(inner)]
    Present(Txid),

    #[strict_type(tag = 2)]
    #[display("~")]
    Extension,
}

impl SealWitness {
    pub fn txid(&self) -> Option<Txid> {
        match self {
            SealWitness::Genesis | SealWitness::Extension => None,
            SealWitness::Present(txid) => Some(*txid),
        }
    }
    pub fn map_txid<U>(&self, f: impl FnOnce(Txid) -> U) -> Option<U> { self.txid().map(f) }
}

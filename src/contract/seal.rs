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
use commit_verify::{strategies, CommitVerify, Conceal, DigestExt, Sha256, UntaggedProtocol};
use strict_encoding::{StrictDecode, StrictDumb, StrictEncode, StrictWriter};

use crate::contract::contract::Output;
use crate::{Layer1, LIB_NAME_RGB};

pub trait ExposedSeal:
    Debug + StrictDumb + StrictEncode + StrictDecode + Eq + Ord + Copy + Hash + TxoSeal
{
}

impl ExposedSeal for GraphSeal {}

impl ExposedSeal for GenesisSeal {}

/*
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct SealPreimage(Bytes32);
 */

#[derive(Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB, tags = custom, dumb = Self::Bitcoin(strict_dumb!()))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[non_exhaustive]
pub enum SealDefinition<U: ExposedSeal> {
    #[strict_type(tag = 0x00)]
    Bitcoin(U),
    #[strict_type(tag = 0x01)]
    Liquid(U),
    /*
    #[strict_type(tag = 0x10)]
    Abraxas(SealPreimage),
    #[strict_type(tag = 0x11)]
    Prime(SealPreimage),
     */
}

impl<U: ExposedSeal> Conceal for SealDefinition<U> {
    type Concealed = SecretSeal;

    #[inline]
    fn conceal(&self) -> Self::Concealed { SecretSeal::commit(self) }
}

impl<U: ExposedSeal> CommitVerify<SealDefinition<U>, UntaggedProtocol> for SecretSeal {
    fn commit(reveal: &SealDefinition<U>) -> Self {
        let mut engine = Sha256::default();
        let w = StrictWriter::with(u32::MAX as usize, &mut engine);
        reveal.strict_encode(w).ok();
        engine.finish().into()
    }
}

impl<U: ExposedSeal> commit_verify::CommitStrategy for SealDefinition<U> {
    type Strategy = strategies::ConcealStrict;
}

impl SealDefinition<GenesisSeal> {
    pub fn transmutate(self) -> SealDefinition<GraphSeal> {
        match self {
            SealDefinition::Bitcoin(seal) => SealDefinition::Bitcoin(seal.transmutate()),
            SealDefinition::Liquid(seal) => SealDefinition::Liquid(seal.transmutate()),
            /*
            SealDefinition::Abraxas(seal) => SealDefinition::Abraxas(seal),
            SealDefinition::Prime(seal) => SealDefinition::Prime(seal),
             */
        }
    }
}

impl<U: ExposedSeal> SealDefinition<U> {
    pub fn layer1(self) -> Layer1 {
        match self {
            SealDefinition::Bitcoin(_) => Layer1::Bitcoin,
            SealDefinition::Liquid(_) => Layer1::Liquid,
        }
    }

    #[inline]
    pub fn output(self) -> Option<Output> {
        match self {
            SealDefinition::Bitcoin(seal) => seal.outpoint().map(Output::Bitcoin),
            SealDefinition::Liquid(seal) => seal.outpoint().map(Output::Liquid),
        }
    }

    pub fn output_or_witness(self, witness_id: WitnessId) -> Result<Output, Self> {
        match (self, witness_id) {
            (SealDefinition::Bitcoin(seal), WitnessId::Bitcoin(txid)) => {
                Ok(Output::Bitcoin(seal.outpoint_or(txid)))
            }
            (SealDefinition::Liquid(seal), WitnessId::Liquid(txid)) => {
                Ok(Output::Liquid(seal.outpoint_or(txid)))
            }
            (me, _) => Err(me),
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB, tags = custom, dumb = WitnessId::Bitcoin(strict_dumb!()))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[non_exhaustive]
pub enum WitnessId {
    #[strict_type(tag = 0x00)]
    #[display("bitcoin:{0}")]
    Bitcoin(Txid),

    #[strict_type(tag = 0x01)]
    #[display("liquid:{0}")]
    Liquid(Txid),
    // Prime,
    // Abraxas,
}

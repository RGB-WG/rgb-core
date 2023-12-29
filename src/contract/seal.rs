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
use std::cmp::Ordering;
use std::hash::Hash;
use std::num::NonZeroU32;

use bp::dbc::Method;
pub use bp::seals::txout::blind::{ChainBlindSeal, ParseError, SingleBlindSeal};
pub use bp::seals::txout::TxoSeal;
use bp::seals::txout::{CloseMethod, ExplicitSeal, SealTxid};
pub use bp::seals::SecretSeal;
use bp::Txid;
use commit_verify::{strategies, CommitVerify, Conceal, DigestExt, Sha256, UntaggedProtocol};
use strict_encoding::{StrictDecode, StrictDumb, StrictEncode, StrictType, StrictWriter};

use crate::{Layer1, XChain, LIB_NAME_RGB};

pub type GenesisSeal = SingleBlindSeal<Method>;
pub type GraphSeal = ChainBlindSeal<Method>;

/*
impl ToBaid58<32> for SecretSeal {
    const HRI: &'static str = "utxob";
    const CHUNKING: Option<Chunking> = CHUNKING_32CHECKSUM;
    fn to_baid58_payload(&self) -> [u8; 32] { self.0.into_inner() }
    fn to_baid58_string(&self) -> String { self.to_string() }
}
impl FromBaid58<32> for SecretSeal {}
impl FromStr for SecretSeal {
    type Err = Baid58ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SecretSeal::from_baid58_maybe_chunked_str(s, ':', ' ')
    }
}
impl Display for SecretSeal {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(f, "{::^}", self.to_baid58())
        } else {
            write!(f, "{::^.3}", self.to_baid58())
        }
    }
}

impl<Id: SealTxid> CommitVerify<BlindSeal<Id>, TapretFirst> for SecretSeal {
    fn commit(reveal: &BlindSeal<Id>) -> Self { Bytes32::commit(reveal).into() }
}

impl<Id: SealTxid> Conceal for BlindSeal<Id> {
    type Concealed = SecretSeal;

    #[inline]
    fn conceal(&self) -> Self::Concealed { SecretSeal::commit(self) }
}

impl<Id: SealTxid> BlindSeal<Id> {
    /// Converts revealed seal into concealed.
    #[inline]
    pub fn to_concealed_seal(&self) -> SecretSeal { self.conceal() }
}

mod test {
    use super::*;

    #[test]
    fn secret_seal_is_sha256d() {
        let reveal = BlindSeal {
            method: CloseMethod::TapretFirst,
            blinding: 54683213134637,
            txid: TxPtr::Txid(
                Txid::from_hex("646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839")
                    .unwrap(),
            ),
            vout: Vout::from(2),
        };
        assert_eq!(reveal.to_concealed_seal(), reveal.conceal())
    }

    #[test]
    fn secret_seal_baid58() {
        let seal = BlindSeal {
            method: CloseMethod::TapretFirst,
            blinding: 54683213134637,
            txid: TxPtr::Txid(
                Txid::from_hex("646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839")
                    .unwrap(),
            ),
            vout: Vout::from(2),
        }
        .to_concealed_seal();

        let baid58 = "utxob:2eFrirU-RjqLnqR74-AKRfdnc9M-DpvSRjmZG-mFPrw7nvu-Te1wy83";
        assert_eq!(baid58, seal.to_string());
        assert_eq!(baid58.replace('-', ""), format!("{seal:#}"));
        assert_eq!(seal.to_string(), seal.to_baid58_string());
        let reconstructed = SecretSeal::from_str(baid58).unwrap();
        assert_eq!(reconstructed, seal);
        let reconstructed = SecretSeal::from_str(&baid58.replace('-', "")).unwrap();
        assert_eq!(reconstructed, seal);
    }
}
 */

pub trait ExposedSeal:
    Debug + StrictDumb + StrictEncode + StrictDecode + Eq + Ord + Copy + Hash + TxoSeal
{
}

impl ExposedSeal for GraphSeal {}

impl ExposedSeal for GenesisSeal {}

impl<Id: SealTxid> ExposedSeal for ExplicitSeal<Id> {}

pub type OutputSeal = XSeal<ExplicitSeal<Txid>>;

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

pub type XSeal<T> = XChain<T>;

impl<U: ExposedSeal> Conceal for XSeal<U> {
    type Concealed = SecretSeal;

    #[inline]
    fn conceal(&self) -> Self::Concealed { SecretSeal::commit(self) }
}

impl<U: ExposedSeal> CommitVerify<XSeal<U>, UntaggedProtocol> for SecretSeal {
    fn commit(reveal: &XSeal<U>) -> Self {
        let mut engine = Sha256::default();
        let w = StrictWriter::with(u32::MAX as usize, &mut engine);
        reveal.strict_encode(w).ok();
        engine.finish().into()
    }
}

impl<U: ExposedSeal> commit_verify::CommitStrategy for XSeal<U> {
    type Strategy = strategies::ConcealStrict;
}

impl XSeal<GenesisSeal> {
    pub fn transmutate(self) -> XSeal<GraphSeal> {
        match self {
            XSeal::Bitcoin(seal) => XSeal::Bitcoin(seal.transmutate()),
            XSeal::Liquid(seal) => XSeal::Liquid(seal.transmutate()),
            /*
            SealDefinition::Abraxas(seal) => SealDefinition::Abraxas(seal),
            SealDefinition::Prime(seal) => SealDefinition::Prime(seal),
             */
        }
    }
}

impl<U: ExposedSeal> XSeal<U> {
    pub fn with(layer1: Layer1, seal: impl Into<U>) -> Self {
        match layer1 {
            Layer1::Bitcoin => XSeal::Bitcoin(seal.into()),
            Layer1::Liquid => XSeal::Liquid(seal.into()),
        }
    }

    pub fn layer1(self) -> Layer1 {
        match self {
            XSeal::Bitcoin(_) => Layer1::Bitcoin,
            XSeal::Liquid(_) => Layer1::Liquid,
        }
    }

    pub fn reduce_to_bp(self) -> Option<U> {
        Some(match self {
            XSeal::Bitcoin(seal) => seal,
            XSeal::Liquid(seal) => seal,
        })
    }

    pub fn method(self) -> CloseMethod {
        match self {
            XSeal::Bitcoin(seal) => seal.method(),
            XSeal::Liquid(seal) => seal.method(),
        }
    }

    #[inline]
    pub fn to_output_seal(self) -> Option<OutputSeal> {
        Some(match self {
            XSeal::Bitcoin(seal) => {
                let outpoint = seal.outpoint()?;
                XSeal::Bitcoin(ExplicitSeal::new(seal.method(), outpoint))
            }
            XSeal::Liquid(seal) => {
                let outpoint = seal.outpoint()?;
                XSeal::Liquid(ExplicitSeal::new(seal.method(), outpoint))
            }
        })
    }

    pub fn try_to_output_seal(self, witness_id: WitnessId) -> Result<OutputSeal, Self> {
        match (self, witness_id) {
            (XSeal::Bitcoin(seal), WitnessId::Bitcoin(txid)) => {
                Ok(XSeal::Bitcoin(ExplicitSeal::new(seal.method(), seal.outpoint_or(txid))))
            }
            (XSeal::Liquid(seal), WitnessId::Liquid(txid)) => {
                Ok(XSeal::Liquid(ExplicitSeal::new(seal.method(), seal.outpoint_or(txid))))
            }
            (me, _) => Err(me),
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[display("{height}@{timestamp}")]
pub struct WitnessPos {
    height: u32,
    timestamp: i64,
}

impl WitnessPos {
    pub fn new(height: u32, timestamp: i64) -> Option<Self> {
        if height == 0 || timestamp < 1231006505 {
            return None;
        }
        Some(WitnessPos { height, timestamp })
    }

    pub fn height(&self) -> NonZeroU32 { NonZeroU32::new(self.height).expect("invariant") }
}

impl PartialOrd for WitnessPos {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl Ord for WitnessPos {
    fn cmp(&self, other: &Self) -> Ordering { self.timestamp.cmp(&other.timestamp) }
}

/// RGB consensus information about the current mined height of a witness
/// transaction defining the ordering of the contract state data.
#[derive(Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Debug, Display, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB, tags = order)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum WitnessOrd {
    #[from]
    #[display(inner)]
    OnChain(WitnessPos),

    #[display("offchain")]
    #[strict_type(dumb)]
    OffChain,
}

impl WitnessOrd {
    pub fn with_mempool_or_height(height: u32, timestamp: i64) -> Self {
        WitnessPos::new(height, timestamp)
            .map(WitnessOrd::OnChain)
            .unwrap_or(WitnessOrd::OffChain)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB, tags = custom, dumb = WitnessId::Bitcoin(strict_dumb!()))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
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

impl PartialOrd for WitnessId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl Ord for WitnessId {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (WitnessId::Bitcoin(_), WitnessId::Liquid(_)) => Ordering::Greater,
            (WitnessId::Liquid(_), WitnessId::Bitcoin(_)) => Ordering::Less,
            (
                WitnessId::Bitcoin(txid1) | WitnessId::Liquid(txid1),
                WitnessId::Bitcoin(txid2) | WitnessId::Liquid(txid2),
            ) => txid1.cmp(txid2),
        }
    }
}

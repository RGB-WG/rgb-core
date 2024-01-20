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
use std::io::Write;
use std::num::NonZeroU32;

use bp::dbc::Method;
pub use bp::seals::txout::blind::{ChainBlindSeal, ParseError, SingleBlindSeal};
pub use bp::seals::txout::TxoSeal;
use bp::seals::txout::{BlindSeal, CloseMethod, ExplicitSeal, SealTxid, VerifyError, Witness};
pub use bp::seals::SecretSeal;
use bp::{dbc, Outpoint, Tx, Txid, Vout};
use commit_verify::{mpc, strategies, CommitEncode, CommitStrategy, Conceal};
use single_use_seals::SealWitness;
use strict_encoding::{StrictDecode, StrictDumb, StrictEncode, StrictType};

use crate::{XChain, XOutpoint, LIB_NAME_RGB};

pub type GenesisSeal = SingleBlindSeal<Method>;
pub type GraphSeal = ChainBlindSeal<Method>;

pub type OutputSeal = ExplicitSeal<Txid, Method>;

pub type WitnessId = XChain<Txid>;

pub type XGenesisSeal = XChain<GenesisSeal>;
pub type XGraphSeal = XChain<GraphSeal>;
pub type XOutputSeal = XChain<OutputSeal>;

pub trait ExposedSeal:
    Debug
    + StrictDumb
    + StrictEncode
    + StrictDecode
    + Eq
    + Ord
    + Copy
    + Hash
    + TxoSeal
    + Conceal<Concealed = SecretSeal>
{
}

impl ExposedSeal for GraphSeal {}

impl ExposedSeal for GenesisSeal {}

impl<Seal: TxoSeal> TxoSeal for XChain<Seal> {
    fn method(&self) -> CloseMethod {
        match self {
            XChain::Bitcoin(seal) | XChain::Liquid(seal) => seal.method(),
        }
    }

    fn txid(&self) -> Option<Txid> {
        match self {
            XChain::Bitcoin(seal) | XChain::Liquid(seal) => seal.txid(),
        }
    }

    fn vout(&self) -> Vout {
        match self {
            XChain::Bitcoin(seal) | XChain::Liquid(seal) => seal.vout(),
        }
    }

    fn outpoint(&self) -> Option<Outpoint> {
        match self {
            XChain::Bitcoin(seal) | XChain::Liquid(seal) => seal.outpoint(),
        }
    }

    fn txid_or(&self, default_txid: Txid) -> Txid {
        match self {
            XChain::Bitcoin(seal) | XChain::Liquid(seal) => seal.txid_or(default_txid),
        }
    }

    fn outpoint_or(&self, default_txid: Txid) -> Outpoint {
        match self {
            XChain::Bitcoin(seal) | XChain::Liquid(seal) => seal.outpoint_or(default_txid),
        }
    }
}

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

impl From<XChain<GenesisSeal>> for XOutpoint {
    #[inline]
    fn from(seal: XChain<GenesisSeal>) -> Self { seal.to_outpoint() }
}

impl XChain<GenesisSeal> {
    pub fn transmutate(self) -> XChain<GraphSeal> { self.map_ref(|seal| seal.transmutate()) }

    /// Converts seal into a transaction outpoint.
    #[inline]
    pub fn to_outpoint(&self) -> XOutpoint { self.map_ref(GenesisSeal::to_outpoint) }
}

impl<U: ExposedSeal> XChain<U> {
    pub fn method(self) -> CloseMethod
    where U: TxoSeal {
        match self {
            XChain::Bitcoin(seal) => seal.method(),
            XChain::Liquid(seal) => seal.method(),
        }
    }

    #[inline]
    pub fn to_output_seal(self) -> Option<XOutputSeal>
    where U: TxoSeal {
        Some(match self {
            XChain::Bitcoin(seal) => {
                let outpoint = seal.outpoint()?;
                XChain::Bitcoin(ExplicitSeal::new(seal.method(), outpoint))
            }
            XChain::Liquid(seal) => {
                let outpoint = seal.outpoint()?;
                XChain::Liquid(ExplicitSeal::new(seal.method(), outpoint))
            }
        })
    }

    pub fn try_to_output_seal(self, witness_id: WitnessId) -> Result<XOutputSeal, Self>
    where U: TxoSeal {
        match (self, witness_id) {
            (XChain::Bitcoin(seal), WitnessId::Bitcoin(txid)) => {
                Ok(XChain::Bitcoin(ExplicitSeal::new(seal.method(), seal.outpoint_or(txid))))
            }
            (XChain::Liquid(seal), WitnessId::Liquid(txid)) => {
                Ok(XChain::Liquid(ExplicitSeal::new(seal.method(), seal.outpoint_or(txid))))
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

pub type XPubWitness = XChain<Tx>;

pub type XWitness<Dbc> = XChain<Witness<Dbc>>;

impl XPubWitness {
    pub fn witness_id(&self) -> WitnessId {
        match self {
            Self::Bitcoin(tx) => WitnessId::Bitcoin(tx.txid()),
            Self::Liquid(tx) => WitnessId::Liquid(tx.txid()),
        }
    }
}

impl<Dbc: dbc::Proof> XWitness<Dbc> {
    pub fn witness_id(&self) -> WitnessId {
        match self {
            Self::Bitcoin(w) => WitnessId::Bitcoin(w.txid),
            Self::Liquid(w) => WitnessId::Liquid(w.txid),
        }
    }
}

impl<Dbc: dbc::Proof, Seal: TxoSeal> SealWitness<Seal> for XWitness<Dbc> {
    type Message = mpc::Commitment;
    type Error = VerifyError<Dbc::Error>;

    fn verify_seal(&self, seal: &Seal, msg: &Self::Message) -> Result<(), Self::Error> {
        match self {
            Self::Bitcoin(witness) | Self::Liquid(witness) => witness.verify_seal(seal, msg),
        }
    }

    fn verify_many_seals<'seal>(
        &self,
        seals: impl IntoIterator<Item = &'seal Seal>,
        msg: &Self::Message,
    ) -> Result<(), Self::Error>
    where
        Seal: 'seal,
    {
        match self {
            Self::Bitcoin(witness) | Self::Liquid(witness) => witness.verify_many_seals(seals, msg),
        }
    }
}

impl<Id: SealTxid> CommitStrategy for XChain<BlindSeal<Id>> {
    type Strategy = strategies::Strict;
}

impl<Id: SealTxid> XChain<BlindSeal<Id>> {
    /// Converts revealed seal into concealed.
    #[inline]
    pub fn to_secret_seal(&self) -> XChain<SecretSeal> { self.conceal() }
}

impl CommitEncode for XChain<SecretSeal> {
    fn commit_encode(&self, e: &mut impl Write) {
        e.write_all(&[self.layer1() as u8]).ok();
        self.as_reduced_unsafe().commit_encode(e);
    }
}

#[cfg(test)]
mod test {
    use amplify::hex::FromHex;
    use bp::seals::txout::TxPtr;

    use super::*;

    #[test]
    fn secret_seal_is_sha256d() {
        let reveal = XChain::Bitcoin(BlindSeal {
            method: CloseMethod::TapretFirst,
            blinding: 54683213134637,
            txid: TxPtr::Txid(
                Txid::from_hex("646ca5c1062619e2a2d60771c9dfd820551fb773e4dc8c4ed67965a8d1fae839")
                    .unwrap(),
            ),
            vout: Vout::from(2),
        });
        let secret = reveal.to_secret_seal();
        assert_eq!(
            secret.to_string(),
            "bc:utxob:6JZb8te-bSUsZzCJk-op9E4D8zf-SHTDu2t4W-T21NaPNnb-58DFM9"
        );
        assert_eq!(reveal.to_secret_seal(), reveal.conceal())
    }
}

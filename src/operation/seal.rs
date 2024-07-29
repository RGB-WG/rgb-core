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
use std::hash::Hash;

use bp::dbc::Method;
pub use bp::seals::txout::blind::{ChainBlindSeal, ParseError, SingleBlindSeal};
pub use bp::seals::txout::TxoSeal;
use bp::seals::txout::{BlindSeal, CloseMethod, ExplicitSeal, SealTxid, VerifyError, Witness};
pub use bp::seals::SecretSeal;
use bp::{dbc, Outpoint, Tx, Txid, Vout};
use commit_verify::{mpc, Conceal};
use single_use_seals::SealWitness;
use strict_encoding::{StrictDecode, StrictDumb, StrictEncode};

use crate::operation::xchain::Impossible;
use crate::{XChain, XOutpoint};

pub type GenesisSeal = SingleBlindSeal<Method>;
pub type GraphSeal = ChainBlindSeal<Method>;

pub type OutputSeal = ExplicitSeal<Txid, Method>;

pub type XWitnessId = XChain<Txid>;

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
            XChain::Other(_) => unreachable!(),
        }
    }

    fn txid(&self) -> Option<Txid> {
        match self {
            XChain::Bitcoin(seal) | XChain::Liquid(seal) => seal.txid(),
            XChain::Other(_) => unreachable!(),
        }
    }

    fn vout(&self) -> Vout {
        match self {
            XChain::Bitcoin(seal) | XChain::Liquid(seal) => seal.vout(),
            XChain::Other(_) => unreachable!(),
        }
    }

    fn outpoint(&self) -> Option<Outpoint> {
        match self {
            XChain::Bitcoin(seal) | XChain::Liquid(seal) => seal.outpoint(),
            XChain::Other(_) => unreachable!(),
        }
    }

    fn txid_or(&self, default_txid: Txid) -> Txid {
        match self {
            XChain::Bitcoin(seal) | XChain::Liquid(seal) => seal.txid_or(default_txid),
            XChain::Other(_) => unreachable!(),
        }
    }

    fn outpoint_or(&self, default_txid: Txid) -> Outpoint {
        match self {
            XChain::Bitcoin(seal) | XChain::Liquid(seal) => seal.outpoint_or(default_txid),
            XChain::Other(_) => unreachable!(),
        }
    }
}

/*
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
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
    pub fn to_outpoint(&self) -> XOutpoint { self.map_ref(GenesisSeal::to_outpoint).into() }
}

impl<U: ExposedSeal> XChain<U> {
    pub fn method(self) -> CloseMethod
    where U: TxoSeal {
        match self {
            XChain::Bitcoin(seal) => seal.method(),
            XChain::Liquid(seal) => seal.method(),
            XChain::Other(_) => unreachable!(),
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
            XChain::Other(_) => unreachable!(),
        })
    }

    pub fn try_to_output_seal(self, witness_id: XWitnessId) -> Result<XOutputSeal, Self>
    where U: TxoSeal {
        self.to_output_seal()
            .or(match (self, witness_id) {
                (XChain::Bitcoin(seal), XWitnessId::Bitcoin(txid)) => {
                    Some(XChain::Bitcoin(ExplicitSeal::new(seal.method(), seal.outpoint_or(txid))))
                }
                (XChain::Liquid(seal), XWitnessId::Liquid(txid)) => {
                    Some(XChain::Liquid(ExplicitSeal::new(seal.method(), seal.outpoint_or(txid))))
                }
                _ => None,
            })
            .ok_or(self)
    }
}

pub type XWitnessTx<X = Impossible> = XChain<Tx, X>;

impl XWitnessTx {
    pub fn witness_id(&self) -> XWitnessId {
        match self {
            Self::Bitcoin(tx) => XWitnessId::Bitcoin(tx.txid()),
            Self::Liquid(tx) => XWitnessId::Liquid(tx.txid()),
            Self::Other(_) => unreachable!(),
        }
    }
}

impl<Dbc: dbc::Proof> XChain<Witness<Dbc>> {
    pub fn witness_id(&self) -> XWitnessId {
        match self {
            Self::Bitcoin(w) => XWitnessId::Bitcoin(w.txid),
            Self::Liquid(w) => XWitnessId::Liquid(w.txid),
            Self::Other(_) => unreachable!(),
        }
    }
}

impl<Dbc: dbc::Proof, Seal: TxoSeal> SealWitness<Seal> for XChain<Witness<Dbc>> {
    type Message = mpc::Commitment;
    type Error = VerifyError<Dbc::Error>;

    fn verify_seal(&self, seal: &Seal, msg: &Self::Message) -> Result<(), Self::Error> {
        match self {
            Self::Bitcoin(witness) | Self::Liquid(witness) => witness.verify_seal(seal, msg),
            Self::Other(_) => unreachable!(),
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
            Self::Other(_) => unreachable!(),
        }
    }
}

impl<Id: SealTxid> XChain<BlindSeal<Id>> {
    /// Converts revealed seal into concealed.
    #[inline]
    pub fn to_secret_seal(&self) -> XChain<SecretSeal> { self.conceal() }
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
            "bc:utxob:lD72u61i-sxCEKth-vqjH0mI-kcEwa1Q-fbnPLon-tDtXveO-keHh0"
        );
        assert_eq!(reveal.to_secret_seal(), reveal.conceal())
    }
}

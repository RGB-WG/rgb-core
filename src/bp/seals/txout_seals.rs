// LNP/BP Core Library implementing LNPBP specifications & standards
// Written in 2020 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the MIT License
// along with this software.
// If not, see <https://opensource.org/licenses/MIT>.


use bitcoin::{Transaction, OutPoint};

use crate::single_use_seals::{Message, SingleUseSeal, SealMedium, SealStatus};
use crate::bp::ShortId;
// use crate::bp::dbc::{TxCommitment, TxContainer};
use super::tx_graph::{SpendingStatus, TxGraph};


// TODO: Fixit
pub type TxoutWitness = ();

pub struct TxoutSeal<'a> {
    seal_definition: OutPoint,
    prototyper: &'a dyn TxPrototype,
}

impl<'a> TxoutSeal<'a> {
    fn new(seal_definition: OutPoint, prototyper: &'a dyn TxPrototype) -> Self {
        Self { seal_definition, prototyper }
    }
}

impl SingleUseSeal for TxoutSeal<'_> {
    type Witness = TxoutWitness;
    type Definition = OutPoint;

    fn close(&self, over: &Message) -> Self::Witness {
        let (mut tx, txout_index) = self.prototyper.tx_prototype(self.seal_definition);
        tx.input.get_mut(txout_index as usize);
        unimplemented!()
    }

    fn verify(&self, msg: &Message, witness: &Self::Witness) -> bool {
        unimplemented!()
    }
}

impl<'a, TXGRAPH> SealMedium<'a, TxoutSeal<'a>> for TXGRAPH
where
    TXGRAPH: TxGraph + TxPrototype,
{
    type PublicationId = ShortId;
    type Error = Error<TXGRAPH::AccessError>;

    fn define_seal(&'a self, seal_definition: &OutPoint) -> Result<TxoutSeal<'a>, Self::Error> {
        let outpoint = seal_definition;
        match self.spending_status(outpoint)? {
            SpendingStatus::Unknown => Err(Error::InvalidSealDefinition),
            SpendingStatus::Invalid => Err(Error::InvalidSealDefinition),
            SpendingStatus::Unspent => Ok(TxoutSeal::new(outpoint.clone(), self)),
            SpendingStatus::Spent(_) => Err(Error::SpentTxout),
        }
    }

    fn get_seal_status(&self, seal: &TxoutSeal) -> Result<SealStatus, Self::Error> {
        match self.spending_status(&seal.seal_definition)? {
            SpendingStatus::Unknown => Ok(SealStatus::Undefined),
            SpendingStatus::Invalid => Ok(SealStatus::Undefined),
            SpendingStatus::Unspent => Ok(SealStatus::Undefined),
            SpendingStatus::Spent(_) => Ok(SealStatus::Closed),
        }
    }

    // TODO: Implement publication-related methods
}

pub trait TxPrototype {
    fn tx_prototype(&self, outpoint: OutPoint) -> (Transaction, u16);
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Display, From, Error)]
#[display_from(Debug)]
pub enum Error<AE: std::error::Error> {
    InvalidSealDefinition,
    SpentTxout,
    #[derive_from(AE)]
    MediumAccessError(AE)
}
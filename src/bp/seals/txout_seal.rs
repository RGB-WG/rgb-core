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

use bitcoin::{OutPoint, Transaction};

use super::{SpendingStatus, TxGraph, Witness};
use crate::bp::dbc::{Container, TxContainer};
use crate::bp::ShortId;
use crate::commit_verify::CommitEmbedVerify;
use crate::single_use_seals::{Message, SealMedium, SealStatus, SingleUseSeal};

pub struct TxoutSeal<'a, RESOLVER>
where
    RESOLVER: TxResolve,
{
    seal_definition: OutPoint,
    resolver: &'a RESOLVER,
}

impl<'a, RESOLVER> TxoutSeal<'a, RESOLVER>
where
    RESOLVER: TxResolve,
{
    fn new(seal_definition: OutPoint, resolver: &'a RESOLVER) -> Self {
        Self {
            seal_definition,
            resolver,
        }
    }
}

impl<'a, RESOLVER> SingleUseSeal for TxoutSeal<'a, RESOLVER>
where
    RESOLVER: TxResolve,
{
    type Witness = Witness;
    type Definition = OutPoint;

    // TODO: Decide with unfailability of seal closing
    fn close(&self, over: &Message) -> Self::Witness {
        let container = self
            .resolver
            .tx_container(self.seal_definition)
            .expect("Seal close procedure is cannot fail");
        let tx_commitment = Transaction::commit_embed(container.clone(), &over)
            .expect("Seal close procedure is cannot fail");
        Witness(tx_commitment, container.to_proof())
    }

    fn verify(&self, msg: &Message, witness: &Self::Witness) -> bool {
        unimplemented!()
    }
}

impl<'a, TXGRAPH> SealMedium<'a, TxoutSeal<'a, TXGRAPH>> for TXGRAPH
where
    TXGRAPH: TxGraph + TxResolve,
{
    type PublicationId = ShortId;
    type Error = Error<TXGRAPH::AccessError>;

    fn define_seal(
        &'a self,
        seal_definition: &OutPoint,
    ) -> Result<TxoutSeal<TXGRAPH>, Self::Error> {
        let outpoint = seal_definition;
        match self.spending_status(outpoint)? {
            SpendingStatus::Unknown => Err(Error::InvalidSealDefinition),
            SpendingStatus::Invalid => Err(Error::InvalidSealDefinition),
            SpendingStatus::Unspent => Ok(TxoutSeal::new(outpoint.clone(), self)),
            SpendingStatus::Spent(_) => Err(Error::SpentTxout),
        }
    }

    fn get_seal_status(&self, seal: &TxoutSeal<TXGRAPH>) -> Result<SealStatus, Self::Error> {
        match self.spending_status(&seal.seal_definition)? {
            SpendingStatus::Unknown => Ok(SealStatus::Undefined),
            SpendingStatus::Invalid => Ok(SealStatus::Undefined),
            SpendingStatus::Unspent => Ok(SealStatus::Undefined),
            SpendingStatus::Spent(_) => Ok(SealStatus::Closed),
        }
    }

    // TODO: Implement publication-related methods
}

pub trait TxResolve {
    type Error: std::error::Error;
    fn tx_container(&self, outpoint: OutPoint) -> Result<TxContainer, Self::Error>;
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Display, From, Error)]
#[display_from(Debug)]
pub enum Error<AE: std::error::Error> {
    InvalidSealDefinition,
    SpentTxout,
    #[derive_from(AE)]
    MediumAccessError(AE),
}

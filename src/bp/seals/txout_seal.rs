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

use amplify::Wrapper;
use bitcoin::{OutPoint, Transaction};

use super::{Error, SpendingStatus, TxGraph, Witness};
use crate::bp::dbc::{Container, TxCommitment, TxContainer, TxSupplement};
use crate::bp::ShortId;
use crate::commit_verify::EmbedCommitVerify;
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
    type Error = Error;

    fn close(&self, over: &Message) -> Result<Self::Witness, Self::Error> {
        let container = self
            .resolver
            .tx_container(self.seal_definition)
            .map_err(|_| Error::ResolverError)?;
        let tx_commitment = TxCommitment::embed_commit(&container, &over)?;
        Ok(Witness(tx_commitment, container.to_proof()))
    }

    fn verify(&self, msg: &Message, witness: &Self::Witness) -> Result<bool, Self::Error> {
        let (host, supplement) = self
            .resolver
            .tx_and_data(self.seal_definition)
            .map_err(|_| Error::ResolverError)?;
        let found_seals = host
            .input
            .iter()
            .filter(|txin| txin.previous_output == self.seal_definition);
        if found_seals.count() != 1 {
            Err(Error::ResolverLying)?
        }
        let container = TxContainer::reconstruct(&witness.1, &supplement, &host)?;
        let commitment = TxCommitment::from_inner(host);
        Ok(commitment.verify(&container, &msg)?)
    }
}

impl<'a, TXGRAPH> SealMedium<'a, TxoutSeal<'a, TXGRAPH>> for TXGRAPH
where
    TXGRAPH: TxGraph + TxResolve,
{
    type PublicationId = ShortId;
    type Error = Error;

    fn define_seal(
        &'a self,
        seal_definition: &OutPoint,
    ) -> Result<TxoutSeal<TXGRAPH>, Self::Error> {
        let outpoint = seal_definition;
        match self
            .spending_status(outpoint)
            .map_err(|_| Error::MediumAccessError)?
        {
            SpendingStatus::Unknown => Err(Error::InvalidSealDefinition),
            SpendingStatus::Invalid => Err(Error::InvalidSealDefinition),
            SpendingStatus::Unspent => Ok(TxoutSeal::new(outpoint.clone(), self)),
            SpendingStatus::Spent(_) => Err(Error::SpentTxout),
        }
    }

    fn get_seal_status(&self, seal: &TxoutSeal<TXGRAPH>) -> Result<SealStatus, Self::Error> {
        match self
            .spending_status(&seal.seal_definition)
            .map_err(|_| Error::MediumAccessError)?
        {
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
    fn tx_and_data(&self, outpoint: OutPoint) -> Result<(Transaction, TxSupplement), Self::Error>;
}

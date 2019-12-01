// LNP/BP Rust Library
// Written in 2019 by
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

use bitcoin::{Amount, TxOut, Transaction, hashes::sha256};
use secp256k1::PublicKey;

use crate::common::*;
use super::{*, pubkey::Error};


#[derive(Clone, Eq, PartialEq)]
pub struct TxContainer {
    pub entropy: u32,
    pub tx: Transaction,
    pub container: TxoutContainer,
}

#[derive(Clone, Eq, PartialEq)]
pub struct TxCommitment {
    pub entropy: u32,
    pub tx: Transaction,
    pub tweaked: TxoutCommitment,
    pub original: TxoutContainer,
}

impl<MSG> CommitmentVerify<MSG> for TxCommitment where
    MSG: EmbedCommittable<Self> + EmbedCommittable<TxoutCommitment> + AsSlice
{

    #[inline]
    fn reveal_verify(&self, msg: &MSG) -> bool {
        <Self as EmbeddedCommitment<MSG>>::reveal_verify(&self, msg)
    }
}

impl<MSG> EmbeddedCommitment<MSG> for TxCommitment where
    MSG: EmbedCommittable<Self> + EmbedCommittable<TxoutCommitment> + AsSlice
{
    type Container = TxContainer;
    type Error = Error;

    #[inline]
    fn get_original_container(&self) -> Self::Container {
        let root = match &self.tweaked {
            TxoutCommitment::LockScript(script) => None,
            TxoutCommitment::TapRoot(cmt) => Some(cmt.script_root),
        };
        TxContainer {
            entropy: self.entropy,
            tx: self.tx.clone(),
            container: self.original.clone()
        }
    }

    fn from(container: &Self::Container, msg: &MSG) -> Result<Self, Self::Error> {
        let tx = container.tx.clone();
        let fee = 0; // FIXME: tx.get_fee();
        let entropy = container.entropy;
        let nouts = tx.output.len();
        let vout = (fee + entropy) % (nouts as u32);
        let txout = tx.output[vout as usize].clone();
        let txout_container = container.container.clone();
        let tweaked: TxoutCommitment = EmbeddedCommitment::<MSG>::from(&txout_container, msg)?;
        Ok(Self {
            entropy, tx, original: txout_container, tweaked
        })
    }
}

impl<T> Verifiable<TxCommitment> for T where T: AsSlice { }

impl<T> EmbedCommittable<TxCommitment> for T where T: AsSlice { }

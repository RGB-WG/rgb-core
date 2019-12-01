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
use super::*;


#[derive(Clone, Eq, PartialEq)]
pub struct TxContainer {
    pub entropy: u64,
    pub script_root: Option<sha256::Hash>,
    pub tx: Transaction,
}

#[derive(Clone, Eq, PartialEq)]
pub struct TxCommitment {
    pub entropy: u64,
    pub fee: Amount,
    pub tweaked: TxoutCommitment,
    pub original: Transaction,
}

impl<MSG> CommitmentVerify<MSG> for TxCommitment where
    MSG: EmbedCommittable<TxContainer, Self> + AsSlice
{

    #[inline]
    fn reveal_verify(&self, msg: &MSG) -> bool {
        <Self as EmbeddedCommitment<TxContainer, MSG>>::reveal_verify(&self, msg)
    }
}

impl<MSG> EmbeddedCommitment<TxContainer, MSG> for TxCommitment where
    MSG: EmbedCommittable<TxContainer, Self> + AsSlice,
{
    type Error = ();

    #[inline]
    fn get_original_container(&self) -> &TxContainer {
        let root = match &self.tweaked {
            TxoutCommitment::LockScript(script) => None,
            TxoutCommitment::TapRoot(cmt) => Ok(cmt.script_root),
        };
        &TxContainer {
            entropy: self.entropy,
            script_root: root,
            tx: self.tx
        }
    }

    fn from(container: &TxContainer, msg: &MSG) -> Result<Self, Self::Error> {
        let tx = &container.tx;
        let entropy = container.entropy;
        let fee = tx.get_fee();
        let nouts = tx.output.len();
        let vout = (fee + entropy) % nouts;
        let txout = tx.output[vout];
        let txout_container = TxoutContainer::from(txout, container.script_root)?;
        let tweaked = TxoutCommitment::from(&txout_container, msg)?;
        Ok(Self {
            entropy, fee, original: txout, tweaked
        })
    }
}

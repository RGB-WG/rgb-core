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

use bitcoin::{PublicKey, Transaction, Script};
use crate::commitments::{base::*, secp256k1::*, txout::*};

pub struct TxContainer {
    pub tx: Transaction,
    pub redeem_script: Option<Script>,
    pub vout: Option<u64>,
    pub entropy: u32,
}

pub struct TxProofs {
    pub redeem_script: Option<Script>,
    pub original_pubkeys: Vec<PublicKey>,
    pub entropy: u32,
}

impl CommitmentContainer for TxContainer {}
impl CommitmentProofs for TxProofs {}

impl CommitmentEngine<TweakSource, TxContainer, TxProofs> for TweakEngine {
    fn commit(&self, message: &TweakSource, container: &mut TxContainer) -> TxProofs { unimplemented!() }
    fn verify(&self, message: &TweakSource, container: &TxContainer, proofs: &TxProofs) -> bool { unimplemented!() }
}

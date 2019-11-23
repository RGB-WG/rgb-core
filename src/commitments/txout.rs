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

use bitcoin::{TxOut, Script, PublicKey};
use crate::commitments::{base::*, secp256k1::*};

pub struct TxoutContainer {
    pub txout: TxOut,
    pub redeem_script: Option<Script>,
}

pub struct TxoutProofs {
    pub redeem_script: Option<Script>,
    pub original_pubkeys: Vec<PublicKey>,
}

impl CommitmentContainer for TxoutContainer {}
impl CommitmentProofs for TxoutProofs {}

impl CommitmentEngine<TweakSource, TxoutContainer, TxoutProofs> for TweakEngine {
    fn commit(&self, message: &TweakSource, container: &mut TxoutContainer) -> TxoutProofs { unimplemented!() }
    fn verify(&self, message: &TweakSource, container: &TxoutContainer, proofs: &TxoutProofs) -> bool { unimplemented!() }
}

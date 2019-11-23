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

use secp256k1::{PublicKey, Secp256k1, All};
use bitcoin::hashes::sha256;
use crate::commitments::base::*;

pub struct MessageSource {
    pub msg: sha256::Hash,
    pub protocol: sha256::Hash,
}
type MultimsgSource = Vec<MessageSource>;

impl CommittableMessage for MultimsgSource {}

pub struct MultimsgContainer(Box<[u8]>);
pub struct PedersenProof {
    pub blinding_factor: sha256::Hash,
    pub pedersen_commitment: PublicKey,
}
type MultimsgProofs = Vec<PedersenProof>;

impl CommitmentContainer for MultimsgContainer {}
impl CommitmentProofs for MultimsgProofs {}

pub struct MultimsgEngine {}

impl CommitmentEngine<MultimsgSource, MultimsgContainer, MultimsgProofs> for MultimsgEngine {
    fn commit(&self, message: &MultimsgSource, container: &mut MultimsgContainer) -> MultimsgProofs { unimplemented!() }
    fn verify(&self, message: &MultimsgSource, container: &MultimsgContainer, proofs: &MultimsgProofs) -> bool { unimplemented!() }
}

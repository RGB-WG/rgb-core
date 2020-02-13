// LNP/BP Rust Library
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

use secp256k1zkp::*;
use rand;

// TODO: Convert Amount into a wrapper type later
//wrapper!(Amount, _AmountPhantom, u64, doc="64-bit data for amounts");
pub type Amount = u64;

pub struct AmountCommitment {
    pub commitment: pedersen::Commitment,
    pub bulletproof: pedersen::RangeProof,
}

impl From<Amount> for AmountCommitment {
    fn from(amount: Amount) -> Self {
        let secp = secp256k1zkp::Secp256k1::with_caps(ContextFlag::Commit);
        let blinding = secp256k1zkp::key::SecretKey::new(&secp, &mut rand::thread_rng());
        let value = amount;
        let commitment = secp.commit(value, blinding.clone())
            .expect("Internal inconsistency in Grin secp256k1zkp library Pedersen commitments");
        let bulletproof = secp.bullet_proof(
            value, blinding.clone(),
            blinding.clone(), blinding.clone(),
            None, None
        );
        AmountCommitment {
            commitment, bulletproof
        }
    }
}


#[non_exhaustive]
#[derive(Clone, PartialEq, PartialOrd, Debug, Display)]
#[display_from(Debug)]
pub enum Data {
    Balance(Amount),
    Binary(Box<[u8]>),
    // TODO: Add other supported bound state types according to the schema
}

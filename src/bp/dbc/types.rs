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

use crate::bp::RedeemScript;
use bitcoin::{hashes::sha256, secp256k1};

pub trait Container {
    fn to_proof(&self) -> Proof;
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
#[display_from(Debug)]
pub struct Proof {
    pub pubkey: secp256k1::PublicKey,
    pub suppl: ProofSuppl,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
#[display_from(Debug)]
#[non_exhaustive]
pub enum ProofSuppl {
    None,
    RedeemScript(RedeemScript),
    Taproot(sha256::Hash),
}

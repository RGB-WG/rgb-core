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

use super::Error;
use crate::bp::LockScript;
use bitcoin::{hashes::sha256, secp256k1};

pub trait Container: Sized {
    type Supplement;
    type Host;

    fn reconstruct(
        proof: &Proof,
        supplement: &Self::Supplement,
        host: &Self::Host,
    ) -> Result<Self, Error>;

    fn deconstruct(self) -> (Proof, Self::Supplement);

    fn to_proof(&self) -> Proof;
    fn into_proof(self) -> Proof;
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
#[display_from(Debug)]
pub struct Proof {
    pub pubkey: secp256k1::PublicKey,
    pub script_info: ScriptInfo,
}

impl From<secp256k1::PublicKey> for Proof {
    fn from(pubkey: secp256k1::PublicKey) -> Self {
        Self {
            pubkey,
            script_info: ScriptInfo::None,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
#[display_from(Debug)]
#[non_exhaustive]
pub enum ScriptInfo {
    None,
    LockScript(LockScript),
    Taproot(sha256::Hash),
}

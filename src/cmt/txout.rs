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

use bitcoin::{Script, PublicKey, hashes::sha256};

use crate::common::{*, ScriptPubkeyType::*};
use super::PubkeyCommitment;


#[derive(Clone, Eq, PartialEq)]
pub struct LockscriptCommitment {
    pub tweaked: LockScript,
    pub original: LockScript,
}

#[derive(Clone, Eq, PartialEq)]
pub struct TaprootCommitment {
    pub script_root: sha256::Hash,
    pub pubkey_commitment: PubkeyCommitment,
}

#[derive(Clone, Eq, PartialEq)]
pub enum TxoutCommitment {
    LockScript(LockscriptCommitment),
    TapRoot(TaprootCommitment),
}

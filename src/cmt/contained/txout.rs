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

use crate::common::{*, ScriptPubkeyType::*};
use crate::cvp::SplitData;
use super::container::*;

// LNP
pub type HashLock = sha256::Hash;
pub type HashPreimage = sha256::Hash;

// LNP
pub enum DeterministicScript {
    MultiSig(u8, Vec<PublicKey>),
    LNToRemote(u8, PublicKey),
    LNHtlcSuccess(u8, HashLock, PublicKey, PublicKey),
    LNHtlcTimeout(u8, HashLock, PublicKey, PublicKey),
}

pub enum OutputSuppl {
    PubkeyHash(PublicKey),
    ScriptHash(DeterministicScript),
    Taproot(PublicKey),
}

pub struct TxoutCommitment {
    pub txout: TxOut,
    pub suppl: Option<TxoutSuppl>,
    pub original_pubkeys: Vec<PublicKey>,
}

// pub type TxoutCommitment = SplitData<TxOut, CommitmentSuppl>;

impl Container for TxoutCommitment {
    type Message = Box<dyn AsBytes>;

    fn commit(&mut self, msg: &Self::Message) {
        match ScriptPubkeyType::from(&self.txout.script_pubkey) {
            P2S(&script) => self.commit_script(script),
            P2PK(&pubkey) => self.commit_pubkey(pubkey),
            P2PKH(&pkh) | W0_P2WPKH(&pkh) => self.commit_pkh(pkh),
            P2SH(&sh) | W0_P2WSH(&sh) => self.commit_sh(sh),
            P2OR(&data) => self.commit_opreturn(data),
            W1_P2TR(&pk) => self.commit_taproot(pk),
        }
    }
}

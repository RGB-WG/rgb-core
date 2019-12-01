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


pub type HashLock = sha256::Hash;
pub type HashPreimage = sha256::Hash;


pub enum ScriptPubkeyType {
    P2S(Script),
    P2PK(PublicKey),
    P2PKH(sha256d::Hash),
    P2SH(hash160::Hash),
    P2OR(Box<[u8]>),
    P2WPKH(sha256d::Hash),
    P2WSH(hash160::Hash),
    P2TR(PublicKey),
}

pub enum DeterministicScript {
    MultiSig(u8, Vec<PublicKey>),
    LNToRemote(u8, PublicKey),
    LNHtlcSuccess(u8, HashLock, PublicKey, PublicKey),
    LNHtlcTimeout(u8, HashLock, PublicKey, PublicKey),
}

pub struct ScriptPubkey(Script);

impl ScriptPubkey {
    fn get_type(&self) -> ScriptPubkeyType {

    }
}

pub enum ScriptPubkeySuppl {
    PubkeyHash(PublicKey),
    ScriptHash(DeterministicScript),
    Taproot(PublicKey),
}

pub enum Thing {
    Pubkey(PublicKey),
    TaprootPubkey(PublicKey),
    Script(DeterministicScript, Vec<PublicKey>),
    Unspendable(PublicKey),
}

impl Thing {
    pub fn commit(&mut self, msg: &Message) -> Result<(), Error> { unimplemented!() }
    pub fn verify(&self, msg: &Message) -> bool { unimplemented!() }
}

pub struct ThingCommitment {
    pub thing: Thing,
    pub commitment: Commitment,
}

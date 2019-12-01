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

use std::marker::PhantomData;

use bitcoin::hashes::{Hash, Error, sha256, hash160};
use bitcoin::hash_types::*;
use std::ops::{Index, RangeFull};
use bitcoin::Script;
use secp256k1::PublicKey;

use crate::Wrapper;


pub struct BitcoinTag(sha256::Hash);

impl BitcoinTag {
    pub fn tag(tag: &str) -> Self {
        let hash = sha256::Hash::hash(tag.as_bytes());
        let mut prefix = hash.to_vec();
        prefix.extend(hash.to_vec());
        BitcoinTag(sha256::Hash::hash(&prefix[..]))
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, Error> {
        Ok(BitcoinTag(sha256::Hash::from_slice(slice)?))
    }
}

impl Index<RangeFull> for BitcoinTag {
    type Output = [u8];
    fn index(&self, _: RangeFull) -> &[u8] { &self.0[..] }
}

//
// PubkeyScript -+====> LockScript <----+
//               |                      |
//               +----> RedeemScript ---+
//               |
//               +----> TapScript
//

pub struct _LockScriptPhantom;
pub struct _PubkeyScriptPhantom;
pub struct _RedeemScriptPhantom;
pub struct _TapScriptPhantom;
pub type LockScript = Wrapper<Script, PhantomData<_LockScriptPhantom>>;
pub type PubkeyScript = Wrapper<Script, PhantomData<_PubkeyScriptPhantom>>;
pub type RedeemScript = Wrapper<Script, PhantomData<_RedeemScriptPhantom>>;
pub type TapScript = Wrapper<Script, PhantomData<_TapScriptPhantom>>;

pub enum ScriptPubkeyType {
    P2S(Script),
    P2PK(PublicKey),
    P2PKH(PubkeyHash),
    P2SH(ScriptHash),
    P2OR(Box<[u8]>),
    P2WPKH(WPubkeyHash),
    P2WSH(WScriptHash),
    P2TR(PublicKey),
}

impl From<Script> for ScriptPubkeyType {
    fn from(script_pubkey: Script) -> Self {
        Self::P2S(script_pubkey)
    }
}

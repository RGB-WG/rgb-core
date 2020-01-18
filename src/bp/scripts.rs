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

use core::marker::PhantomData;
use bitcoin::{
    hashes::Hash,
    hash_types::*,
    blockdata::script::*,
    secp256k1
};
use miniscript::{Miniscript, Terminal::*, Error, MiniscriptKey};
use crate::Wrapper;


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

impl LockScript {
    pub fn extract_pubkeys(&self) -> Result<Vec<PubkeyHash>, Error> {
        let miniscript = Miniscript::parse(&self.clone().into_inner())?;
        Ok(Self::extract_pubkeys_from_terminal(&miniscript))
    }

    fn extract_pubkeys_from_terminal(miniscript: &Miniscript<miniscript::bitcoin::PublicKey>) -> Vec<PubkeyHash> {
        match &miniscript.node {
            Pk(key) => vec![key.to_pubkeyhash().into()],
            PkH(pkh) => vec![
                PubkeyHash::from_slice(&pkh[..]).expect("Directo conversion from another hash can't fail")
            ],
            ThreshM(_, keys) =>
                keys.iter().map(|key| key.to_pubkeyhash().into()).collect(),

            Alt(node) |
            Swap(node) |
            Check(node) |
            DupIf(node) |
            Verify(node) |
            NonZero(node) |
            ZeroNotEqual(node) =>
                Self::extract_pubkeys_from_terminal(&node),
            AndV(node1, node2) |
            AndB(node1, node2) |
            OrB(node1, node2) |
            OrD(node1, node2) |
            OrC(node1, node2) |
            OrI(node1, node2) =>
                Self::extract_pubkeys_from_terminal(&node1).into_iter()
                    .chain(Self::extract_pubkeys_from_terminal(&node2).into_iter()).collect(),
            AndOr(node1, node2, node3) =>
                Self::extract_pubkeys_from_terminal(&node1).into_iter()
                    .chain(Self::extract_pubkeys_from_terminal(&node2).into_iter())
                    .chain(Self::extract_pubkeys_from_terminal(&node3).into_iter()).collect(),
            Thresh(_, node_vec) =>
                node_vec.into_iter().flat_map(|node|
                    Self::extract_pubkeys_from_terminal(&node)
                ).collect(),

            _ => vec![],
        }
    }
}


pub enum ScriptPubkeyType {
    P2S(Script),
    P2PK(secp256k1::PublicKey),
    P2PKH(PubkeyHash),
    P2SH(ScriptHash),
    P2OR(Vec<u8>),
    P2WPKH(WPubkeyHash),
    P2WSH(WScriptHash),
    P2TR(secp256k1::PublicKey),
}
use ScriptPubkeyType::*;

impl From<Script> for ScriptPubkeyType {
    fn from(script_pubkey: Script) -> Self {
        Self::P2S(script_pubkey)
    }
}

impl From<ScriptPubkeyType> for PubkeyScript {
    fn from(spkt: ScriptPubkeyType) -> PubkeyScript {
        PubkeyScript::from_inner(match spkt {
            P2S(script) => script,
            P2PK(pubkey) =>
                Builder::gen_p2pk(&bitcoin::PublicKey { compressed: false, key: pubkey }).into_script(),
            P2PKH(pubkey_hash) => Builder::gen_p2pkh(&pubkey_hash).into_script(),
            P2SH(script_hash) => Builder::gen_p2sh(&script_hash).into_script(),
            P2OR(data) => Builder::gen_op_return(&data).into_script(),
            P2WPKH(wpubkey_hash) => Builder::gen_v0_p2wpkh(&wpubkey_hash).into_script(),
            P2WSH(wscript_hash) => Builder::gen_v0_p2wsh(&wscript_hash).into_script(),
            P2TR(pubkey) => unimplemented!(),
        })
    }
}
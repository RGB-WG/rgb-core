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

use bitcoin::blockdata::script::Builder;
use bitcoin::secp256k1;

use super::{
    Container, LockscriptCommitment, LockscriptContainer, Proof, ProofSuppl, PubkeyCommitment,
    TaprootCommitment, TaprootContainer,
};
use crate::bp::PubkeyScript;
use crate::commit_verify::CommitEmbedVerify;

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
#[display_from(Debug)]
#[non_exhaustive]
pub enum ScriptPubkeyContainer {
    PublicKey(secp256k1::PublicKey),
    PubkeyHash(secp256k1::PublicKey),
    ScriptHash(LockscriptContainer),
    TapRoot(TaprootContainer),
    OpReturn(secp256k1::PublicKey),
    OtherScript(LockscriptContainer),
}

impl Container for ScriptPubkeyContainer {
    fn to_proof(&self) -> Proof {
        use ScriptPubkeyContainer::*;

        let mut suppl = ProofSuppl::None;
        let pubkey = match self {
            PublicKey(pubkey) => pubkey.clone(),
            PubkeyHash(pubkey) => pubkey.clone(),
            ScriptHash(lsc) => {
                suppl = ProofSuppl::RedeemScript(lsc.script.clone());
                lsc.pubkey
            }
            TapRoot(trc) => {
                suppl = ProofSuppl::Taproot(trc.script_root);
                trc.intermediate_key
            }
            OpReturn(pubkey) => pubkey.clone(),
            OtherScript(lsc) => lsc.pubkey,
            _ => unimplemented!(),
        };
        Proof { pubkey, suppl }
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
#[display_from(Debug)]
#[non_exhaustive]
pub enum ScriptPubkeyCommitment {
    PublicKey(PubkeyCommitment),
    PubkeyHash(PubkeyCommitment),
    ScriptHash(LockscriptCommitment),
    TapRoot(TaprootCommitment),
    OpReturn(PubkeyCommitment),
    OtherScript(LockscriptCommitment),
}

impl From<ScriptPubkeyContainer> for PubkeyScript {
    fn from(container: ScriptPubkeyContainer) -> Self {
        use ScriptPubkeyContainer::*;
        let script = match container {
            OtherScript(script_continer) => (*script_continer.script).clone(),
            PublicKey(pubkey) => Builder::gen_p2pk(&bitcoin::PublicKey {
                compressed: true,
                key: pubkey,
            })
            .into_script(),
            PubkeyHash(pubkey) => {
                let keyhash = bitcoin::PublicKey {
                    compressed: true,
                    key: pubkey,
                }
                .wpubkey_hash();
                Builder::gen_v0_p2wpkh(&keyhash).into_script()
            }
            ScriptHash(script_container) => {
                let script = (*script_container.script).clone();
                Builder::gen_v0_p2wsh(&script.wscript_hash()).into_script()
            }
            OpReturn(data) => {
                let keyhash = bitcoin::PublicKey {
                    compressed: true,
                    key: data,
                }
                .wpubkey_hash();
                Builder::gen_op_return(&keyhash.to_vec()).into_script()
            }
            TapRoot(taproot_container) => unimplemented!(),
            _ => unimplemented!(),
        };
        script.into()
    }
}

impl From<ScriptPubkeyCommitment> for PubkeyScript {
    fn from(commitment: ScriptPubkeyCommitment) -> Self {
        use ScriptPubkeyCommitment::*;
        let script = match commitment {
            OtherScript(script_commitment) => (*(*script_commitment)).clone(),
            PublicKey(pubkey) => Builder::gen_p2pk(&bitcoin::PublicKey {
                compressed: true,
                key: *pubkey,
            })
            .into_script(),
            PubkeyHash(pubkey) => {
                let keyhash = bitcoin::PublicKey {
                    compressed: true,
                    key: *pubkey,
                }
                .wpubkey_hash();
                Builder::gen_v0_p2wpkh(&keyhash).into_script()
            }
            ScriptHash(script_commitment) => {
                let script = (*script_commitment).clone();
                Builder::gen_v0_p2wsh(&script.wscript_hash()).into_script()
            }
            OpReturn(pubkey) => {
                let keyhash = bitcoin::PublicKey {
                    compressed: true,
                    key: *pubkey,
                }
                .wpubkey_hash();
                Builder::gen_op_return(&keyhash.to_vec()).into_script()
            }
            TapRoot(taproot_commitment) => unimplemented!(),
            _ => unimplemented!(),
        };
        script.into()
    }
}

impl<MSG> CommitEmbedVerify<MSG> for ScriptPubkeyCommitment
where
    MSG: AsRef<[u8]>,
{
    type Container = ScriptPubkeyContainer;
    type Error = super::Error;

    fn commit_embed(container: Self::Container, msg: &MSG) -> Result<Self, Self::Error> {
        Ok(match container {
            ScriptPubkeyContainer::PublicKey(pubkey) => {
                let cmt = PubkeyCommitment::commit_embed(pubkey, msg)?;
                ScriptPubkeyCommitment::PublicKey(cmt)
            }
            ScriptPubkeyContainer::PubkeyHash(pubkey) => {
                let cmt = PubkeyCommitment::commit_embed(pubkey, msg)?;
                ScriptPubkeyCommitment::PublicKey(cmt)
            }
            ScriptPubkeyContainer::ScriptHash(script) => {
                let cmt = LockscriptCommitment::commit_embed(script, msg)?;
                ScriptPubkeyCommitment::ScriptHash(cmt)
            }
            ScriptPubkeyContainer::TapRoot(container) => {
                let cmt = TaprootCommitment::commit_embed(container, msg)?;
                ScriptPubkeyCommitment::TapRoot(cmt)
            }
            ScriptPubkeyContainer::OpReturn(pubkey) => {
                let cmt = PubkeyCommitment::commit_embed(pubkey, msg)?;
                ScriptPubkeyCommitment::PublicKey(cmt)
            }
            ScriptPubkeyContainer::OtherScript(script) => {
                let cmt = LockscriptCommitment::commit_embed(script, msg)?;
                ScriptPubkeyCommitment::OtherScript(cmt)
            }
            _ => unimplemented!(),
        })
    }
}

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

use super::{LockscriptCommitment, PubkeyCommitment, TaprootCommitment, TaprootContainer};
use crate::bp::scripts::{LockScript, PubkeyScript};
use crate::primitives::commit_verify::CommitEmbedVerify;
use bitcoin::blockdata::script::Builder;
use bitcoin::secp256k1;

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
#[display_from(Debug)]
#[non_exhaustive]
pub enum ScriptPubkeyContainer {
    PublicKey(secp256k1::PublicKey),
    PubkeyHash(secp256k1::PublicKey),
    ScriptHash(LockScript),
    TapRoot(TaprootContainer),
    OpReturn(secp256k1::PublicKey),
    OtherScript(PubkeyScript),
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
#[display_from(Debug)]
#[non_exhaustive]
pub enum ScriptPubkeyCommitment {
    PublicKey(PubkeyCommitment),
    LockScript(LockscriptCommitment),
    TapRoot(TaprootCommitment),
}

impl From<ScriptPubkeyContainer> for PubkeyScript {
    fn from(container: ScriptPubkeyContainer) -> Self {
        let script = match container {
            ScriptPubkeyContainer::OtherScript(script) => (*script).clone(),
            ScriptPubkeyContainer::PublicKey(pubkey) => Builder::gen_p2pk(&bitcoin::PublicKey {
                compressed: false,
                key: pubkey,
            })
            .into_script(),
            ScriptPubkeyContainer::PubkeyHash(pubkey) => {
                let keyhash = bitcoin::PublicKey {
                    compressed: false,
                    key: pubkey,
                }
                .wpubkey_hash();
                Builder::gen_v0_p2wpkh(&keyhash).into_script()
            }
            ScriptPubkeyContainer::ScriptHash(script) => {
                let script = (*script).clone();
                Builder::gen_v0_p2wsh(&script.wscript_hash()).into_script()
            }
            ScriptPubkeyContainer::OpReturn(data) => {
                let keyhash = bitcoin::PublicKey {
                    compressed: false,
                    key: data,
                }
                .wpubkey_hash();
                Builder::gen_op_return(&keyhash.to_vec()).into_script()
            }
            ScriptPubkeyContainer::TapRoot(taproot_container) => unimplemented!(),
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
                ScriptPubkeyCommitment::LockScript(cmt)
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
                // FIXME: Extract it from the txout
                let script = LockScript::from((*script).clone());
                let cmt = LockscriptCommitment::commit_embed(script, msg)?;
                ScriptPubkeyCommitment::LockScript(cmt)
            }
            _ => unimplemented!(),
        })
    }
}

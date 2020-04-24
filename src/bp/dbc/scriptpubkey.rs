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
use core::convert::TryFrom;

use super::{
    Container, LockscriptCommitment, LockscriptContainer, Proof, ProofSuppl, PubkeyCommitment,
    TaprootContainer,
};
use crate::bp::dbc::Error;
use crate::bp::scripts::ScriptPubkeyDescriptor;
use crate::bp::PubkeyScript;
use crate::commit_verify::CommitEmbedVerify;

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
#[display_from(Debug)]
#[non_exhaustive]
// TODO: Convert in simplier structure with bp::scripts::Encoding
pub enum ScriptPubkeyContainer {
    PublicKey(secp256k1::PublicKey),
    PubkeyHash(secp256k1::PublicKey),
    ScriptHash(LockscriptContainer),
    WPubkeyHash(secp256k1::PublicKey),
    WScriptHash(LockscriptContainer),
    SHWPubkeyHash(secp256k1::PublicKey),
    SHWScriptHash(LockscriptContainer),
    TapRoot(TaprootContainer),
    OpReturn(secp256k1::PublicKey),
    OtherScript(LockscriptContainer),
}

impl Container for ScriptPubkeyContainer {
    type Supplement = Option<()>;
    type Commitment = PubkeyScript;

    fn restore(
        proof: &Proof,
        _: &Self::Supplement,
        commitment: &Self::Commitment,
    ) -> Result<Self, Error> {
        use ScriptPubkeyContainer as Cont;
        use ScriptPubkeyDescriptor as Descr;
        let (lockscript, tapscript_hash) = match &proof.suppl {
            ProofSuppl::None => (None, None),
            ProofSuppl::RedeemScript(script) => (Some(script), None),
            ProofSuppl::Taproot(hash) => (None, Some(hash)),
            _ => unimplemented!(),
        };
        Ok(
            match ScriptPubkeyDescriptor::try_from(commitment.clone())? {
                Descr::P2SH(_) | Descr::P2S(_) => Cont::OtherScript(LockscriptContainer {
                    script: lockscript.ok_or(Error::InvalidProofSupplement)?.clone(),
                    pubkey: proof.pubkey,
                }),
                Descr::P2PK(_) | Descr::P2PKH(_) => Cont::PublicKey(proof.pubkey),
                Descr::P2OR(_) => Cont::OpReturn(proof.pubkey),
                Descr::P2WPKH(_) => Cont::WPubkeyHash(proof.pubkey),
                Descr::P2WSH(_) => Cont::WScriptHash(LockscriptContainer {
                    script: lockscript.ok_or(Error::InvalidProofSupplement)?.clone(),
                    pubkey: proof.pubkey,
                }),
                Descr::P2TR(_) => Cont::TapRoot(TaprootContainer {
                    script_root: tapscript_hash.ok_or(Error::InvalidProofSupplement)?.clone(),
                    intermediate_key: proof.pubkey,
                }),
                _ => unimplemented!(),
            },
        )
    }

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

impl<MSG> CommitEmbedVerify<MSG> for PubkeyScript
where
    MSG: AsRef<[u8]>,
{
    type Container = ScriptPubkeyContainer;
    type Error = super::Error;

    fn commit_embed(container: Self::Container, msg: &MSG) -> Result<Self, Self::Error> {
        use ScriptPubkeyContainer::*;
        Ok(match container {
            PublicKey(pubkey) => {
                let pk = *PubkeyCommitment::commit_embed(pubkey, msg)?;
                let bpk = bitcoin::PublicKey {
                    compressed: true,
                    key: pk,
                };
                Builder::gen_p2pk(&bpk).into_script().into()
            }
            PubkeyHash(pubkey) => {
                let pk = *PubkeyCommitment::commit_embed(pubkey, msg)?;
                let bpk = bitcoin::PublicKey {
                    compressed: true,
                    key: pk,
                };
                Builder::gen_p2pkh(&bpk.pubkey_hash()).into_script().into()
            }
            ScriptHash(script) => {
                let script = (**LockscriptCommitment::commit_embed(script, msg)?).clone();
                Builder::gen_p2sh(&script.script_hash())
                    .into_script()
                    .into()
            }
            WPubkeyHash(pubkey) => {
                let pk = *PubkeyCommitment::commit_embed(pubkey, msg)?;
                let bpk = bitcoin::PublicKey {
                    compressed: true,
                    key: pk,
                };
                Builder::gen_v0_p2wpkh(&bpk.wpubkey_hash())
                    .into_script()
                    .into()
            }
            WScriptHash(script) => {
                let script = (**LockscriptCommitment::commit_embed(script, msg)?).clone();
                Builder::gen_v0_p2wsh(&script.wscript_hash())
                    .into_script()
                    .into()
            }
            // TODO: Implement P2SH-P2W* schemes
            SHWPubkeyHash(pubkey) => unimplemented!(),
            SHWScriptHash(script) => unimplemented!(),
            TapRoot(container) => unimplemented!(),
            OpReturn(pubkey) => {
                let pubkey = *PubkeyCommitment::commit_embed(pubkey, msg)?;
                Builder::gen_op_return(&pubkey.serialize().to_vec())
                    .into_script()
                    .into()
            }
            OtherScript(script) => {
                let script = (**LockscriptCommitment::commit_embed(script, msg)?).clone();
                script.into()
            }
            _ => unreachable!(),
        })
    }
}

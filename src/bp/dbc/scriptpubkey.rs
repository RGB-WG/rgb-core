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

use amplify::Wrapper;
use bitcoin::blockdata::script::Builder;
use bitcoin::{hashes::sha256, secp256k1};
use core::convert::TryFrom;

use super::{
    Container, Error, LNPBP1Commitment, LNPBP1Container, LockscriptCommitment, LockscriptContainer,
    Proof, ScriptInfo, TaprootCommitment, TaprootContainer,
};
use crate::bp::{GenerateScripts, LockScript, PubkeyScript, ScriptPubkeyDescriptor, Strategy};
use crate::commit_verify::EmbedCommitVerify;

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
#[display_from(Debug)]
#[non_exhaustive]
pub enum ScriptPubkeyComposition {
    PublicKey,
    PubkeyHash,
    ScriptHash,
    WPubkeyHash,
    WScriptHash,
    SHWPubkeyHash,
    SHWScriptHash,
    TapRoot,
    OpReturn,
    PlainScript,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
#[display_from(Debug)]
pub struct ScriptPubkeyContainer {
    pub pubkey: secp256k1::PublicKey,
    pub script_info: ScriptInfo,
    pub scriptpubkey_composition: ScriptPubkeyComposition,
    /// Single SHA256 hash of the protocol-specific tag
    pub tag: sha256::Hash,
}

impl ScriptPubkeyContainer {
    pub fn construct(
        protocol_tag: &sha256::Hash,
        pubkey: secp256k1::PublicKey,
        script_info: ScriptInfo,
        scriptpubkey_composition: ScriptPubkeyComposition,
    ) -> Self {
        Self {
            pubkey,
            script_info,
            scriptpubkey_composition,
            tag: protocol_tag.clone(),
        }
    }
}

impl Container for ScriptPubkeyContainer {
    /// Out supplement is a protocol-specific tag in its hashed form
    type Supplement = sha256::Hash;
    type Host = PubkeyScript;

    fn reconstruct(
        proof: &Proof,
        supplement: &Self::Supplement,
        host: &Self::Host,
    ) -> Result<Self, Error> {
        use ScriptPubkeyComposition as Comp;
        use ScriptPubkeyDescriptor as Descr;

        let (lockscript, _) = match &proof.script_info {
            ScriptInfo::None => (None, None),
            ScriptInfo::LockScript(script) => (Some(script), None),
            ScriptInfo::Taproot(hash) => (None, Some(hash)),
        };

        let mut proof = proof.clone();
        let composition = match ScriptPubkeyDescriptor::try_from(host.clone())? {
            Descr::P2SH(script_hash) => {
                let script = Builder::gen_p2sh(&script_hash).into_script();
                if let Some(lockscript) = lockscript {
                    if *lockscript.gen_script_pubkey(Strategy::LegacyHashed) == script {
                        Comp::ScriptHash
                    } else if *lockscript.gen_script_pubkey(Strategy::WitnessScriptHash) == script {
                        Comp::SHWScriptHash
                    } else {
                        Err(Error::InvalidProofStructure)?
                    }
                } else {
                    if *proof.pubkey.gen_script_pubkey(Strategy::WitnessScriptHash) == script {
                        Comp::SHWPubkeyHash
                    } else {
                        Err(Error::InvalidProofStructure)?
                    }
                }
            }
            Descr::P2S(script) => {
                proof.script_info = ScriptInfo::LockScript(LockScript::from(script.to_inner()));
                Comp::PlainScript
            }
            Descr::P2PK(_) => Comp::PubkeyHash,
            Descr::P2PKH(_) => Comp::PublicKey,
            Descr::P2OR(_) => Comp::OpReturn,
            Descr::P2WPKH(_) => Comp::WPubkeyHash,
            Descr::P2WSH(_) => Comp::WScriptHash,
            Descr::P2TR(_) => Comp::TapRoot,
        };
        let proof = proof;

        match composition {
            Comp::PublicKey
            | Comp::PubkeyHash
            | Comp::WPubkeyHash
            | Comp::SHWPubkeyHash
            | Comp::OpReturn => {
                if let ScriptInfo::None = proof.script_info {
                } else {
                    Err(Error::InvalidProofStructure)?
                }
            }
            Comp::PlainScript | Comp::ScriptHash | Comp::WScriptHash | Comp::SHWScriptHash => {
                if let ScriptInfo::LockScript(_) = proof.script_info {
                } else {
                    Err(Error::InvalidProofStructure)?
                }
            }
            Comp::TapRoot => {
                if let ScriptInfo::Taproot(_) = proof.script_info {
                } else {
                    Err(Error::InvalidProofStructure)?
                }
            }
        }

        Ok(Self {
            pubkey: proof.pubkey,
            script_info: proof.script_info,
            scriptpubkey_composition: composition,
            tag: supplement.clone(),
        })
    }

    fn deconstruct(self) -> (Proof, Self::Supplement) {
        (
            Proof {
                pubkey: self.pubkey,
                script_info: self.script_info,
            },
            self.tag,
        )
    }

    fn to_proof(&self) -> Proof {
        Proof {
            pubkey: self.pubkey.clone(),
            script_info: self.script_info.clone(),
        }
    }

    fn into_proof(self) -> Proof {
        Proof {
            pubkey: self.pubkey,
            script_info: self.script_info,
        }
    }
}

wrapper!(
    ScriptPubkeyCommitment,
    PubkeyScript,
    doc = "[PubkeyScript] containing LNPBP-2 commitment",
    derive = [PartialEq, Eq, Hash]
);

impl<MSG> EmbedCommitVerify<MSG> for ScriptPubkeyCommitment
where
    MSG: AsRef<[u8]>,
{
    type Container = ScriptPubkeyContainer;
    type Error = super::Error;

    fn embed_commit(container: &Self::Container, msg: &MSG) -> Result<Self, Self::Error> {
        use ScriptPubkeyComposition::*;
        let script_pubkey = if let ScriptInfo::LockScript(ref lockscript) = container.script_info {
            let lockscript = LockscriptCommitment::embed_commit(
                &LockscriptContainer {
                    script: lockscript.clone(),
                    pubkey: container.pubkey,
                    tag: container.tag,
                },
                msg,
            )?
            .into_inner();
            match container.scriptpubkey_composition {
                PlainScript => lockscript.gen_script_pubkey(Strategy::Exposed),
                ScriptHash => lockscript.gen_script_pubkey(Strategy::LegacyHashed),
                WScriptHash => lockscript.gen_script_pubkey(Strategy::WitnessV0),
                SHWScriptHash => lockscript.gen_script_pubkey(Strategy::WitnessScriptHash),
                _ => Err(Error::InvalidProofStructure)?,
            }
        } else if let ScriptInfo::Taproot(taproot_hash) = container.script_info {
            if container.scriptpubkey_composition != TapRoot {
                Err(Error::InvalidProofStructure)?
            }
            let _taproot = TaprootCommitment::embed_commit(
                &TaprootContainer {
                    script_root: taproot_hash,
                    intermediate_key: container.pubkey,
                    tag: container.tag,
                },
                msg,
            )?;
            // TODO: Finalize taproot commitments once taproot will be finalized
            // We don't know yet how to form scripPubkey from Taproot data
            unimplemented!()
        } else {
            let pubkey = *LNPBP1Commitment::embed_commit(
                &LNPBP1Container {
                    pubkey: container.pubkey,
                    tag: container.tag,
                },
                msg,
            )?;
            match container.scriptpubkey_composition {
                PublicKey => pubkey.gen_script_pubkey(Strategy::Exposed),
                PubkeyHash => pubkey.gen_script_pubkey(Strategy::LegacyHashed),
                WPubkeyHash => pubkey.gen_script_pubkey(Strategy::WitnessV0),
                SHWScriptHash => pubkey.gen_script_pubkey(Strategy::WitnessScriptHash),
                OpReturn => Builder::gen_op_return(&pubkey.serialize().to_vec())
                    .into_script()
                    .into(),
                _ => Err(Error::InvalidProofStructure)?,
            }
        };
        Ok(ScriptPubkeyCommitment::from_inner(script_pubkey))
    }
}

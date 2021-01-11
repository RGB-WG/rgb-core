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
use bitcoin::blockdata::script::Script;
use bitcoin::hashes::{sha256, Hmac};
use bitcoin::secp256k1;
use core::convert::TryFrom;

use super::{
    Container, Error, LockscriptCommitment, LockscriptContainer, Proof,
    PubkeyCommitment, PubkeyContainer, TaprootCommitment, TaprootContainer,
};
use crate::bp::{descriptor, LockScript, PubkeyScript, ToPubkeyScript};
use crate::commit_verify::EmbedCommitVerify;

/// Enum defining how given `scriptPubkey` is constructed from the script data
/// or a public key. It is similar to Bitcoin Core descriptors, however it does
/// provide additional variants required for RGB, in particular - `OpReturn`
/// variant with a requirement of public key presence (this key will contain
/// commitment). Because of this we can't use miniscript descriptors as well;
/// also in miniscript, descriptor contains a script source, while here the
/// script source is kept separately and is a part of the [`Proof`], while
/// [`DescriptorInfo`] is not included into the proof (it can be guessed from
/// a given proof and `scriptPubkey` and we'd like to preserve space with
/// client-validated data).
#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
#[display(Debug)]
#[non_exhaustive]
pub enum ScriptEncodeMethod {
    PublicKey,
    PubkeyHash,
    ScriptHash,
    WPubkeyHash,
    WScriptHash,
    ShWPubkeyHash,
    ShWScriptHash,
    Taproot,
    OpReturn,
    Bare,
}

/// Structure keeping the minimum of information (bytewise) required to verify
/// deterministic bitcoin commitment given only the transaction source, its
/// fee and protocol-specific constants. It is a part of the [`Proof`] data.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
#[display(doc_comments)]
#[non_exhaustive]
pub enum ScriptEncodeData {
    /// Public key. Since we keep the original public key as a part of a proof,
    /// and value of the tweaked key can be reconstructed with DBC source data
    /// and the original pubkey, so we do not need to keep any additional data
    /// here).
    SinglePubkey,

    /// Any output containing script information, aside from OP_RETURN outputs
    /// (using [`ScriptInfo::SimplePubkey`]) and tapscript.
    /// We have to store full original script in it's byte form since when
    /// the deteministic bitcoin commitment is verified, the output may be
    /// still unspent and we will not be able to reconstruct the script without
    /// this data kept in the client-validated part.
    LockScript(LockScript),

    /// Taproot-based outputs. We need to keep only the hash of the taprscript
    /// merkle tree root.
    Taproot(sha256::Hash),
}

impl Default for ScriptEncodeData {
    fn default() -> Self {
        Self::SinglePubkey
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
#[display(Debug)]
pub struct SpkContainer {
    pub pubkey: secp256k1::PublicKey,
    pub method: ScriptEncodeMethod,
    pub source: ScriptEncodeData,
    /// Single SHA256 hash of the protocol-specific tag
    pub tag: sha256::Hash,
    /// Tweaking factor stored after [ScriptPubkeyContainer::commit_verify]
    /// procedure
    pub tweaking_factor: Option<Hmac<sha256::Hash>>,
}

pub(super) mod strict_encoding {
    use super::*;
    use crate::strict_encoding::{Error, StrictDecode, StrictEncode};
    use std::io;

    #[derive(
        Copy,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        FromPrimitive,
        ToPrimitive,
        Debug,
    )]
    #[repr(u8)]
    pub(in super::super) enum EncodingTag {
        None = 0,
        LockScript = 1,
        Taproot = 2,
    }
    impl_enum_strict_encoding!(EncodingTag);

    impl StrictEncode for ScriptEncodeData {
        fn strict_encode<E: io::Write>(
            &self,
            mut e: E,
        ) -> Result<usize, strict_encoding::Error> {
            Ok(match self {
                ScriptEncodeData::SinglePubkey => {
                    EncodingTag::None.strict_encode(&mut e)?
                }
                ScriptEncodeData::LockScript(val) => {
                    strict_encode_list!(e; EncodingTag::LockScript, val)
                }
                ScriptEncodeData::Taproot(val) => {
                    strict_encode_list!(e; EncodingTag::Taproot, val)
                }
            })
        }
    }

    impl StrictDecode for ScriptEncodeData {
        fn strict_decode<D: io::Read>(
            mut d: D,
        ) -> Result<Self, strict_encoding::Error> {
            let format = EncodingTag::strict_decode(&mut d)?;
            Ok(match format {
                EncodingTag::None => ScriptEncodeData::SinglePubkey,
                EncodingTag::LockScript => ScriptEncodeData::LockScript(
                    LockScript::strict_decode(&mut d)?,
                ),
                EncodingTag::Taproot => ScriptEncodeData::Taproot(
                    sha256::Hash::strict_decode(&mut d)?,
                ),
            })
        }
    }

    #[cfg(test)]
    mod test {
        use super::*;

        #[test]
        fn test_encoding_tag_exhaustive() {
            test_enum_u8_exhaustive!(EncodingTag;
                EncodingTag::None => 0,
                EncodingTag::LockScript => 1,
                EncodingTag::Taproot => 2
            );
        }
    }
}

impl SpkContainer {
    pub fn construct(
        protocol_tag: &sha256::Hash,
        pubkey: secp256k1::PublicKey,
        source: ScriptEncodeData,
        method: ScriptEncodeMethod,
    ) -> Self {
        Self {
            pubkey,
            source,
            method,
            tag: protocol_tag.clone(),
            tweaking_factor: None,
        }
    }
}

impl Container for SpkContainer {
    /// Out supplement is a protocol-specific tag in its hashed form
    type Supplement = sha256::Hash;
    type Host = PubkeyScript;

    fn reconstruct(
        proof: &Proof,
        supplement: &Self::Supplement,
        host: &Self::Host,
    ) -> Result<Self, Error> {
        let (lockscript, _) = match &proof.source {
            ScriptEncodeData::SinglePubkey => (None, None),
            ScriptEncodeData::LockScript(script) => (Some(script), None),
            ScriptEncodeData::Taproot(hash) => (None, Some(hash)),
        };

        let mut proof = proof.clone();
        let method = match descriptor::Compact::try_from(host.clone())? {
            descriptor::Compact::Sh(script_hash) => {
                let script = Script::new_p2sh(&script_hash);
                if let Some(lockscript) = lockscript {
                    if *lockscript
                        .to_pubkey_script(descriptor::Category::Hashed)
                        == script
                    {
                        ScriptEncodeMethod::ScriptHash
                    } else if *lockscript
                        .to_pubkey_script(descriptor::Category::Nested)
                        == script
                    {
                        ScriptEncodeMethod::ShWScriptHash
                    } else {
                        Err(Error::InvalidProofStructure)?
                    }
                } else {
                    if *proof
                        .pubkey
                        .to_pubkey_script(descriptor::Category::Nested)
                        == script
                    {
                        ScriptEncodeMethod::ShWPubkeyHash
                    } else {
                        Err(Error::InvalidProofStructure)?
                    }
                }
            }
            descriptor::Compact::Bare(script)
                if script.as_inner().is_op_return() =>
            {
                ScriptEncodeMethod::OpReturn
            }
            descriptor::Compact::Bare(script) => {
                proof.source = ScriptEncodeData::LockScript(LockScript::from(
                    script.to_inner(),
                ));
                ScriptEncodeMethod::Bare
            }
            descriptor::Compact::Pk(_) => ScriptEncodeMethod::PublicKey,
            descriptor::Compact::Pkh(_) => ScriptEncodeMethod::PubkeyHash,
            descriptor::Compact::Wpkh(_) => ScriptEncodeMethod::WPubkeyHash,
            descriptor::Compact::Wsh(_) => ScriptEncodeMethod::WScriptHash,
            descriptor::Compact::Taproot(_) => ScriptEncodeMethod::Taproot,
        };
        let proof = proof;

        match method {
            ScriptEncodeMethod::PublicKey
            | ScriptEncodeMethod::PubkeyHash
            | ScriptEncodeMethod::WPubkeyHash
            | ScriptEncodeMethod::ShWPubkeyHash
            | ScriptEncodeMethod::OpReturn => {
                if let ScriptEncodeData::SinglePubkey = proof.source {
                } else {
                    Err(Error::InvalidProofStructure)?
                }
            }
            ScriptEncodeMethod::Bare
            | ScriptEncodeMethod::ScriptHash
            | ScriptEncodeMethod::WScriptHash
            | ScriptEncodeMethod::ShWScriptHash => {
                if let ScriptEncodeData::LockScript(_) = proof.source {
                } else {
                    Err(Error::InvalidProofStructure)?
                }
            }
            ScriptEncodeMethod::Taproot => {
                if let ScriptEncodeData::Taproot(_) = proof.source {
                } else {
                    Err(Error::InvalidProofStructure)?
                }
            }
        }

        Ok(Self {
            pubkey: proof.pubkey,
            source: proof.source,
            method,
            tag: supplement.clone(),
            tweaking_factor: None,
        })
    }

    fn deconstruct(self) -> (Proof, Self::Supplement) {
        (
            Proof {
                pubkey: self.pubkey,
                source: self.source,
            },
            self.tag,
        )
    }

    fn to_proof(&self) -> Proof {
        Proof {
            pubkey: self.pubkey.clone(),
            source: self.source.clone(),
        }
    }

    fn into_proof(self) -> Proof {
        Proof {
            pubkey: self.pubkey,
            source: self.source,
        }
    }
}

/// [`PubkeyScript`] containing LNPBP-2 commitment
#[derive(
    Wrapper,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    Debug,
    Display,
    From,
)]
#[display(inner)]
#[wrapper(LowerHex, UpperHex)]
pub struct SpkCommitment(PubkeyScript);

impl<MSG> EmbedCommitVerify<MSG> for SpkCommitment
where
    MSG: AsRef<[u8]>,
{
    type Container = SpkContainer;
    type Error = super::Error;

    fn embed_commit(
        container: &mut Self::Container,
        msg: &MSG,
    ) -> Result<Self, Self::Error> {
        use ScriptEncodeMethod::*;
        let script_pubkey =
            if let ScriptEncodeData::LockScript(ref lockscript) =
                container.source
            {
                let mut lockscript_container = LockscriptContainer {
                    script: lockscript.clone(),
                    pubkey: container.pubkey,
                    tag: container.tag,
                    tweaking_factor: None,
                };
                let lockscript = LockscriptCommitment::embed_commit(
                    &mut lockscript_container,
                    msg,
                )?
                .into_inner();
                container.tweaking_factor =
                    lockscript_container.tweaking_factor;
                match container.method {
                    Bare => {
                        lockscript.to_pubkey_script(descriptor::Category::Bare)
                    }
                    ScriptHash => lockscript
                        .to_pubkey_script(descriptor::Category::Hashed),
                    WScriptHash => lockscript
                        .to_pubkey_script(descriptor::Category::SegWit),
                    ShWScriptHash => lockscript
                        .to_pubkey_script(descriptor::Category::Nested),
                    _ => Err(Error::InvalidProofStructure)?,
                }
            } else if let ScriptEncodeData::Taproot(taproot_hash) =
                container.source
            {
                if container.method != Taproot {
                    Err(Error::InvalidProofStructure)?
                }
                let mut taproot_container = TaprootContainer {
                    script_root: taproot_hash,
                    intermediate_key: container.pubkey,
                    tag: container.tag,
                    tweaking_factor: None,
                };
                let _taproot = TaprootCommitment::embed_commit(
                    &mut taproot_container,
                    msg,
                )?;
                container.tweaking_factor = taproot_container.tweaking_factor;
                // TODO: Finalize taproot commitments once taproot will be
                //       finalized. We don't know yet how to form scripPubkey
                //       from Taproot data
                unimplemented!()
            } else {
                let mut pubkey_container = PubkeyContainer {
                    pubkey: container.pubkey,
                    tag: container.tag,
                    tweaking_factor: None,
                };
                let pubkey = *PubkeyCommitment::embed_commit(
                    &mut pubkey_container,
                    msg,
                )?;
                container.tweaking_factor = pubkey_container.tweaking_factor;
                match container.method {
                    PublicKey => {
                        pubkey.to_pubkey_script(descriptor::Category::Bare)
                    }
                    PubkeyHash => {
                        pubkey.to_pubkey_script(descriptor::Category::Hashed)
                    }
                    WPubkeyHash => {
                        pubkey.to_pubkey_script(descriptor::Category::SegWit)
                    }
                    ShWScriptHash => {
                        pubkey.to_pubkey_script(descriptor::Category::Nested)
                    }
                    OpReturn => {
                        let ser = pubkey.serialize();
                        if ser[0] != 0x02 {
                            Err(Error::InvalidOpReturnKey)?
                        }
                        Script::new_op_return(&ser).into()
                    }
                    _ => Err(Error::InvalidProofStructure)?,
                }
            };
        Ok(SpkCommitment::from_inner(script_pubkey))
    }
}

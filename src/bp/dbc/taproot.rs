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

use bitcoin::hashes::sha256;
use bitcoin::secp256k1;

use super::{Container, Error, LNPBP1Commitment, Proof, ScriptInfo};
use crate::bp::dbc::LNPBP1Container;
use crate::commit_verify::EmbedCommitVerify;

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
#[display_from(Debug)]
pub struct TaprootContainer {
    pub script_root: sha256::Hash,
    pub intermediate_key: secp256k1::PublicKey,
    /// Single SHA256 hash of the protocol-specific tag
    pub tag: sha256::Hash,
}

impl Container for TaprootContainer {
    /// Out supplement is a protocol-specific tag in its hashed form
    type Supplement = sha256::Hash;
    /// Our proof contains the host, so we don't need host here
    type Host = Option<()>;

    fn reconstruct(
        proof: &Proof,
        supplement: &Self::Supplement,
        _: &Self::Host,
    ) -> Result<Self, Error> {
        if let ScriptInfo::Taproot(ref tapscript_root) = proof.script_info {
            Ok(Self {
                script_root: tapscript_root.clone(),
                intermediate_key: proof.pubkey,
                tag: supplement.clone(),
            })
        } else {
            Err(Error::InvalidProofStructure)
        }
    }

    fn deconstruct(self) -> (Proof, Self::Supplement) {
        (
            Proof {
                pubkey: self.intermediate_key,
                script_info: ScriptInfo::Taproot(self.script_root),
            },
            self.tag,
        )
    }

    fn to_proof(&self) -> Proof {
        Proof {
            pubkey: self.intermediate_key.clone(),
            script_info: ScriptInfo::Taproot(self.script_root.clone()),
        }
    }

    fn into_proof(self) -> Proof {
        Proof {
            pubkey: self.intermediate_key,
            script_info: ScriptInfo::Taproot(self.script_root),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
#[display_from(Debug)]
pub struct TaprootCommitment {
    pub script_root: sha256::Hash,
    pub intermediate_key_commitment: LNPBP1Commitment,
}

impl<MSG> EmbedCommitVerify<MSG> for TaprootCommitment
where
    MSG: AsRef<[u8]>,
{
    type Container = TaprootContainer;
    type Error = Error;

    fn embed_commit(container: &Self::Container, msg: &MSG) -> Result<Self, Self::Error> {
        let cmt = LNPBP1Commitment::embed_commit(
            &LNPBP1Container {
                pubkey: container.intermediate_key.clone(),
                tag: container.tag.clone(),
            },
            msg,
        )?;
        Ok(Self {
            script_root: container.script_root,
            intermediate_key_commitment: cmt,
        })
    }
}

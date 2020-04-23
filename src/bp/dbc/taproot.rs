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
use bitcoin::secp256k1::PublicKey;

use super::{Error, PubkeyCommitment};
use crate::primitives::commit_verify::CommitEmbedVerify;

#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[display_from(Debug)]
pub struct TaprootContainer {
    pub script_root: sha256::Hash,
    pub intermediate_key: PublicKey,
}

#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[display_from(Debug)]
pub struct TaprootCommitment {
    pub script_root: sha256::Hash,
    pub pubkey_commitment: PubkeyCommitment,
}

impl<MSG> CommitEmbedVerify<MSG> for TaprootCommitment
where
    MSG: AsRef<[u8]>,
{
    type Container = TaprootContainer;
    type Error = Error;

    #[inline]
    fn container(&self) -> Self::Container {
        TaprootContainer {
            script_root: self.script_root,
            intermediate_key: self.pubkey_commitment.original,
        }
    }

    fn commit_embed(container: Self::Container, msg: &MSG) -> Result<Self, Self::Error> {
        let cmt = PubkeyCommitment::commit_embed(container.intermediate_key, msg)?;
        Ok(Self {
            script_root: container.script_root,
            pubkey_commitment: cmt,
        })
    }
}

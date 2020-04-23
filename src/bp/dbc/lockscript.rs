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

use bitcoin::secp256k1::PublicKey;

use super::pubkey::PubkeyCommitment;
use crate::bp::scripts::{LockScript, LockScriptParseError};
use crate::primitives::commit_verify::CommitEmbedVerify;

#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[display_from(Debug)]
pub struct LockscriptCommitment {
    pub tweaked: LockScript,
    pub original: LockScript,
}

impl<MSG> CommitEmbedVerify<MSG> for LockscriptCommitment
where
    MSG: AsRef<[u8]>,
{
    type Container = LockScript;
    type Error = LockScriptParseError<bitcoin::PublicKey>;

    #[inline]
    fn container(&self) -> Self::Container {
        self.original.clone()
    }

    fn commit_embed(container: Self::Container, msg: &MSG) -> Result<Self, Self::Error> {
        let tweaked = container.clone().replace_pubkeys(|pubkey: PublicKey| {
            PubkeyCommitment::commit_embed(pubkey, msg)
                .ok()
                .map(|c| c.tweaked)
        })?;
        Ok(Self {
            original: container,
            tweaked,
        })
    }
}

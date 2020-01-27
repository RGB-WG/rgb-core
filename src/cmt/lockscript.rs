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

use crate::{
    common::*,
    bp::scripts::*
};
use super::committable::*;
use super::pubkey::*;


#[derive(Clone, Eq, PartialEq)]
pub struct LockscriptCommitment {
    pub tweaked: LockScript,
    pub original: LockScript,
}

impl<MSG> CommitmentVerify<MSG> for LockscriptCommitment where
    MSG: EmbedCommittable<Self> + AsSlice
{

    #[inline]
    fn reveal_verify(&self, msg: &MSG) -> bool {
        <Self as EmbeddedCommitment<MSG>>::reveal_verify(&self, &msg)
    }
}

impl<MSG> EmbeddedCommitment<MSG> for LockscriptCommitment where
    MSG: EmbedCommittable<Self> + AsSlice
{
    type Container = LockScript;
    type Error = LockScriptParseError<bitcoin::PublicKey>;

    #[inline]
    fn get_original_container(&self) -> Self::Container {
        self.original.clone()
    }

    fn commit_to(container: Self::Container, msg: &MSG) -> Result<Self, Self::Error> {
        let tweaked = container.clone().replace_pubkeys(|pubkey: PublicKey| {
            PubkeyCommitment::commit_to(pubkey, msg).ok().map(|c| c.tweaked)
        })?;
        Ok(Self {
            original: container,
            tweaked
        })
    }
}

impl<T> Verifiable<LockscriptCommitment> for T where T: AsSlice { }

impl<T> EmbedCommittable<LockscriptCommitment> for T where T: AsSlice { }

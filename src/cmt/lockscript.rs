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

use bitcoin::{Script, PublicKey, hashes::sha256};

use crate::common::*;
use super::committable::*;


#[derive(Clone, Eq, PartialEq)]
pub struct LockscriptCommitment {
    pub tweaked: LockScript,
    pub original: LockScript,
}

impl<MSG> CommitmentVerify<MSG> for LockscriptCommitment where
    MSG: EmbedCommittable<LockScript, Self> + AsSlice
{

    #[inline]
    fn reveal_verify(&self, msg: &MSG) -> bool {
        <Self as EmbeddedCommitment<LockScript, MSG>>::reveal_verify(&self, msg)
    }
}

impl<MSG> EmbeddedCommitment<LockScript, MSG> for LockscriptCommitment where
    MSG: EmbedCommittable<LockScript, Self> + AsSlice,
{
    type Error = ();

    #[inline]
    fn get_original_container(&self) -> &LockScript {
        &self.original
    }

    fn from(container: &LockScript, msg: &MSG) -> Result<Self, Self::Error> {
        let tweaked: LockScript;
        // Parse script
        // Find all required patterns
        // Extract public keys
        // Tweak each of them
        // Pack back into the script
        Ok(Self {
            original: container.clone(), tweaked
        })
    }
}

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

use bitcoin::{TxOut, Script, PublicKey, hashes::sha256};

use crate::common::*;
use super::{committable::*, LockscriptCommitment, TaprootCommitment, TaprootContainer};


#[derive(Clone, Eq, PartialEq)]
pub enum TxoutContainer {
    LockScript(LockScript),
    TapRoot(TaprootContainer),
}


#[derive(Clone, Eq, PartialEq)]
pub enum TxoutCommitment {
    LockScript(LockscriptCommitment),
    TapRoot(TaprootCommitment),
}


impl<MSG> CommitmentVerify<MSG> for TxoutCommitment where
    MSG: EmbedCommittable<TxoutContainer, Self> + AsSlice
{

    #[inline]
    fn reveal_verify(&self, msg: &MSG) -> bool {
        <Self as EmbeddedCommitment<TxoutContainer, MSG>>::reveal_verify(&self, msg)
    }
}

impl<MSG> EmbeddedCommitment<TxoutContainer, MSG> for TxoutCommitment where
    MSG: EmbedCommittable<TxoutContainer, Self> + AsSlice,
{
    type Error = ();

    #[inline]
    fn get_original_container(&self) -> &TxoutContainer {
        &match self {
            Self::LockScript(cmt) => {
                let container: &LockScript = EmbeddedCommitment::<PublicKey, MSG>::get_original_container(&cmt);
                TxoutContainer::LockScript(*container)
            },
            Self::TapRoot(cmt) => {
                TxoutContainer::TapRoot(*cmt.get_original_container())
            },
        }
    }

    fn from(container: &TxoutContainer, msg: &MSG) -> Result<Self, Self::Error> {
        Ok(match container {
            TxoutContainer::LockScript(script)
                => Self::LockScript(LockscriptCommitment::from(&script)),
            TxoutContainer::TapRoot(container)
                => Self::TapRoot(TaprootCommitment::from(&container)),
        })
    }
}

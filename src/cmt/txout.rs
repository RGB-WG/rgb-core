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
use super::{committable::*, LockscriptCommitment, TaprootCommitment, TaprootContainer, pubkey::Error};


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
    MSG: EmbedCommittable<Self> + EmbedCommittable<LockscriptCommitment> + AsSlice
{

    #[inline]
    fn reveal_verify(&self, msg: &MSG) -> bool {
        <Self as EmbeddedCommitment<MSG>>::reveal_verify(&self, msg)
    }
}

impl<MSG> EmbeddedCommitment<MSG> for TxoutCommitment where
    MSG: EmbedCommittable<Self> + EmbedCommittable<LockscriptCommitment> + AsSlice
{
    type Container = TxoutContainer;
    type Error = Error;

    #[inline]
    fn get_original_container(&self) -> Self::Container {
        match self {
            Self::LockScript(cmt) => {
                let container: LockScript = EmbeddedCommitment::<MSG>::get_original_container(cmt);
                TxoutContainer::LockScript(container)
            },
            Self::TapRoot(cmt) => {
                let container: TaprootContainer = EmbeddedCommitment::<MSG>::get_original_container(cmt);
                TxoutContainer::TapRoot(container)
            },
        }
    }

    fn from(container: &Self::Container, msg: &MSG) -> Result<Self, Self::Error> {
        Ok(match container {
            TxoutContainer::LockScript(script) => {
                let cmt: LockscriptCommitment = EmbeddedCommitment::<MSG>::from(script, msg)?;
                Self::LockScript(cmt)
            },
            TxoutContainer::TapRoot(container) => {
                let cmt: TaprootCommitment = EmbeddedCommitment::<MSG>::from(container, msg)?;
                Self::TapRoot(cmt)
            },
        })
    }
}

impl<T> Verifiable<TxoutCommitment> for T where T: AsSlice { }

impl<T> EmbedCommittable<TxoutCommitment> for T where T: AsSlice { }

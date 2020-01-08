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

use bitcoin::Script;
use bitcoin::secp256k1::PublicKey;

use crate::common::*;
use super::{committable::*, PubkeyCommitment, LockscriptCommitment,
            TaprootCommitment, TaprootContainer, pubkey::Error};


#[derive(Clone, Eq, PartialEq)]
pub enum TxoutContainer {
    PublicKey,
    PubkeyHash(PublicKey),
    ScriptHash(LockScript),
    TapRoot(TaprootContainer),
    OpReturn(PublicKey),
    OtherScript,
}


#[derive(Clone, Eq, PartialEq)]
pub enum TxoutCommitment {
    PublicKey(PubkeyCommitment),
    LockScript(LockscriptCommitment),
    TapRoot(TaprootCommitment),
}


impl<MSG> CommitmentVerify<MSG> for TxoutCommitment where
    MSG: EmbedCommittable<Self> + EmbedCommittable<LockscriptCommitment> + AsSlice
{

    #[inline]
    fn reveal_verify(&self, msg: MSG) -> bool {
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
            // TODO: Re-implement by analyzing scriptPubkey content
            Self::PublicKey(cmt) => {
                let container: PublicKey = EmbeddedCommitment::<MSG>::get_original_container(cmt);
                TxoutContainer::PubkeyHash(container)
            },
            Self::LockScript(cmt) => {
                let container: LockScript = EmbeddedCommitment::<MSG>::get_original_container(cmt);
                TxoutContainer::ScriptHash(container)
            },
            Self::TapRoot(cmt) => {
                let container: TaprootContainer = EmbeddedCommitment::<MSG>::get_original_container(cmt);
                TxoutContainer::TapRoot(container)
            },
        }
    }

    fn commit_to(container: Self::Container, msg: MSG) -> Result<Self, Self::Error> {
        Ok(match container {
            TxoutContainer::PublicKey => {
                // FIXME: Extract it from the script using LockScript
                let pubkey: PublicKey = PublicKey::from_slice(&[0])?;
                let cmt: PubkeyCommitment = EmbeddedCommitment::<MSG>::commit_to(pubkey, msg)?;
                Self::PublicKey(cmt)
            },
            TxoutContainer::PubkeyHash(pubkey) => {
                let cmt: PubkeyCommitment = EmbeddedCommitment::<MSG>::commit_to(pubkey, msg)?;
                Self::PublicKey(cmt)
            },
            TxoutContainer::ScriptHash(script) => {
                let cmt: LockscriptCommitment = EmbeddedCommitment::<MSG>::commit_to(script, msg)?;
                Self::LockScript(cmt)
            },
            TxoutContainer::TapRoot(container) => {
                let cmt: TaprootCommitment = EmbeddedCommitment::<MSG>::commit_to(container, msg)?;
                Self::TapRoot(cmt)
            },
            TxoutContainer::OpReturn(pubkey) => {
                let cmt: PubkeyCommitment = EmbeddedCommitment::<MSG>::commit_to(pubkey, msg)?;
                Self::PublicKey(cmt)
            }
            TxoutContainer::OtherScript => {
                // FIXME: Extract if from the txout
                let script = LockScript::from(Script::new());
                let cmt: LockscriptCommitment = EmbeddedCommitment::<MSG>::commit_to(script, msg)?;
                Self::LockScript(cmt)
            },
        })
    }
}

impl<T> Verifiable<TxoutCommitment> for T where T: AsSlice { }

impl<T> EmbedCommittable<TxoutCommitment> for T where T: AsSlice { }

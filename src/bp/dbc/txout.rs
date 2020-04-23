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


use crate::common::AsSlice;
use crate::primitives::commit_verify::{
    CommitmentVerify, Verifiable, EmbedCommittable, EmbeddedCommitment
};
use super::scriptpubkey::{Error, ScriptPubkeyContainer, ScriptPubkeyCommitment};


#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[display_from(Debug)]
pub struct TxoutContainer {
    pub value: u64,
    pub script_container: ScriptPubkeyContainer,
}

#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[display_from(Debug)]
pub struct TxoutCommitment {
    pub value: u64,
    pub script_commitment: ScriptPubkeyCommitment,
}


impl<MSG> CommitmentVerify<MSG> for TxoutCommitment where
    MSG: EmbedCommittable<Self> + EmbedCommittable<ScriptPubkeyCommitment> + AsSlice
{

    #[inline]
    fn reveal_verify(&self, msg: &MSG) -> bool {
        <Self as EmbeddedCommitment<MSG>>::reveal_verify(&self, msg)
    }
}

impl<MSG> EmbeddedCommitment<MSG> for TxoutCommitment where
    MSG: EmbedCommittable<Self> + EmbedCommittable<ScriptPubkeyCommitment> + AsSlice
{
    type Container = TxoutContainer;
    type Error = Error;

    #[inline]
    fn get_original_container(&self) -> Self::Container {
        TxoutContainer {
            value: self.value,
            script_container: EmbeddedCommitment::<MSG>::get_original_container(&self.script_commitment)
        }
    }

    fn commit_to(container: Self::Container, msg: &MSG) -> Result<Self, Self::Error> {
        Ok(Self {
            value: container.value,
            script_commitment: ScriptPubkeyCommitment::commit_to(container.script_container, msg)?
        })
    }
}

impl<T> Verifiable<TxoutCommitment> for T where T: AsSlice { }

impl<T> EmbedCommittable<TxoutCommitment> for T where T: AsSlice { }

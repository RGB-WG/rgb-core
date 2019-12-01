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

use bitcoin::{Script, hashes::sha256};

use crate::common::*;
use super::{committable::*, PubkeyCommitment, pubkey::Error};
use secp256k1::PublicKey;


#[derive(Clone, Eq, PartialEq)]
pub struct TaprootContainer {
    pub script_root: sha256::Hash,
    pub intermediate_key: PublicKey,
}

#[derive(Clone, Eq, PartialEq)]
pub struct TaprootCommitment {
    pub script_root: sha256::Hash,
    pub pubkey_commitment: PubkeyCommitment,
}

impl<MSG> CommitmentVerify<MSG> for TaprootCommitment where
    MSG: EmbedCommittable<Self> + EmbedCommittable<PubkeyCommitment> + AsSlice
{

    #[inline]
    fn reveal_verify(&self, msg: &MSG) -> bool {
        <Self as EmbeddedCommitment<MSG>>::reveal_verify(&self, msg)
    }
}

impl<MSG> EmbeddedCommitment<MSG> for TaprootCommitment where
    MSG: EmbedCommittable<Self> + EmbedCommittable<PubkeyCommitment> + AsSlice
{
    type Container = TaprootContainer;
    type Error = Error;

    #[inline]
    fn get_original_container(&self) -> Self::Container {
        TaprootContainer {
            script_root: self.script_root,
            intermediate_key: self.pubkey_commitment.original
        }
    }

    fn from(container: &Self::Container, msg: &MSG) -> Result<Self, Self::Error> {
        let cmt = EmbeddedCommitment::from(&container.intermediate_key, msg)?;
        Ok(Self {
            script_root: container.script_root,
            pubkey_commitment: cmt
        })
    }
}

impl<T> Verifiable<TaprootCommitment> for T where T: AsSlice { }

impl<T> EmbedCommittable<TaprootCommitment> for T where T: AsSlice { }

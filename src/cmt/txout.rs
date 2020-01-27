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

use bitcoin::{
    secp256k1,
    secp256k1::PublicKey,
    blockdata::script::Builder
};

use crate::{
    common::*,
    bp::scripts::*,
};
use super::{
    committable::*,
    pubkey,
    PubkeyCommitment, LockscriptCommitment, TaprootCommitment, TaprootContainer
};


#[derive(Clone, Eq, PartialEq)]
pub enum TxoutContainer {
    PublicKey(PublicKey),
    PubkeyHash(PublicKey),
    ScriptHash(LockScript),
    TapRoot(TaprootContainer),
    OpReturn(PublicKey),
    OtherScript(PubkeyScript),
}


#[derive(Clone, Eq, PartialEq)]
pub enum TxoutCommitment {
    PublicKey(PubkeyCommitment),
    LockScript(LockscriptCommitment),
    TapRoot(TaprootCommitment),
}


#[derive(Debug)]
pub enum Error {
    Pubkey(pubkey::Error),
    Secp256k1(secp256k1::Error),
    LockScript(LockScriptParseError<bitcoin::PublicKey>),
}

impl From<pubkey::Error> for Error {
    fn from(err: pubkey::Error) -> Self {
        Self::Pubkey(err)
    }
}

impl From<secp256k1::Error> for Error {
    fn from(err: secp256k1::Error) -> Self {
        Self::Secp256k1(err)
    }
}

impl From<LockScriptParseError<bitcoin::PublicKey>> for Error {
    fn from(err: LockScriptParseError<bitcoin::PublicKey>) -> Self {
        Self::LockScript(err)
    }
}


impl From<TxoutContainer> for PubkeyScript {
    fn from(container: TxoutContainer) -> Self {
        let script = match container {
            TxoutContainer::OtherScript(script) =>
                script.into_inner(),
            TxoutContainer::PublicKey(pubkey) =>
                Builder::gen_p2pk(&bitcoin::PublicKey { compressed: false, key: pubkey }).into_script(),
            TxoutContainer::PubkeyHash(pubkey) => {
                let keyhash = bitcoin::PublicKey { compressed: false, key: pubkey }.wpubkey_hash();
                Builder::gen_v0_p2wpkh(&keyhash).into_script()
            },
            TxoutContainer::ScriptHash(script) =>
                Builder::gen_v0_p2wsh(&script.into_inner().wscript_hash()).into_script(),
            TxoutContainer::OpReturn(data) => {
                let keyhash = bitcoin::PublicKey { compressed: false, key: data }.wpubkey_hash();
                Builder::gen_op_return(&keyhash.to_vec()).into_script()
            },
            TxoutContainer::TapRoot(taproot_container) => unimplemented!(),
        };
        script.into()
    }
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

    fn commit_to(container: Self::Container, msg: &MSG) -> Result<Self, Self::Error> {
        Ok(match container {
            TxoutContainer::PublicKey(pubkey) => {
                let cmt = PubkeyCommitment::commit_to(pubkey, msg)?;
                Self::PublicKey(cmt)
            },
            TxoutContainer::PubkeyHash(pubkey) => {
                let cmt = PubkeyCommitment::commit_to(pubkey, msg)?;
                Self::PublicKey(cmt)
            },
            TxoutContainer::ScriptHash(script) => {
                let cmt = LockscriptCommitment::commit_to(script, msg)?;
                Self::LockScript(cmt)
            },
            TxoutContainer::TapRoot(container) => {
                let cmt = TaprootCommitment::commit_to(container, msg)?;
                Self::TapRoot(cmt)
            },
            TxoutContainer::OpReturn(pubkey) => {
                let cmt = PubkeyCommitment::commit_to(pubkey, msg)?;
                Self::PublicKey(cmt)
            }
            TxoutContainer::OtherScript(script) => {
                // FIXME: Extract it from the txout
                let script = LockScript::from_inner(script.into_inner());
                let cmt = LockscriptCommitment::commit_to(script, msg)?;
                Self::LockScript(cmt)
            },
        })
    }
}

impl<T> Verifiable<TxoutCommitment> for T where T: AsSlice { }

impl<T> EmbedCommittable<TxoutCommitment> for T where T: AsSlice { }

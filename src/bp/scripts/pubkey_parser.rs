// LNP/BP Core Library implementing LNPBP specifications & standards
// Written in 2020 by
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

use super::LockScript;
use bitcoin::{secp256k1, PubkeyHash};
use miniscript::miniscript::iter::PubkeyOrHash;
use miniscript::{Miniscript, MiniscriptKey};
use std::collections::HashSet;
use std::iter::FromIterator;

#[derive(Debug, Display, Error)]
#[display_from(Debug)]
pub enum PubkeyParseError {
    PubkeyHash(<bitcoin::PublicKey as MiniscriptKey>::Hash),
    Miniscript(miniscript::Error),
}

impl From<miniscript::Error> for PubkeyParseError {
    fn from(miniscript_error: miniscript::Error) -> Self {
        Self::Miniscript(miniscript_error)
    }
}

impl LockScript {
    pub fn extract_pubkeyset(&self) -> Result<HashSet<secp256k1::PublicKey>, PubkeyParseError> {
        Ok(HashSet::from_iter(self.extract_pubkeys()?))
    }

    pub fn extract_pubkeys(&self) -> Result<Vec<secp256k1::PublicKey>, PubkeyParseError> {
        Miniscript::parse(&*self.clone())?
            .iter_pubkeys_and_hashes()
            .try_fold(
                Vec::<secp256k1::PublicKey>::new(),
                |mut keys, item| match item {
                    PubkeyOrHash::HashedPubkey(hash) => Err(PubkeyParseError::PubkeyHash(hash)),
                    PubkeyOrHash::PlainPubkey(key) => {
                        keys.push(key.key);
                        Ok(keys)
                    }
                },
            )
    }

    pub fn replace_pubkeys(
        &self,
        processor: impl Fn(secp256k1::PublicKey) -> Option<secp256k1::PublicKey>,
    ) -> Result<Self, PubkeyParseError> {
        let result = Miniscript::parse(&*self.clone())?.replace_pubkeys_and_hashes(
            &|item: PubkeyOrHash<bitcoin::PublicKey>| match item {
                PubkeyOrHash::PlainPubkey(pubkey) => processor(pubkey.key).map(|key| {
                    PubkeyOrHash::PlainPubkey(bitcoin::PublicKey {
                        compressed: true,
                        key,
                    })
                }),
                PubkeyOrHash::HashedPubkey(_) => None,
            },
        )?;
        Ok(LockScript::from(result.encode()))
    }

    pub fn replace_pubkeys_and_hashes(
        &self,
        key_processor: impl Fn(secp256k1::PublicKey) -> Option<secp256k1::PublicKey>,
        hash_processor: impl Fn(PubkeyHash) -> Option<PubkeyHash>,
    ) -> Result<Self, PubkeyParseError> {
        let result = Miniscript::parse(&*self.clone())?.replace_pubkeys_and_hashes(
            &|item: PubkeyOrHash<bitcoin::PublicKey>| match item {
                PubkeyOrHash::PlainPubkey(pubkey) => key_processor(pubkey.key).map(|key| {
                    PubkeyOrHash::PlainPubkey(bitcoin::PublicKey {
                        compressed: true,
                        key,
                    })
                }),
                PubkeyOrHash::HashedPubkey(hash) => {
                    hash_processor(hash.into()).map(|hash| PubkeyOrHash::HashedPubkey(hash.into()))
                }
            },
        )?;
        Ok(LockScript::from(result.encode()))
    }
}

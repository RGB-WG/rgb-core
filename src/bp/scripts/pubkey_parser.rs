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

/// Errors that may happen during LockScript parsing process
#[derive(Debug, Display, Error)]
#[display_from(Debug)]
pub enum PubkeyParseError {
    /// Unexpected pubkey hash when enumerating in "keys only" mode
    PubkeyHash(<bitcoin::PublicKey as MiniscriptKey>::Hash),

    /// Miniscript-level error
    Miniscript(miniscript::Error),
}

impl From<miniscript::Error> for PubkeyParseError {
    fn from(miniscript_error: miniscript::Error) -> Self {
        Self::Miniscript(miniscript_error)
    }
}

impl LockScript {
    /// Returns set of unique public keys from the script; fails on public key
    /// hash
    pub fn extract_pubkeyset(&self) -> Result<HashSet<secp256k1::PublicKey>, PubkeyParseError> {
        Ok(HashSet::from_iter(self.extract_pubkeys()?))
    }

    /// Returns tuple of two sets: one for unique public keys and one for
    /// unique hash values, extracted from the script
    pub fn extract_pubkey_hash_set(
        &self,
    ) -> Result<(HashSet<secp256k1::PublicKey>, HashSet<PubkeyHash>), PubkeyParseError> {
        let (keys, hashes) = self.extract_pubkeys_and_hashes()?;
        Ok((HashSet::from_iter(keys), HashSet::from_iter(hashes)))
    }

    /// Returns tuple with two vectors: one for public keys and one for public
    /// key hashes present in the script; if any of the keys or hashes has more
    /// than a single occurrence it returns all occurrences for each of them
    pub fn extract_pubkeys_and_hashes(
        &self,
    ) -> Result<(Vec<secp256k1::PublicKey>, Vec<PubkeyHash>), PubkeyParseError> {
        Miniscript::parse(&*self.clone())?
            .iter_pubkeys_and_hashes()
            .try_fold(
                (Vec::<secp256k1::PublicKey>::new(), Vec::<PubkeyHash>::new()),
                |(mut keys, mut hashes), item| {
                    match item {
                        PubkeyOrHash::HashedPubkey(hash) => hashes.push(hash.into()),
                        PubkeyOrHash::PlainPubkey(key) => keys.push(key.key),
                    }
                    Ok((keys, hashes))
                },
            )
    }

    /// Returns all public keys found in the script; fails on public key hash.
    /// If the key present multiple times in the script it returns all
    /// occurrences.
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

    /// Replaces pubkeys using provided matching function; does not fail on
    /// public key hashes.
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

    /// Replaces public kes and public key hashes using provided matching
    /// functions.
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

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::bp::test::*;
    use bitcoin::hashes::{hash160, sha256, Hash};
    use bitcoin::{PubkeyHash, PublicKey};
    use std::collections::HashSet;
    use std::iter::FromIterator;
    use std::str::FromStr;

    macro_rules! ms_str {
        ($($arg:tt)*) => (LockScript::from(Miniscript::<bitcoin::PublicKey>::from_str(&format!($($arg)*)).unwrap().encode()))
    }

    macro_rules! policy_str {
        ($($arg:tt)*) => (LockScript::from(miniscript::policy::Concrete::<bitcoin::PublicKey>::from_str(&format!($($arg)*)).unwrap().compile().unwrap().encode()))
    }

    pub(crate) fn gen_pubkeys_and_hashes(n: usize) -> (Vec<PublicKey>, Vec<PubkeyHash>) {
        let pks = gen_bitcoin_pubkeys(n, true);
        let pkhs = pks.iter().map(PublicKey::pubkey_hash).collect();
        (pks, pkhs)
    }

    pub(crate) fn no_keys_or_hashes_suite(proc: fn(LockScript) -> ()) {
        let sha_hash = sha256::Hash::hash(&"(nearly)random string".as_bytes());
        let dummy_hashes: Vec<hash160::Hash> = (1..13)
            .map(|i| hash160::Hash::from_inner([i; 20]))
            .collect();

        proc(ms_str!("older(921)"));
        proc(ms_str!("sha256({})", sha_hash));
        proc(ms_str!("hash256({})", sha_hash));
        proc(ms_str!("hash160({})", dummy_hashes[0]));
        proc(ms_str!("ripemd160({})", dummy_hashes[1]));
        proc(ms_str!("hash160({})", dummy_hashes[2]));
    }

    pub(crate) fn single_key_suite(proc: fn(LockScript, secp256k1::PublicKey) -> ()) {
        let (keys, _) = gen_pubkeys_and_hashes(6);
        proc(ms_str!("c:pk_k({})", keys[1]), keys[1].key);
        proc(ms_str!("c:pk_k({})", keys[2]), keys[2].key);
        proc(ms_str!("c:pk_k({})", keys[3]), keys[3].key);
        proc(ms_str!("c:pk_k({})", keys[0]), keys[0].key);
    }

    pub(crate) fn single_unmatched_key_suite(proc: fn(LockScript, secp256k1::PublicKey) -> ()) {
        let (keys, _) = gen_pubkeys_and_hashes(6);
        proc(ms_str!("c:pk_k({})", keys[1]), keys[0].key);
        proc(ms_str!("c:pk_k({})", keys[2]), keys[3].key);
        proc(ms_str!("c:pk_k({})", keys[3]), keys[4].key);
        proc(ms_str!("c:pk_k({})", keys[4]), keys[1].key);
    }

    pub(crate) fn single_keyhash_suite(proc: fn(LockScript, PubkeyHash) -> ()) {
        let (_, hashes) = gen_pubkeys_and_hashes(6);
        proc(ms_str!("c:pk_h({})", hashes[1]), hashes[1]);
        proc(ms_str!("c:pk_h({})", hashes[2]), hashes[2]);
        proc(ms_str!("c:pk_h({})", hashes[3]), hashes[3]);
        proc(ms_str!("c:pk_h({})", hashes[0]), hashes[0]);
    }

    pub(crate) fn single_unmatched_keyhash_suite(proc: fn(LockScript, PubkeyHash) -> ()) {
        let (_, hashes) = gen_pubkeys_and_hashes(6);
        proc(ms_str!("c:pk_h({})", hashes[1]), hashes[0]);
        proc(ms_str!("c:pk_h({})", hashes[2]), hashes[3]);
        proc(ms_str!("c:pk_h({})", hashes[3]), hashes[4]);
        proc(ms_str!("c:pk_h({})", hashes[4]), hashes[1]);
    }

    pub(crate) fn complex_keys_suite(proc: fn(LockScript, Vec<secp256k1::PublicKey>) -> ()) {
        let (keys, _) = gen_pubkeys_and_hashes(6);
        proc(
            policy_str!("thresh(2,pk({}),pk({}))", keys[0], keys[1]),
            keys[..2].iter().map(|pk| pk.key).collect(),
        );
        proc(
            policy_str!(
                "thresh(3,pk({}),pk({}),pk({}),pk({}),pk({}))",
                keys[0],
                keys[1],
                keys[2],
                keys[3],
                keys[4]
            ),
            keys[..5].iter().map(|pk| pk.key).collect(),
        );
    }

    pub(crate) fn complex_unmatched_keys_suite(
        proc: fn(LockScript, Vec<secp256k1::PublicKey>) -> (),
    ) {
        let (keys, _) = gen_pubkeys_and_hashes(10);
        proc(
            policy_str!("thresh(2,pk({}),pk({}))", keys[0], keys[1]),
            keys[2..].iter().map(|pk| pk.key).collect(),
        );
        proc(
            policy_str!(
                "thresh(3,pk({}),pk({}),pk({}),pk({}),pk({}))",
                keys[0],
                keys[1],
                keys[2],
                keys[3],
                keys[4]
            ),
            keys[2..7].iter().map(|pk| pk.key).collect(),
        );
    }

    pub(crate) fn complex_suite(proc: fn(LockScript, Vec<secp256k1::PublicKey>) -> ()) {
        let (keys, _) = gen_pubkeys_and_hashes(10);
        proc(
            policy_str!(
                "or(thresh(3,pk({}),pk({}),pk({})),and(thresh(2,pk({}),pk({})),older(10000)))",
                keys[0],
                keys[1],
                keys[2],
                keys[3],
                keys[4]
            ),
            vec![keys[3], keys[4], keys[0], keys[1], keys[2]]
                .iter()
                .map(|pk| pk.key)
                .collect(),
        );
        proc(
            policy_str!(
                "or(thresh(3,pk({}),pk({}),pk({})),and(thresh(2,pk({}),pk({})),older(10000)))",
                keys[0],
                keys[1],
                keys[3],
                keys[3],
                keys[4]
            ),
            vec![keys[3], keys[4], keys[0], keys[1], keys[3]]
                .iter()
                .map(|pk| pk.key)
                .collect(),
        );
    }

    #[test]
    fn test_script_parse_no_key() {
        no_keys_or_hashes_suite(|lockscript| {
            assert_eq!(lockscript.extract_pubkeys().unwrap(), vec![]);
            assert_eq!(
                lockscript.extract_pubkey_hash_set().unwrap(),
                (HashSet::new(), HashSet::new())
            );
        })
    }

    #[test]
    fn test_script_parse_single_key() {
        single_key_suite(|lockscript, pubkey| {
            let extract = lockscript.extract_pubkeys().unwrap();
            assert_eq!(extract[0], pubkey);
            assert_eq!(
                lockscript.extract_pubkey_hash_set().unwrap(),
                (HashSet::from_iter(vec![pubkey]), HashSet::new())
            );
        });

        single_unmatched_key_suite(|lockscript, pubkey| {
            assert_ne!(lockscript.extract_pubkeys().unwrap(), vec![pubkey]);
        });
    }

    #[test]
    fn test_script_parse_singlehash() {
        single_keyhash_suite(|lockscript, hash| {
            if let Err(PubkeyParseError::PubkeyHash(found_hash)) = lockscript.extract_pubkeyset() {
                assert_eq!(hash, found_hash.into())
            } else {
                panic!("extract_pubkeyset must return error")
            }
            assert_eq!(
                lockscript.extract_pubkey_hash_set().unwrap(),
                (HashSet::new(), HashSet::from_iter(vec![hash]))
            );
        });

        single_unmatched_keyhash_suite(|lockscript, hash| {
            let (_, hashset) = lockscript.extract_pubkey_hash_set().unwrap();
            assert_ne!(hashset, HashSet::from_iter(vec![hash]));
        });
    }

    #[test]
    fn test_script_parse_complex_keys() {
        complex_keys_suite(|lockscript, keys| {
            assert_eq!(lockscript.extract_pubkeys().unwrap(), keys.clone());
            assert_eq!(
                lockscript.extract_pubkey_hash_set().unwrap(),
                (HashSet::from_iter(keys), HashSet::new())
            );
        });
    }

    #[test]
    fn test_script_parse_complex_unmatched_keys() {
        complex_unmatched_keys_suite(|lockscript, keys| {
            let extract = lockscript.extract_pubkeys().unwrap();
            assert_ne!(extract.len(), 0);
            assert_ne!(extract, keys);
        });
    }

    #[test]
    fn test_script_parse_complex_script() {
        complex_suite(|lockscript, keys| {
            assert_eq!(lockscript.extract_pubkeys().unwrap(), keys.clone());
            assert_eq!(
                lockscript.extract_pubkeyset().unwrap(),
                HashSet::from_iter(keys)
            );
        });
    }
}

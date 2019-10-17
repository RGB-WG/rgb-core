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

//! Library for Secp256k1 elliptic curve based collision-resistant commitments, implementing
//! [LNPBPS-0001](https://github.com/LNP-BP/lnpbps/blob/master/lnpbps-0001.md)
//!
//! In order to use, first implement `TweakSource` traid for your source data type, which you
//! would like to commit to. `from` function must transform your custom data structure into
//! byte array (`message`) and also provide a name for the commitment protocol you are using.
//! The sample below show how this can be done for a string type:
//!
//! ```rust
//!     impl<'a> From<&'a str> for TweakSource<'a> {
//!       fn from(msg: &'a str) -> Self {
//!           TweakSource {
//!               protocol: "str",
//!               message: msg.as_bytes()
//!           }
//!       }
//!   }
//! ```
//!
//! After this, define an original public key you would like to use for a commitment and create
//! and instance of `TweakingEngine` using this key. Method `engine.reveal` will create the data
//! for public key tweaking procedure (`TweakData`), including the tweaking `factor` and random
//! `nonce`. These data can be used later for both commit phase (public key will be tweaked with
//! these data creating an actual commitment) and reveal phase (i.e. they will allow any third
//! party to verify the actual commitment):
//!
//! ```rust
//! let original_pubkey = PublicKey::from_str("02d1d80235fa5bba42e9612a7fe7cd74c6b2bf400c92d866f28d429846c679cceb").unwrap();
//! let engine = TweakingEngine(original_pubkey);
//! let msg = "Some message";
//! let tweak = engine.reveal(&TweakSource::from(msg));
//! let commitment = tweak.commit();
//! assert!()
//! ```
//!
//! NB: The library works with `secp256k1::PublicKey` and `secp256k1::SecretKey` keys, not
//! their wrapped bitcoin counterparts `bitcoin::PublickKey` and `bitcoin::PrivateKey`.

use secp256k1::{rand::random, PublicKey, SecretKey, Secp256k1, All};
use bitcoin::hashes::{sha256, HmacEngine, HashEngine, Hmac, Hash};

use crate::commitments::base::*;

/// Data structure providing necessary structured information for an elliptic curve-based
/// commitments based on LNPBPS-0001
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct TweakSource<'a> {
    /// Protocol tag literal
    pub protocol: &'static str,

    /// Message to commit to. The message is stored as a reference to a byte array. The commit
    /// procedure will compute HMAC-SHA256 from this array and original public key defined as a part
    /// of `TweakingEngine`
    pub message: &'a [u8],
}

impl<'a> CommitmentSource for TweakSource<'a> {}

/// We commit by tweaking public key, so we need to define `PublicKey` as a `CommitTarget`
impl CommitTarget for PublicKey {}

/// Elliptic curve key pairs are tweaked with 32-bit number, which corresponds to the Secp256k1
/// order. Usually this is a digest (result of a hash function, but we define it as a special type,
/// since it may change in the future to be a generic non-hash 32-bit value
pub type TweakFactor = sha256::Hash;

/// Data required for both creating the actual elliptic-curve based commitment and for verifying
/// existing commitment during the *reveal* phase. They provide a family of elliptic curve
/// (for the current version it's always Secp256k1), tweaking factor, computed with a tagged-hash
/// and HMAC procedure over the source message from `TweakSource` with original public key coming
/// from `TweakingEngine`, the original public key itself and a `nonce`. These data are sufficient
/// to compute the tweaked version of both public and private keys – or to verify that an existing
/// tweaked public key contain a commitment to message under given protocol from which `TweakData`
/// was created.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TweakData {
    /// Used elliptic curve family
    pub ec: Secp256k1<All>,

    /// Tweak factor created from `TweakSource` by tweaking procedure, unique for each `TweakSource`
    /// Non-deterministic, because it includes a `nonce` non-determinism.
    pub factor: TweakFactor,

    /// Non-deterministic part for the tweak, generated randomly. Required for:
    /// 1. Reducing probability of rainbow-table attacks
    /// 2. Prevent `factor` overflow beyond elliptoc-curve order
    ///
    /// It is present separately from the `factor` since w/o it the factor can't be reconstructed
    /// from the original message, making `reveal` procedure impossible.
    pub nonce: u8,
    // FIXME: consider making random part a 32-bit number, to reduce probability of rainbow-table attacks

    /// The original (untweaked) public key, required for the verification procedure
    pub key: PublicKey,
}

impl RevealData<PublicKey> for TweakData {
    /// Commitment procedure, which basically calls crate-internal `tweak_public` function
    /// tweaking the public key with a given factor
    fn commit(&self) -> PublicKey {
        self.tweak_public()
    }

    /// Verifies a given commitment (a tweaked public key) by comparing it with the version that
    /// can be reconstructed from the original public key by adding to it a tweaking factor
    fn verify(&self, commit: PublicKey) -> bool {
        let tweaked = self.tweak_public();
        return commit == tweaked
    }
}

impl TweakData {
    /// Tweaks original public key (stored in `key` field) producing commitment (tweaked key) by
    /// adding a second elliptic curve point created from a generator point multiplied by
    /// a tweaking `factor`.
    pub(crate) fn tweak_public(&self) -> PublicKey {
        let mut tweaked = self.key.clone();
        tweaked.add_exp_assign(&self.ec, &self.factor[..]).expect("Must not fail");
        tweaked
    }

    /// Tweaks a given private key `original` producing a tweaked version matching thee
    /// public key containing commitment to a given `factor` by adding the factor to the key
    /// and modulo-dividing it on the elliptic curve order number (the operation is performedby by
    /// the standard Secp256k1 library.
    pub fn tweak_secret(&self, original: SecretKey) -> SecretKey {
        let mut tweaked_secret = original.clone();
        tweaked_secret.add_assign(&self.factor[..]).expect("Must not fail");
        tweaked_secret
    }
}

/// Wrapper around `PublicKey` that can produce different tweaks of the key
/// by implementing `CommitmentEngine` trait
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct TweakingEngine(PublicKey);

impl<'a> CommitmentEngine<PublicKey, TweakSource<'a>, TweakData> for TweakingEngine {
    /// The function produces a tweaking factor and related data packed into the returned `TweakData`
    /// type for a given source message and protocol information from it's `src` argument of
    /// `TweakSource` type.
    ///
    /// The resulting `TweakData` can be used for producing the actual commitment to the tweak factor
    /// in form of a tweaked public key (with `commit` method) -- or to verify some public key to
    /// contain the commitment to the factor from the `TweakData` with `verify` method
    ///
    /// The function implementation strictly follows the specification from
    /// [LNPBPS-0001](https://github.com/LNP-BP/lnpbps/blob/master/lnpbps-0001.md#Specification)
    fn reveal(&self, src: &TweakSource) -> TweakData {
        let ec = Secp256k1::new();

        // 1. Compute HMAC-SHA256 of the `msg` and `P`: `hmac = HMAC_SHA256(msg, P)`
        let mut hmac_engine: HmacEngine<sha256::Hash> = HmacEngine::new(&self.0.serialize());
        hmac_engine.input(&src.message[..]);
        let hmac_sha256 = Hmac::from_engine(hmac_engine);

        // 2. Compute concatenation of two single SHA256 hashes for protocol tag `t`
        let tag_hash = sha256::Hash::hash(&src.protocol.as_bytes()).to_vec();
        let mut t = tag_hash.clone();
        t.extend(&tag_hash);

        // TODO: Avoid unbonded loop; transform the return type into `Result` and return a error if it was impossible to find a proper nonce
        loop {
            // 3. Compute a random 8-bit nonce
            let nonce: u8 = random();

            // 4.  Compute tweaking string `s = t || SHA256('LNPBPS-0001') || hmac || n`
            let mut s = t.clone();
            s.extend(&sha256::Hash::hash(b"LNPBPS-0001").to_vec());
            s.extend(&hmac_sha256[..].to_vec());
            s.extend(&vec![nonce]);

            // 5. Compute tweaking factor `h = SHA256(s)`
            let factor = &sha256::Hash::hash(&s);

            // 6. If the factor value is equal of greater than the elliptic curve order repeat
            // from step 3 with a different nonce
            let mut pk = self.0.clone();
            if pk.add_exp_assign(&ec, &factor[..]).is_ok() {
                return TweakData {
                    ec,
                    factor: *factor,
                    nonce,
                    key: self.0
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashes::core::str::FromStr;

    impl<'a> From<&'a str> for TweakSource<'a> {
        fn from(msg: &'a str) -> Self {
            TweakSource {
                protocol: "str",
                message: msg.as_bytes()
            }
        }
    }

    fn get_public_key(index: usize) -> PublicKey {
        [
            PublicKey::from_str("02d1d80235fa5bba42e9612a7fe7cd74c6b2bf400c92d866f28d429846c679cceb").unwrap(),
            PublicKey::from_str("02d1d80235fa5bba42e9612a7fe7cd74c6b2bf400c92d866f28d429846c679cceb").unwrap(),
        ][index]
    }

    /// `TweakSource::from` must produce deterministic result for the same message
    #[test]
    fn tweaksource_deterministic() {
        let msg = "Some message";
        let src1 = TweakSource::from(msg);
        let src2 = TweakSource::from(msg);
        assert_eq!(src1, src2);
    }

    /// `TweakSource::from` must produce unique tweak for two slightnly-different messages
    #[test]
    fn tweaksource_unique() {
        let msg1 = "Some message";
        let msg2 = "Some messagè";
        let src1 = TweakSource::from(msg1);
        let src2 = TweakSource::from(msg2);
        assert_ne!(src1, src2);
        // But the protocol tag should be the same
        assert_eq!(src1.protocol, src2.protocol);
    }

    /// `TweakEngine::reveal` must be a non-deterministic tweak-generation procedure due to the
    /// presence of random `nonce`
    #[test]
    fn reveal_nondeterministic() {
        let engine = TweakingEngine(get_public_key(0));

        let msg = "Some message";
        let src = TweakSource::from(msg);
        let tweak1 = engine.reveal(&src);
        let mut tweak2 = engine.reveal(&src);
        // There are 1/256 probability that both tweaks will be the same, so we need to avoid
        // occasional test failures due to this probability and re-compute the second tweak,
        // so the probability of two tweaks matching will be reduced to 1/(256^3), which is
        // sufficient to have stable test results
        if tweak1 == tweak2 {
            tweak2 = engine.reveal(&src);
        }
        if tweak1 == tweak2 {
            tweak2 = engine.reveal(&src);
        }
        // Here we check both equation function and each of the fields which must be non-equal
        assert_ne!(tweak1, tweak2);
        assert_ne!(tweak1.factor, tweak2.factor);
        assert_ne!(tweak1.nonce, tweak2.nonce);
        // But the  public key should remain the same
        assert_eq!(tweak1.key, tweak2.key);
    }

    /// `TweakEngine::reveal` must *always* produce unique tweaks for two distinct messages
    #[test]
    fn reveal_unique() {
        let engine = TweakingEngine(get_public_key(0));

        let msg1 = "Some message";
        let msg2 = "Some messagè";
        let src1 = TweakSource::from(msg1);
        let src2 = TweakSource::from(msg2);
        let tweak1 = engine.reveal(&src1);
        let tweak2 = engine.reveal(&src2);
        assert_ne!(tweak1, tweak2);
        assert_ne!(tweak1.factor, tweak2.factor);
        // But the original public key should still be the same (it's provided by the engine)
        assert_eq!(tweak1.key, tweak2.key);
    }

    /// The commitment must be verifiable given the same tweak data
    #[test]
    fn commit_reveal() {
        let engine = TweakingEngine(get_public_key(0));

        let msg = "Some message";
        let src = TweakSource::from(msg);
        let tweak = engine.reveal(&src);
        let commitment = tweak.commit();
        assert!(tweak.verify(commitment));
    }

    /// The commitment must fail verification for a tweak data produced by some other message
    /// or having the different nonce
    #[test]
    fn failed_reveal() {
        let engine = TweakingEngine(get_public_key(0));

        let msg1 = "Some message";
        let src1 = TweakSource::from(msg1);
        let tweak1 = engine.reveal(&src1);
        let commitment = tweak1.commit();

        let msg2 = "Some messagè";
        let src2 = TweakSource::from(msg2);
        let tweak2 = engine.reveal(&src2);

        assert!( !tweak2.verify(commitment) );

        let mut tweak3 = engine.reveal(&src1);
        if tweak1 == tweak2 {
            tweak3 = engine.reveal(&src1);
        }
        if tweak1 == tweak2 {
            tweak3 = engine.reveal(&src1);
        }

        assert!( !tweak3.verify(commitment) );
    }
}

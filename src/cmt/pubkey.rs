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
//! [LNPBP-1](https://github.com/LNP-BP/lnpbps/blob/master/lnpbp-0001.md)
//!
//! NB: The library works with `secp256k1::PublicKey` and `secp256k1::SecretKey` keys, not
//! their wrapped bitcoin counterparts `bitcoin::PublickKey` and `bitcoin::PrivateKey`.

use std::sync::Once;

use bitcoin::hashes::*;
use bitcoin::secp256k1::{*, Error as CurveError};

use crate::common::*;
use super::committable::*;

const TAG: &'static str = "LNPBP1";
static INIT: Once = Once::new();
static mut PREFIX: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

#[derive(Debug)]
pub enum Error {
    ECPointAtInfinity
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PubkeyCommitment {
    pub tweaked: PublicKey,
    pub original: PublicKey,
}

impl<MSG> CommitmentVerify<MSG> for PubkeyCommitment where
    MSG: EmbedCommittable<Self> + AsSlice
{

    #[inline]
    fn reveal_verify(&self, msg: &MSG) -> bool {
        <Self as EmbeddedCommitment<MSG>>::reveal_verify(&self, &msg)
    }
}

impl<MSG> EmbeddedCommitment<MSG> for PubkeyCommitment where
    MSG: EmbedCommittable<Self> + AsSlice,
{
    type Container = PublicKey;
    type Error = CurveError;

    #[inline]
    fn get_original_container(&self) -> Self::Container {
        self.original
    }

    /// According to LNPBP-1 the message supplied here must be already prefixed with 32-byte SHA256
    /// has of the protocol-specific prefix
    fn commit_to(container: Self::Container, msg: &MSG) -> Result<Self, Self::Error> {
        let ec: Secp256k1<All> = Secp256k1::new();

        // Unsafe since we use a mutable static
        INIT.call_once(|| unsafe {
            PREFIX = sha256::Hash::hash(TAG.as_bytes()).into_inner()
        });

        let mut buff = vec!();
        // Unsafe since we use a mutable static
        unsafe {
            buff.extend(&PREFIX);
        }
        buff.extend(msg.as_slice());
        let mut hmac_engine = HmacEngine::<sha256::Hash>::new(&container.serialize());
        hmac_engine.input(&buff[..]);
        let factor = &Hmac::from_engine(hmac_engine)[..];
        let mut tweaked = container.clone();

        tweaked.add_exp_assign(&ec, factor)?;

        Ok(PubkeyCommitment {
            tweaked,
            original: container
        })
    }
}

impl<T> Verifiable<PubkeyCommitment> for T where T: AsSlice { }

impl<T> EmbedCommittable<PubkeyCommitment> for T where T: AsSlice { }

impl From<CurveError> for self::Error {
    fn from(error: CurveError) -> Self {
        match error {
            CurveError::InvalidTweak => self::Error::ECPointAtInfinity,
            _ => panic!("Other types of Secp256k1 errors can't be fired by `add_exp_assign`"),
        }
    }
}


#[cfg(test)]
mod test {
    use std::str::FromStr;
    use bitcoin::secp256k1::PublicKey;
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    struct Message<'a>(&'a str);
    impl AsSlice for Message<'_> {
        fn as_slice(&self) -> &[u8] {
            &self.0.as_bytes()
        }
    }

    #[test]
    // Test according to LNPBP-1 standard
    fn test_lnpbp1_commitment() {
        let pubkey = PublicKey::from_str(
            "0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166"
        ).unwrap();
        let msg = "Message to commit to";
        let tag = "RGB";

        let prefix = sha256::Hash::hash(tag.as_bytes());
        let mut prefixed_msg = prefix.to_vec();
        prefixed_msg.extend(msg.bytes());

        let commitment: PubkeyCommitment = prefixed_msg.clone().commit_embed(pubkey).unwrap();
        //assert_eq!(commitment.tweaked.to_hex(),
        //           "02b483ae49421fd8751b31278c6905eca00a8241a2ee3584bffc85655aa9123c02");
        assert_eq!(prefixed_msg.verify(&commitment), true);
    }
}
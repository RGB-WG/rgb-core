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
//! [LNPBPS-1](https://github.com/LNP-BP/lnpbps/blob/master/lnpbps-0001.md)
//!
//! NB: The library works with `secp256k1::PublicKey` and `secp256k1::SecretKey` keys, not
//! their wrapped bitcoin counterparts `bitcoin::PublickKey` and `bitcoin::PrivateKey`.

use std::sync::Once;
use std::convert::TryInto;

use secp256k1::{*, Error as CurveError};
use bitcoin::hashes::*;

use crate::common::*;
use super::committable::*;
use crate::cmt::Error::ECPointAtInfinity;

const TAG: &'static str = "LNPBP-1";
static INIT: Once = Once::new();
static mut PREFIX: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

pub enum Error {
    ECPointAtInfinity
}

#[derive(Clone, Eq, PartialEq)]
pub struct PubkeyCommitment {
    pub tweaked: PublicKey,
    pub original: PublicKey,
}

impl<MSG> CommitmentVerify<MSG> for PubkeyCommitment where
    MSG: EmbedCommittable<PublicKey, Self> + AsBytes
{

    #[inline]
    fn reveal_verify(&self, msg: &MSG) -> bool {
        <Self as EmbeddedCommitment<PublicKey, MSG>>::reveal_verify(&self, msg)
    }
}

impl<MSG> EmbeddedCommitment<PublicKey, MSG> for PubkeyCommitment where
    MSG: EmbedCommittable<PublicKey, Self> + AsBytes,
{
    type Error = CurveError;

    #[inline]
    fn get_original_container(&self) -> &PublicKey {
        &self.original
    }

    fn from(container: &PublicKey, msg: &MSG) -> Result<Self, Self::Error> {
        let ec: Secp256k1<All> = Secp256k1::new();
        INIT.call_once(|| unsafe {
            PREFIX = BitcoinTag::tag(TAG)[..].try_into()
                .expect("SHA256 length is 32 bytes always");
        });

        let mut buff = msg[..].to_vec();
        unsafe {
            let prefix = BitcoinTag::from_slice(&PREFIX)
                .expect("Can't fail since it reads hash value");
            buff.extend(&prefix[..]);
        }
        let mut hmac_engine = HmacEngine::<sha256::Hash>::new(&container.serialize());
        hmac_engine.input(&buff[..]);
        let factor = &Hmac::from_engine(hmac_engine)[..];
        let mut tweaked = container.clone();

        tweaked.add_exp_assign(&ec, factor)?;

        Ok(PubkeyCommitment {
            tweaked,
            original: *container
        })
    }
}

impl<T> Verifiable<PubkeyCommitment> for T where T: AsBytes { }

impl<T> EmbedCommittable<PublicKey, PubkeyCommitment> for T where T: AsBytes { }

impl From<CurveError> for self::Error {
    fn from(error: CurveError) -> Self {
        match error {
            CurveError::InvalidTweak => ECPointAtInfinity,
            _ => panic!("This errors should never fire"),
        }
    }
}

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

use secp256k1::{PublicKey, Secp256k1, All};
use bitcoin::hashes::{sha256, HmacEngine, HashEngine, Hmac, Hash};

use crate::commitments::base::*;

pub struct TweakSource(pub sha256::Hash);
impl CommittableMessage for TweakSource {}
impl CommitmentContainer for PublicKey {}
impl CommitmentProofs for PublicKey {}

pub struct TweakEngine {}

impl TweakEngine {
    const TAG: &'static str = "LNPBP-1";
    //static EC: Secp256k1<All> = Secp256k1::new();

    pub fn new() -> Self {
        TweakEngine {}
    }
}

impl CommitmentEngine<TweakSource, PublicKey, PublicKey> for TweakEngine {
    fn commit(&self, message: &TweakSource, container: &mut PublicKey) -> PublicKey {
        let ec: Secp256k1<All> = Secp256k1::new();

        let tag_hash = sha256::Hash::hash(&TweakEngine::TAG.as_bytes()).to_vec();
        let mut s = tag_hash.clone();
        s.extend(&tag_hash);
        s.extend(&message.0[..]);

        let original_pubkey = container.clone();
        let mut hmac_engine: HmacEngine<sha256::Hash> = HmacEngine::new(&original_pubkey.serialize());
        hmac_engine.input(&s[..]);
        let factor = &Hmac::from_engine(hmac_engine)[..];

        container.add_exp_assign(&ec, factor).expect("Must not fail");

        original_pubkey
    }

    fn verify(&self, message: &TweakSource, container: &PublicKey, original_pubkey: &PublicKey) -> bool { unimplemented!() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashes::core::str::FromStr;

}

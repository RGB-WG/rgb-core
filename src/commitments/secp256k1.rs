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

use std::any::Any;

use secp256k1::{rand::random, PublicKey, SecretKey, Secp256k1, All};
use bitcoin::hashes::{sha256, HmacEngine, HashEngine, Hmac, Hash};

use crate::commitments::base::*;

/// Data structure for elliptic curve-based commitments from LNPBPS-0001
pub struct TweakCommitmentSource {
    /// Protocol tag
    pub protocol: &'static str,

    /// Message to commit to
    pub message: Vec<u8>,
}

impl CommitmentSource for TweakCommitmentSource {
    fn as_any(&self) -> &(dyn Any) {
        self
    }
}

impl CommitTarget for PublicKey {}

pub type TweakFactor = sha256::Hash;

pub struct TweakData {
    pub ec: Secp256k1<All>,
    pub factor: TweakFactor,
    pub nonce: u8,
    pub key: PublicKey,
}

impl RevealData<PublicKey> for TweakData {
    fn commit(&self) -> PublicKey {
        self.tweak_public()
    }

    fn verify(&self, commit: PublicKey) -> bool {
        let tweaked = self.tweak_public();
        return commit == tweaked
    }
}

impl TweakData {
    pub fn tweak_public(&self) -> PublicKey {
        let mut tweaked = self.key.clone();
        tweaked.add_exp_assign(&self.ec, &self.factor[..]).expect("Must not fail");
        tweaked
    }

    pub fn tweak_secret(&self, original: SecretKey) -> SecretKey {
        let mut tweaked_secret = original.clone();
        tweaked_secret.add_assign(&self.factor[..]).expect("Must not fail");
        tweaked_secret
    }
}

pub struct TweakingEngine(PublicKey);

impl CommitmentEngine<PublicKey, TweakData> for TweakingEngine {
    fn reveal(&self, src: &CommitmentSource) -> TweakData {
        let a: Box<&dyn CommitmentSource> = Box::new(src);
        let src: &TweakCommitmentSource = match a.as_any().downcast_ref::<TweakCommitmentSource>() {
            Some(b) => b,
            None => panic!("src must be of TweakCommitmentSource type"),
        };
        let ec = Secp256k1::new();

        // 1. Compute HMAC-SHA256 of the `msg` and `P`: `hmac = HMAC_SHA256(msg, P)`
        let mut hmac_engine: HmacEngine<sha256::Hash> = HmacEngine::new(&self.0.serialize());
        hmac_engine.input(&src.message[..]);
        let hmac_sha256 = Hmac::from_engine(hmac_engine);

        // 2. Compute concatenation of two single SHA256 hashes for protocol tag `t`
        let tag_hash = sha256::Hash::hash(&src.protocol.as_bytes()).to_vec();
        let mut t = tag_hash.clone();
        t.extend(&tag_hash);

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

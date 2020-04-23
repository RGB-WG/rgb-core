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

use bitcoin::hashes::{sha256, Hash, HashEngine, Hmac, HmacEngine};
use bitcoin::secp256k1::{self, Secp256k1};

use crate::primitives::commit_verify::CommitEmbedVerify;

/// Single SHA256 hash of "LNPBP1" string according to LNPBP-1 acting as a
/// prefix to the message in computing tweaking factor
static SHA256_LNPBP1: [u8; 32] = [
    245, 8, 242, 142, 252, 192, 113, 82, 108, 168, 134, 200, 224, 124, 105, 212, 149, 78, 46, 201,
    252, 82, 171, 140, 204, 209, 41, 17, 12, 0, 64, 175,
];

wrapper!(
    PubkeyCommitment,
    secp256k1::PublicKey,
    doc = "Public key committed to some message via LNPBP1-based tweaking procedure",
    derive = [PartialEq, Eq, Hash]
);

impl<MSG> CommitEmbedVerify<MSG> for PubkeyCommitment
where
    MSG: AsRef<[u8]>,
{
    type Container = secp256k1::PublicKey;
    type Error = secp256k1::Error;

    /// NB: According to LNPBP-1 the message supplied here must be already prefixed with 32-byte SHA256
    /// hash of the protocol-specific prefix
    fn commit_embed(pubkey_container: Self::Container, msg: &MSG) -> Result<Self, Self::Error> {
        let ec = Secp256k1::<secp256k1::All>::new();
        let mut hmac_engine = HmacEngine::<sha256::Hash>::new(&pubkey_container.serialize());
        hmac_engine.input(&SHA256_LNPBP1);
        hmac_engine.input(msg.as_ref());
        let factor = &Hmac::from_engine(hmac_engine)[..];
        let mut pubkey_tweaked = pubkey_container.clone();
        pubkey_tweaked.add_exp_assign(&ec, factor)?;

        Ok(PubkeyCommitment(pubkey_tweaked))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bitcoin::hashes::{hex::ToHex, sha256};
    use bitcoin::secp256k1::PublicKey;
    use std::str::FromStr;

    #[test]
    fn test_lnpbp1_tag() {
        assert_eq!(
            sha256::Hash::hash("LNPBP1".as_ref()).into_inner(),
            SHA256_LNPBP1
        );
        assert_ne!(
            sha256::Hash::hash("LNPBP-1".as_ref()).into_inner(),
            SHA256_LNPBP1
        );
        assert_ne!(
            sha256::Hash::hash("lnpbp1".as_ref()).into_inner(),
            SHA256_LNPBP1
        );
    }

    #[test]
    // Test according to LNPBP-1 standard
    fn test_lnpbp1_commitment() {
        let pubkey = PublicKey::from_str(
            "0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166",
        )
        .unwrap();
        let msg = "Message to commit to";
        let tag = "RGB";

        let prefix = sha256::Hash::hash(tag.as_bytes());
        let mut prefixed_msg = prefix.to_vec();
        prefixed_msg.extend(msg.as_bytes());

        let commitment = PubkeyCommitment::commit_embed(pubkey, &prefixed_msg).unwrap();
        assert_eq!(
            commitment.0.to_hex(),
            "02533c2a16bca85069a7c54c4e5e0682a24783f2c0a7c47c15e545d37cc4c52d5a"
        );
        assert_eq!(commitment.verify(pubkey, &prefixed_msg), true);
    }
}

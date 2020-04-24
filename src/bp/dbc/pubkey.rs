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

//! LNPBP-1
//! =======
//!
//! Module for Secp256k1 elliptic curve based collision-resistant commitments, implementing
//! [LNPBP-1](https://github.com/LNP-BP/lnpbps/blob/master/lnpbp-0001.md)
//!
//! The work proposes a standard for cryptographic commitments based on elliptic
//! curve properties, that can be embedded into Bitcoin transaction without
//! additional storage footprint. This commitments are private: the can be
//! detected and  revealed only to the parties sharing some secret (original
//! value of the public key).
//!
//! NB: The library works with `secp256k1::PublicKey` and `secp256k1::SecretKey` keys, not
//! their wrapped bitcoin counterparts `bitcoin::PublickKey` and `bitcoin::PrivateKey`.

use bitcoin::hashes::{sha256, Hash, HashEngine, Hmac, HmacEngine};
use bitcoin::secp256k1::{self, Secp256k1};

use super::{Container, Proof, ProofSuppl};
use crate::bp::dbc::Error;
use crate::commit_verify::CommitEmbedVerify;

/// Single SHA256 hash of "LNPBP1" string according to LNPBP-1 acting as a
/// prefix to the message in computing tweaking factor
static SHA256_LNPBP1: [u8; 32] = [
    245, 8, 242, 142, 252, 192, 113, 82, 108, 168, 134, 200, 224, 124, 105, 212, 149, 78, 46, 201,
    252, 82, 171, 140, 204, 209, 41, 17, 12, 0, 64, 175,
];

impl Container for secp256k1::PublicKey {
    type Supplement = Option<()>;
    type Commitment = Option<()>;

    fn restore(proof: &Proof, _: &Self::Supplement, _: &Self::Commitment) -> Result<Self, Error> {
        Ok(proof.pubkey)
    }

    // A proof for the LNPBP-1 public key commitment is the original public key
    // value, so the commitment container (original public key) just returns a
    // copy of itself
    fn to_proof(&self) -> Proof {
        Proof {
            pubkey: self.clone(),
            suppl: ProofSuppl::None,
        }
    }
}

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

    /// Function implements commitment procedure according to LNPBP-1.
    ///
    /// LNPBP-1 Specification extract:
    /// ------------------------------
    ///
    /// For a given message `msg` and original public key `P` the **commit procedure** is defined as follows:
    ///
    /// 1. Construct a byte string `lnbp1_msg`, composed of the original message prefixed with a single SHA256 hash of `LNPBP1`
    ///    string and a single SHA256 hash of protocol-specific tag:
    ///    `lnbp1_msg = SHA256("LNPBP1") || SHA256(<protocol-specific-tag>) || msg`
    /// 2. Compute HMAC-SHA256 of the `lnbp1_msg` and `P`, named **tweaking factor**: `f = HMAC_SHA256(s, P)`
    /// 3. Make sure that the tweaking factor is less than order `p` of Zp prime number set used in Secp256k1 curve; otherwise
    ///    fail the protocol.
    /// 3. Multiply the tweaking factor on Secp256k1 generator point `G`: `F = G * f` ignoring the possible overflow of the
    ///    resulting elliptic curve point `F` over the order `n` of `G`. Check that the result not equal to the
    ///    point-at-infinity; otherwise fail the protocol, indicating the reason of failure, such that the protocol may be run
    ///    with another initial public key `P'` value.
    /// 4. Add two elliptic curve points, the original public key `P` and tweaking-factor based point `F`, obtaining the
    ///    resulting tweaked public key `T`: `T = P + F`. Check that the result not equal to the point-at-infinity; otherwise
    ///    fail the protocol, indicating the reason of failure, such that the protocol may be run with another initial
    ///    public key `P'` value.
    ///
    /// The final formula for the commitment is:
    /// `T = P + G * HMAC_SHA256(SHA256("LNPBP1") || SHA256(<protocol-specific-tag>) || msg, P)`
    ///
    /// NB: According to LNPBP-1 the message supplied here must be already
    /// prefixed with 32-byte SHA256 hash of the protocol-specific prefix

    // #[consensus_critical]
    // #[standard_critical("LNPBP-1")]
    fn commit_embed(pubkey_container: Self::Container, msg: &MSG) -> Result<Self, Self::Error> {
        let ec = Secp256k1::<secp256k1::All>::new();

        // ! [CONSENSUS-CRITICAL]:
        // ! [STANDARD-CRITICAL]: HMAC engine is based on sha256 hash
        let mut hmac_engine = HmacEngine::<sha256::Hash>::new(&pubkey_container.serialize());

        // ! [CONSENSUS-CRITICAL]:
        // ! [STANDARD-CRITICAL]: Hash process started with consuming first
        //                        protocol prefix: single SHA256 hash of
        //                        ASCII "LNPBP-1" string
        hmac_engine.input(&SHA256_LNPBP1);

        // ! [CONSENSUS-CRITICAL]:
        // ! [STANDARD-CRITICAL]: Next we hash the message. The message must be
        //                        prefixed with the protocol-specific prefix:
        //                        another single SHA256 hash of protocol name.
        //                        However this is not the part of this function,
        //                        the function expect that the `msg` is already
        //                        properly prefixed
        hmac_engine.input(msg.as_ref());

        // Producing tweaking factor
        let factor = &Hmac::from_engine(hmac_engine)[..];
        // Applying tweaking factor to public key
        let mut pubkey_tweaked = pubkey_container.clone();
        pubkey_tweaked.add_exp_assign(&ec, factor)?;

        // Returning tweaked public key
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

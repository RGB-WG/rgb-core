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

//! # LNPBP-1
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
use bitcoin::secp256k1;

use super::{Container, Error, Proof};
use crate::commit_verify::EmbedCommitVerify;
use crate::SECP256K1;

/// Single SHA256 hash of "LNPBP1" string according to LNPBP-1 acting as a
/// prefix to the message in computing tweaking factor
pub(super) static SHA256_LNPBP1: [u8; 32] = [
    245, 8, 242, 142, 252, 192, 113, 82, 108, 168, 134, 200, 224, 124, 105, 212, 149, 78, 46, 201,
    252, 82, 171, 140, 204, 209, 41, 17, 12, 0, 64, 175,
];

/// Container for LNPBP-1 commitments. In order to be constructed, commitment
/// requires an original public key and a protocol-specific tag, which
/// must be hashed during commitment process. Here we use pre-hashed version
/// of the tag in order to maximize performance for multiple commitments.
#[derive(Clone, PartialEq, Eq, Debug, Display, Hash)]
#[display_from(Debug)]
pub struct LNPBP1Container {
    /// The original public key: host for commitment
    pub pubkey: secp256k1::PublicKey,
    /// Single SHA256 hash of the protocol-specific tag
    pub tag: sha256::Hash,
}

impl Container for LNPBP1Container {
    /// Out supplement is a protocol-specific tag in its hashed form
    type Supplement = sha256::Hash;
    /// Our proof contains the host, so we don't need host here
    type Host = Option<()>;

    fn reconstruct(
        proof: &Proof,
        supplement: &Self::Supplement,
        _: &Self::Host,
    ) -> Result<Self, Error> {
        Ok(Self {
            pubkey: proof.pubkey,
            tag: supplement.clone(),
        })
    }

    #[inline]
    fn deconstruct(self) -> (Proof, Self::Supplement) {
        (Proof::from(self.pubkey), self.tag)
    }

    // A proof for the LNPBP-1 public key commitment is the original public key
    // value, so the commitment container (original public key) just returns a
    // copy of itself
    #[inline]
    fn to_proof(&self) -> Proof {
        Proof::from(self.pubkey.clone())
    }

    #[inline]
    fn into_proof(self) -> Proof {
        Proof::from(self.pubkey)
    }
}

wrapper!(
    LNPBP1Commitment,
    secp256k1::PublicKey,
    doc = "Public key committed to some message via LNPBP1-based tweaking procedure",
    derive = [PartialEq, Eq, Hash]
);

impl<MSG> EmbedCommitVerify<MSG> for LNPBP1Commitment
where
    MSG: AsRef<[u8]>,
{
    type Container = LNPBP1Container;
    type Error = secp256k1::Error;

    /// Function implements commitment procedure according to LNPBP-1.
    ///
    /// ## LNPBP-1 Specification extract:
    ///
    /// For a given message `msg` and original public key `P` the **commit
    /// procedure** is defined as follows:
    ///
    /// 1. Construct a byte string `lnbp1_msg`, composed of the original message
    ///    prefixed with a single SHA256 hash of `LNPBP1`
    ///    string and a single SHA256 hash of protocol-specific tag:
    ///    `lnbp1_msg = SHA256("LNPBP1") || SHA256(<protocol-specific-tag>) || msg`
    /// 2. Compute HMAC-SHA256 of the `lnbp1_msg` and `P`, named **tweaking
    ///    factor**: `f = HMAC_SHA256(s, P)`
    /// 3. Make sure that the tweaking factor is less than order `p` of Zp prime
    ///    number set used in Secp256k1 curve; otherwise fail the protocol.
    /// 3. Multiply the tweaking factor on Secp256k1 generator point
    ///    `G`: `F = G * f` ignoring the possible overflow of the resulting
    ///    elliptic curve point `F` over the order `n` of `G`. Check that the
    ///    result not equal to the point-at-infinity; otherwise fail the
    ///    protocol, indicating the reason of failure, such that the protocol
    ///    may be run with another initial public key `P'` value.
    /// 4. Add two elliptic curve points, the original public key `P` and
    ///    tweaking-factor based point `F`, obtaining the resulting tweaked
    ///    public key `T`: `T = P + F`. Check that the result not equal to the
    ///    point-at-infinity; otherwise fail the protocol, indicating the reason
    ///    of failure, such that the protocol may be run with another initial
    ///    public key `P'` value.
    ///
    /// The final formula for the commitment is:
    /// `T = P + G * HMAC_SHA256(SHA256("LNPBP1") || SHA256(<protocol-specific-tag>) || msg, P)`
    ///
    /// NB: According to LNPBP-1 the message supplied here must be already
    /// prefixed with 32-byte SHA256 hash of the protocol-specific prefix

    // #[consensus_critical]
    // #[standard_critical("LNPBP-1")]
    fn embed_commit(pubkey_container: &Self::Container, msg: &MSG) -> Result<Self, Self::Error> {
        // ! [CONSENSUS-CRITICAL]:
        // ! [STANDARD-CRITICAL]: HMAC engine is based on sha256 hash
        let mut hmac_engine = HmacEngine::<sha256::Hash>::new(&pubkey_container.pubkey.serialize());

        // ! [CONSENSUS-CRITICAL]:
        // ! [STANDARD-CRITICAL]: Hash process started with consuming first
        //                        protocol prefix: single SHA256 hash of
        //                        ASCII "LNPBP-1" string
        hmac_engine.input(&SHA256_LNPBP1);

        // ! [CONSENSUS-CRITICAL]:
        // ! [STANDARD-CRITICAL]: The second prefix comes from the upstream
        //                        protocol as a part of the container
        hmac_engine.input(&pubkey_container.tag[..]);

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
        let mut tweaked_pubkey = pubkey_container.pubkey.clone();
        tweaked_pubkey.add_exp_assign(&SECP256K1, factor)?;

        // Returning tweaked public key
        Ok(LNPBP1Commitment(tweaked_pubkey))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::bp::test::*;
    use crate::commit_verify::test::*;
    use amplify::Wrapper;
    use bitcoin::hashes::{hex::ToHex, sha256};
    use bitcoin::secp256k1;
    use std::str::FromStr;

    #[test]
    fn test_lnpbp1_tag() {
        assert_eq!(
            sha256::Hash::hash("LNPBP1".as_ref()).into_inner(),
            SHA256_LNPBP1
        );
        assert_ne!(
            sha256::Hash::hash("LNPBP2".as_ref()).into_inner(),
            SHA256_LNPBP1
        );
        assert_ne!(
            sha256::Hash::hash("LNPBP-1".as_ref()).into_inner(),
            SHA256_LNPBP1
        );
        assert_ne!(
            sha256::Hash::hash("LNPBP_1".as_ref()).into_inner(),
            SHA256_LNPBP1
        );
        assert_ne!(
            sha256::Hash::hash("lnpbp1".as_ref()).into_inner(),
            SHA256_LNPBP1
        );
        assert_ne!(
            sha256::Hash::hash("lnpbp-1".as_ref()).into_inner(),
            SHA256_LNPBP1
        );
        assert_ne!(
            sha256::Hash::hash("lnpbp_1".as_ref()).into_inner(),
            SHA256_LNPBP1
        );
    }

    #[test]
    fn test_pubkey_commitment() {
        let tag = sha256::Hash::hash(b"TEST_TAG");
        gen_secp_pubkeys(9).into_iter().for_each(|pubkey| {
            embed_commit_verify_suite::<Vec<u8>, LNPBP1Commitment>(
                gen_messages(),
                &LNPBP1Container { pubkey, tag },
            );
        });
    }

    #[test]
    fn test_tweaking_results() {
        let tag = sha256::Hash::hash(b"TEST_TAG");
        let msg = "test message";
        let pubkey = secp256k1::PublicKey::from_str(
            "0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166",
        )
        .unwrap();
        let commitment =
            LNPBP1Commitment::embed_commit(&LNPBP1Container { pubkey, tag }, &msg).unwrap();
        assert_eq!(
            commitment.as_inner().to_hex(),
            "0278565af0da38a7754d3d4551a09bf80cf98841dbec7330db53023af5503acf8d"
        );
    }
}

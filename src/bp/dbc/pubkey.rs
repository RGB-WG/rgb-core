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
//! Module for Secp256k1 elliptic curve based collision-resistant commitments,
//! implementing [LNPBP-1](https://github.com/LNP-BP/lnpbps/blob/master/lnpbp-0001.md)
//!
//! The work proposes a standard for cryptographic commitments based on elliptic
//! curve properties, that can be embedded into Bitcoin transaction without
//! additional storage footprint. This commitments are private: the can be
//! detected and  revealed only to the parties sharing some secret (original
//! value of the public key).
//!
//! NB: The library works with `secp256k1::PublicKey` and `secp256k1::SecretKey`
//! keys, not their wrapped bitcoin counterparts `bitcoin::PublickKey` and
//! `bitcoin::PrivateKey`.

use bitcoin::hashes::{sha256, Hmac};
use bitcoin::secp256k1;

use super::{Container, Error, Proof};
use crate::commit_verify::EmbedCommitVerify;
use crate::lnpbp1;

/// Container for LNPBP-1 commitments. In order to be constructed, commitment
/// requires an original public key and a protocol-specific tag, which
/// must be hashed during commitment process. Here we use pre-hashed version
/// of the tag in order to maximize performance for multiple commitments.
#[derive(Clone, PartialEq, Eq, Debug, Display, Hash)]
#[display(Debug)]
pub struct PubkeyContainer {
    /// The original public key: host for commitment
    pub pubkey: secp256k1::PublicKey,
    /// Single SHA256 hash of the protocol-specific tag
    pub tag: sha256::Hash,
    /// Tweaking factor stored after [`PubkeyContainer::commit_verify()`]
    /// procedure
    pub tweaking_factor: Option<Hmac<sha256::Hash>>,
}

impl Container for PubkeyContainer {
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
            tweaking_factor: None,
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
    PubkeyCommitment,
    secp256k1::PublicKey,
    doc = "Public key committed to some message via LNPBP1-based tweaking procedure",
    derive = [PartialEq, Eq, Hash]
);

impl<MSG> EmbedCommitVerify<MSG> for PubkeyCommitment
where
    MSG: AsRef<[u8]>,
{
    type Container = PubkeyContainer;
    type Error = lnpbp1::Error;

    // #[consensus_critical("RGB")]
    // #[standard_critical("LNPBP-1")]
    fn embed_commit(
        pubkey_container: &mut Self::Container,
        msg: &MSG,
    ) -> Result<Self, Self::Error> {
        let mut keyset = bset![pubkey_container.pubkey.clone()];
        let mut pubkey = pubkey_container.pubkey.clone();

        let tweaking_factor = lnpbp1::commit(
            &mut keyset,
            &mut pubkey,
            &pubkey_container.tag,
            msg,
        )?;

        pubkey_container.tweaking_factor = Some(tweaking_factor);

        // Returning tweaked public key
        Ok(PubkeyCommitment(pubkey))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::bp::test::*;
    use crate::commit_verify::test::*;
    use amplify::Wrapper;
    use bitcoin::hashes::{hex::ToHex, sha256, Hash};
    use bitcoin::secp256k1;
    use std::str::FromStr;

    #[test]
    fn test_pubkey_commitment() {
        let tag = sha256::Hash::hash(b"TEST_TAG");
        gen_secp_pubkeys(9).into_iter().for_each(|pubkey| {
            embed_commit_verify_suite::<Vec<u8>, PubkeyCommitment>(
                gen_messages(),
                &mut PubkeyContainer {
                    pubkey,
                    tag,
                    tweaking_factor: None,
                },
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
        let commitment = PubkeyCommitment::embed_commit(
            &mut PubkeyContainer {
                pubkey,
                tag,
                tweaking_factor: None,
            },
            &msg,
        )
        .unwrap();
        assert_eq!(
            commitment.as_inner().to_hex(),
            "0278565af0da38a7754d3d4551a09bf80cf98841dbec7330db53023af5503acf8d"
        );
    }
}

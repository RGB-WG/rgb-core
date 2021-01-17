// LNP/BP Rust Library
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

//! # LNPBP-2 related

use std::collections::BTreeSet;

use bitcoin::hashes::{sha256, Hmac};
use bitcoin::secp256k1;
use miniscript::Segwitv0;

use super::{Container, Error, Proof, ScriptEncodeData};
use crate::commit_verify::EmbedCommitVerify;
use crate::lnpbp1;

/// Container for LNPBP-1 commitments. In order to be constructed, commitment
/// requires an original public key and a protocol-specific tag, which
/// must be hashed during commitment process. Here we use pre-hashed version
/// of the tag in order to maximize performance for multiple commitments.
#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[display(Debug)]
pub struct KeysetContainer {
    /// The original public key: host for the commitment
    pub pubkey: secp256k1::PublicKey,
    /// Other keys that will participate the commitment procedure
    pub keyset: BTreeSet<secp256k1::PublicKey>,
    /// Single SHA256 hash of the protocol-specific tag
    pub tag: sha256::Hash,
    /// Tweaking factor stored after [KeysetContainer::commit_verify] procedure
    pub tweaking_factor: Option<Hmac<sha256::Hash>>,
}

impl Container for KeysetContainer {
    /// Out supplement is a protocol-specific tag in its hashed form
    type Supplement = sha256::Hash;

    /// Proof contains both original public key and all participating keys
    /// (inside it's script), so we don't need host here
    type Host = Option<()>;

    fn reconstruct(
        proof: &Proof,
        supplement: &Self::Supplement,
        _: &Self::Host,
    ) -> Result<Self, Error> {
        if let ScriptEncodeData::LockScript(ref script) = proof.source {
            Ok(Self {
                pubkey: proof.pubkey,
                keyset: script
                    .extract_pubkeyset::<Segwitv0>()?
                    .into_iter()
                    .map(|pk| pk.key)
                    .collect(),
                tag: supplement.clone(),
                tweaking_factor: None,
            })
        } else {
            Err(Error::InvalidProofStructure)
        }
    }

    #[inline]
    fn deconstruct(self) -> (Proof, Self::Supplement) {
        (Proof::from(self.pubkey), self.tag)
    }

    /// Important: this method should not be used. KeysetContainer does not
    /// support proof generation, use more advanced structures like LockScript
    /// container to generate the proof
    #[inline]
    fn to_proof(&self) -> Proof {
        panic!("KeysetContainer does not support proof generation")
    }

    /// Important: this method should not be used. KeysetContainer does not
    /// support proof generation, use more advanced structures like LockScript
    /// container to generate the proof
    #[inline]
    fn into_proof(self) -> Proof {
        panic!("KeysetContainer does not support proof generation")
    }
}

/// Public key committed to some message plus a sum of other public keys via
/// LNPBP2-based tweaking procedure
#[derive(Wrapper, Clone, Copy, PartialEq, Eq, Hash, Debug, Display, From)]
#[display("{0}", alt = "{_0:#}*")]
#[wrapper(FromStr, LowerHex)]
pub struct KeysetCommitment(secp256k1::PublicKey);

impl<MSG> EmbedCommitVerify<MSG> for KeysetCommitment
where
    MSG: AsRef<[u8]>,
{
    type Container = KeysetContainer;
    type Error = lnpbp1::Error;

    // #[consensus_critical("RGB")]
    // #[standard_critical("LNPBP-1")]
    fn embed_commit(
        keyset_container: &mut Self::Container,
        msg: &MSG,
    ) -> Result<Self, Self::Error> {
        let mut keyset = keyset_container.keyset.clone();
        let mut pubkey = keyset_container.pubkey.clone();
        keyset.insert(pubkey);

        let tweaking_factor = lnpbp1::commit(
            &mut keyset,
            &mut pubkey,
            &keyset_container.tag,
            msg,
        )?;

        keyset_container.tweaking_factor = Some(tweaking_factor);

        // Returning tweaked public key
        Ok(KeysetCommitment(pubkey))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::bp::dbc::pubkey::*;
    use crate::bp::test::*;
    use crate::commit_verify::test::*;
    use amplify::Wrapper;
    use bitcoin::hashes::{hex::ToHex, sha256, Hash};
    use bitcoin::secp256k1;
    use std::iter::FromIterator;
    use std::str::FromStr;

    #[test]
    fn test_lnpbp1_vs_lnpbp2() {
        let tag = sha256::Hash::hash(b"TEST_TAG2");
        let msg = "test message";
        gen_secp_pubkeys(9).into_iter().for_each(|pubkey| {
            let lnpbp1_commitment = PubkeyCommitment::embed_commit(
                &mut PubkeyContainer {
                    pubkey,
                    tag,
                    tweaking_factor: None,
                },
                &msg,
            )
            .unwrap();
            let lnpbp2_commitment = KeysetCommitment::embed_commit(
                &mut KeysetContainer {
                    pubkey,
                    keyset: BTreeSet::new(),
                    tag,
                    tweaking_factor: None,
                },
                &msg,
            )
            .unwrap();

            assert_eq!(
                lnpbp1_commitment.into_inner(),
                lnpbp2_commitment.into_inner()
            );
        });
    }

    #[test]
    fn test_keyset_commitment() {
        let tag = sha256::Hash::hash(b"TEST_TAG2");
        let pubkey = secp256k1::PublicKey::from_str(
            "0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166",
        )
        .unwrap();
        (1..9).into_iter().for_each(|n_keys| {
            embed_commit_verify_suite::<Vec<u8>, KeysetCommitment>(
                gen_messages(),
                &mut KeysetContainer {
                    pubkey,
                    keyset: BTreeSet::from_iter(gen_secp_pubkeys(n_keys)),
                    tag,
                    tweaking_factor: None,
                },
            );
        });
    }

    #[test]
    fn test_keyset_tweaking_results() {
        let tag = sha256::Hash::hash(b"TEST_TAG2");
        let msg = "test message";
        let pubkey = secp256k1::PublicKey::from_str(
            "0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166",
        )
        .unwrap();
        let keyset = BTreeSet::from_iter(vec![secp256k1::PublicKey::from_str(
            "03cfb81a7609a4d40914dfd41860f501209c30468d91834c8af1af34ce73f4f3fd",
        )
        .unwrap()]);

        let commitment = KeysetCommitment::embed_commit(
            &mut KeysetContainer {
                pubkey,
                keyset,
                tag,
                tweaking_factor: None,
            },
            &msg,
        )
        .unwrap();
        assert_eq!(
            commitment.as_inner().to_hex(),
            "02e47bb42c041f158ecfcf1099018f08650ef569a9a51bbb317e8787cdf3e06890"
        );
    }
}

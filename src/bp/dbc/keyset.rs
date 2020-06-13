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

use bitcoin::hashes::{sha256, Hash, HashEngine, Hmac, HmacEngine};
use bitcoin::secp256k1;
use std::collections::HashSet;

use super::{pubkey::SHA256_LNPBP1, Container, Error, Proof, ScriptInfo};
use crate::commit_verify::EmbedCommitVerify;
use crate::SECP256K1;

/// Container for LNPBP-1 commitments. In order to be constructed, commitment
/// requires an original public key and a protocol-specific tag, which
/// must be hashed during commitment process. Here we use pre-hashed version
/// of the tag in order to maximize performance for multiple commitments.
#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[display_from(Debug)]
pub struct KeysetContainer {
    /// The original public key: host for the commitment
    pub pubkey: secp256k1::PublicKey,
    /// Other keys that will participate the commitment procedure
    pub keyset: HashSet<secp256k1::PublicKey>,
    /// Single SHA256 hash of the protocol-specific tag
    pub tag: sha256::Hash,
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
        if let ScriptInfo::LockScript(ref script) = proof.script_info {
            Ok(Self {
                pubkey: proof.pubkey,
                keyset: script.extract_pubkeyset()?,
                tag: supplement.clone(),
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

wrapper!(
    LNPBP2Commitment,
    secp256k1::PublicKey,
    doc = "Public key committed to some message plus a sum of other public keys via LNPBP2-based tweaking procedure",
    derive = [PartialEq, Eq, Hash]
);

impl<MSG> EmbedCommitVerify<MSG> for LNPBP2Commitment
where
    MSG: AsRef<[u8]>,
{
    type Container = KeysetContainer;
    type Error = secp256k1::Error;

    /// Function implements commitment procedure on a set of public keys
    /// according to LNPBP-2.
    // #[consensus_critical]
    // #[standard_critical("LNPBP-1")]
    fn embed_commit(keyset_container: &Self::Container, msg: &MSG) -> Result<Self, Self::Error> {
        // ! [CONSENSUS-CRITICAL]:
        // ! [STANDARD-CRITICAL]: We commit to the sum of all public keys,
        //                        not a single pubkey
        let pubkey_sum = keyset_container
            .keyset
            .iter()
            .try_fold(keyset_container.pubkey, |sum, pubkey| sum.combine(pubkey))?;

        // ! [CONSENSUS-CRITICAL]:
        // ! [STANDARD-CRITICAL]: HMAC engine is based on sha256 hash
        let mut hmac_engine = HmacEngine::<sha256::Hash>::new(&pubkey_sum.serialize());

        // ! [CONSENSUS-CRITICAL]:
        // ! [STANDARD-CRITICAL]: Hash process started with consuming first
        //                        protocol prefix: single SHA256 hash of
        //                        ASCII "LNPBP-1" string.
        // NB: We use the same hash as in LNPBP-1 so when there is no other
        //     keys involved the commitment would not differ.
        hmac_engine.input(&SHA256_LNPBP1);

        // ! [CONSENSUS-CRITICAL]:
        // ! [STANDARD-CRITICAL]: The second prefix comes from the upstream
        //                        protocol as a part of the container
        hmac_engine.input(&keyset_container.tag[..]);

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
        let mut tweaked_pubkey = keyset_container.pubkey.clone();
        tweaked_pubkey.add_exp_assign(&SECP256K1, factor)?;

        // Returning tweaked public key
        Ok(LNPBP2Commitment(tweaked_pubkey))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::bp::dbc::pubkey::*;
    use crate::bp::test::*;
    use crate::commit_verify::test::*;
    use amplify::Wrapper;
    use bitcoin::hashes::{hex::ToHex, sha256};
    use bitcoin::secp256k1;
    use std::iter::FromIterator;
    use std::str::FromStr;

    #[test]
    fn test_lnpbp1_vs_lnpbp2() {
        let tag = sha256::Hash::hash(b"TEST_TAG2");
        let msg = "test message";
        gen_secp_pubkeys(9).into_iter().for_each(|pubkey| {
            let lnpbp1_commitment =
                LNPBP1Commitment::embed_commit(&LNPBP1Container { pubkey, tag }, &msg).unwrap();
            let lnpbp2_commitment = LNPBP2Commitment::embed_commit(
                &KeysetContainer {
                    pubkey,
                    keyset: HashSet::new(),
                    tag,
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
            embed_commit_verify_suite::<Vec<u8>, LNPBP2Commitment>(
                gen_messages(),
                &KeysetContainer {
                    pubkey,
                    keyset: HashSet::from_iter(gen_secp_pubkeys(n_keys)),
                    tag,
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
        let keyset = HashSet::from_iter(vec![secp256k1::PublicKey::from_str(
            "03cfb81a7609a4d40914dfd41860f501209c30468d91834c8af1af34ce73f4f3fd",
        )
        .unwrap()]);

        let commitment = LNPBP2Commitment::embed_commit(
            &KeysetContainer {
                pubkey,
                keyset,
                tag,
            },
            &msg,
        )
        .unwrap();
        assert_eq!(
            commitment.as_inner().to_hex(),
            "02021ef8e5ba59c3c9ec6d9fad0d8fbfffffe0d21f86a2ac329b458b6ea87d2399"
        );
    }
}

// LNP/BP Core Library implementing LNPBP specifications & standards
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

use bitcoin::hashes::sha256;
use bitcoin::secp256k1;

use crate::bp::dbc::{self, Container, LNPBP1Commitment, LNPBP1Container, Proof};
use crate::commit_verify::EmbedCommitVerify;

/// Auxillary structure that can be used for keeping LNPBP-1 commitment-related
/// information
#[derive(Clone, PartialEq, Eq, Debug, Display, Hash)]
#[display_from(Debug)]
pub struct Commitment {
    /// The original public key; it is a proof of the commitment (without
    /// it is impossible to verify the commitment)
    pub original_pubkey: secp256k1::PublicKey,

    /// The commitment itself
    pub tweaked_pubkey: secp256k1::PublicKey,

    /// Used protocol-specific tag
    pub protocol_tag: sha256::Hash,
}

/// Convenience LNPBP-1 commitment function
pub fn lnpbp1_commit(
    pubkey: &secp256k1::PublicKey,
    protocol_tag: &sha256::Hash,
    message: &[u8],
) -> Result<Commitment, secp256k1::Error> {
    let commitment = LNPBP1Commitment::embed_commit(
        &LNPBP1Container {
            pubkey: pubkey.clone(),
            tag: protocol_tag.clone(),
        },
        &message,
    )?;
    Ok(Commitment {
        original_pubkey: pubkey.clone(),
        tweaked_pubkey: *commitment.clone(),
        protocol_tag: protocol_tag.clone(),
    })
}

/// Convenience LNPBP-1 verification function
pub fn lnpbp1_verify(
    commitment: secp256k1::PublicKey,
    proof: secp256k1::PublicKey,
    protocol_tag: sha256::Hash,
    message: &[u8],
) -> Result<bool, dbc::Error> {
    Ok(LNPBP1Commitment::from_inner(commitment).verify(
        &LNPBP1Container::reconstruct(&Proof::from(proof), &protocol_tag, &None)?,
        &message,
    )?)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::bp::test::*;
    use crate::commit_verify::test::*;
    use bitcoin::hashes::{hex::ToHex, Hash};
    use bitcoin::secp256k1;
    use std::str::FromStr;

    #[test]
    // Test according to LNPBP-1 standard
    fn test_lnpbp1_commitment() {
        let tag = sha256::Hash::hash(b"TEST_TAG");

        gen_messages().iter().for_each(|msg| {
            // Isolated commitment resulting in one single proof value
            let (proof, commitment) = {
                let mut prefixed_msg = tag.to_vec();
                prefixed_msg.extend(msg);
                let msgs = vec![prefixed_msg];

                let pubkey = gen_secp_pubkeys(1).first().unwrap().clone();
                let commitment = lnpbp1_commit(&pubkey, &tag, msg).unwrap();
                (commitment.original_pubkey, commitment.tweaked_pubkey)
            };

            // Here we save only proof

            // Later
            assert_eq!(lnpbp1_verify(commitment, proof, tag, msg), Ok(true));
        });
    }

    #[test]
    fn test_lnpbp1_results() {
        let tag = sha256::Hash::hash(b"TEST_TAG");
        let msg = b"test message";
        let pubkey = secp256k1::PublicKey::from_str(
            "0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166",
        )
        .unwrap();
        let commitment = lnpbp1_commit(&pubkey, &tag, &msg[..]).unwrap();
        assert_eq!(
            commitment.tweaked_pubkey.to_hex(),
            "0278565af0da38a7754d3d4551a09bf80cf98841dbec7330db53023af5503acf8d"
        );
    }
}

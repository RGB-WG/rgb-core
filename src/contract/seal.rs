// RGB Core Library: a reference implementation of RGB smart contract standards.
// Written in 2019-2022 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the MIT License along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

//! Single-use-seal API specific for RGB implementation
//!
//! Based on LNP/BP client-side-validation single-use-seals API (see
//! [`lnpbp::seals`]). RGB single-use-seal implementation differs in the fact
//! that seals are organized into a graph; thus a seal may be defined as
//! pointing witness transaction closing some other seal, which is meaningless
//! with LNP/BP seals.
//!
//! Single-use-seals in RGB are used for holding assigned state, i.e. *state* +
//! *seal definition* = *assignment*. Closing of the single-use-seal invalidates
//! the assigned state.
//!
//! Single-use-seals in RGB can have multiple forms because of the
//! confidentiality options and ability to be linked to the witness transaction
//! closing previous seal in RGB state evolution graph.
//!
//! | **Type name**      | **Lib** | **Witness vout** | **Blinding**    | **Confidential** | **String serialization**              | **Use case**                      |
//! | ------------------ | ------- | ----------- | -------------------- | ---------------- | ------------------------------------- | --------------------------------- |
//! | [`Outpoint`]       | Bitcoin | No          | No                   | No               | `<txid>:<vout>`                       | Genesis control rights            |
//! | [`RevealedSeal`]   | BP Core | No          | Yes                  | No               | `<method>:<txid>|~:<vout>#<blinding>` | Stash                             |
//! | [`ConcealedSeal`]  | BP Core | Implicit?   | Implicit             | Yes              | `txob1...`                            | External payments                 |
//! | [`ExplicitSeal`]   | BP Core | Yes         | Yes                  | No               | `<method>:<txid>|~:<vout>`              | Internal                          |
//! | [`SealEndpoint`]   | RGB     | Yes         | Explicit or implicit | Could be         | `txob1...|<method>:~:<vout>#blinding` | Consignments                      |

use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use bp::seals::txout::blind::{ConcealedSeal, ParseError, RevealedSeal};
pub use bp::seals::txout::blind::{ConcealedSeal as Confidential, RevealedSeal as Revealed};
use bp::seals::txout::CloseMethod;
use commit_verify::CommitConceal;
use secp256k1_zkp::rand::RngCore;

/// Trait for types supporting conversion to a [`RevealedSeal`]
pub trait IntoRevealedSeal {
    /// Converts seal into [`RevealedSeal`] type.
    fn into_revealed_seal(self) -> RevealedSeal;
}

/// Seal endpoint is a confidential seal which may be linked to the witness
/// transaction, but does not contain information about its id.
///
/// Seal endpoint can be either a pointer to the output in the witness
/// transaction, plus blinding factor value, or a confidential seal
/// [`ConcealedSeal`] value pointing some external unknown transaction
/// output
///
/// Seal endpoint is required in situations where sender assigns state to the
/// witness transaction output on behalf of receiver
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, From)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "snake_case")
)]
pub enum SealEndpoint {
    /// External transaction output in concealed form (see
    /// [`seal::Confidential`])
    #[from]
    ConcealedUtxo(ConcealedSeal),

    /// Seal contained within the witness transaction
    WitnessVout {
        method: CloseMethod,
        vout: u32,
        blinding: u64,
    },
}

impl From<RevealedSeal> for SealEndpoint {
    fn from(seal: RevealedSeal) -> Self {
        match seal.txid {
            None => SealEndpoint::WitnessVout {
                method: seal.method,
                vout: seal.vout,
                blinding: seal.blinding,
            },
            Some(_) => SealEndpoint::ConcealedUtxo(seal.commit_conceal()),
        }
    }
}

impl SealEndpoint {
    /// Constructs [`SealEndpoint`] for the witness transaction output using
    /// provided random number generator for creating blinding factor
    pub fn with(method: CloseMethod, vout: u32, rng: &mut impl RngCore) -> SealEndpoint {
        SealEndpoint::WitnessVout {
            method,
            vout,
            blinding: rng.next_u64(),
        }
    }
}

impl CommitConceal for SealEndpoint {
    type ConcealedCommitment = Confidential;

    fn commit_conceal(&self) -> Self::ConcealedCommitment {
        match *self {
            SealEndpoint::ConcealedUtxo(hash) => hash,
            SealEndpoint::WitnessVout {
                method,
                vout,
                blinding,
            } => RevealedSeal {
                method,
                txid: None,
                vout,
                blinding,
            }
            .commit_conceal(),
        }
    }
}

impl Display for SealEndpoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            SealEndpoint::ConcealedUtxo(seal) => Display::fmt(seal, f),
            SealEndpoint::WitnessVout {
                method,
                vout,
                blinding,
            } => {
                write!(f, "{}:~:{}#{}", method, vout, blinding)
            }
        }
    }
}

impl FromStr for SealEndpoint {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ConcealedSeal::from_str(s)
            .map(SealEndpoint::from)
            .or_else(|_| RevealedSeal::from_str(s).map(SealEndpoint::from))
    }
}

#[cfg(test)]
mod test {
    use std::convert::TryFrom;

    use bc::{Outpoint, Txid};
    use bitcoin_hashes::hex::FromHex;
    use bp::seals::txout::TxoSeal;
    use commit_verify::CommitEncode;
    use secp256k1_zkp::rand::{thread_rng, RngCore};
    use strict_encoding::{StrictDecode, StrictEncode};
    use strict_encoding_test::test_vec_decoding_roundtrip;

    use super::*;

    // Hard coded TxOutpoint variant of a Revealed Seal
    // Constructed with following data
    // txid = 201fdd1e2b62d7b6938271295118ee181f1bac5e57d9f4528925650d36d3af8e
    // blinding = 13457965799463774082
    // vout = 6
    static REVEALED_TXOUTPOINT: [u8; 45] = [
        0x0, 0x82, 0xe7, 0x64, 0x5c, 0x97, 0x4c, 0xc4, 0xba, 0x8e, 0xaf, 0xd3, 0x36, 0xd, 0x65,
        0x25, 0x89, 0x52, 0xf4, 0xd9, 0x57, 0x5e, 0xac, 0x1b, 0x1f, 0x18, 0xee, 0x18, 0x51, 0x29,
        0x71, 0x82, 0x93, 0xb6, 0xd7, 0x62, 0x2b, 0x1e, 0xdd, 0x1f, 0x20, 0x6, 0x0, 0x0, 0x0,
    ];

    // Hard coded concealed seal of the above TxOutpoint variant
    static CONCEALED_TXOUTPOINT: [u8; 32] = [
        0x43, 0xea, 0xe3, 0x29, 0x3d, 0x22, 0xcb, 0x33, 0x37, 0x53, 0x78, 0x74, 0x8, 0xe, 0xed,
        0x5d, 0x7c, 0xff, 0xde, 0x4c, 0xee, 0x6e, 0x44, 0xc5, 0x62, 0x7d, 0x73, 0x19, 0x61, 0x6e,
        0x4, 0x87,
    ];

    // Hard coded WitnessVout variant of a Revealed Seal
    // Constructred with following data
    // vout = 6
    // blinding = 13457965799463774082
    static REVEALED_WITNESSVOUT: [u8; 13] =
        [0x1, 0x6, 0x0, 0x0, 0x0, 0x82, 0xe7, 0x64, 0x5c, 0x97, 0x4c, 0xc4, 0xba];

    // Hard coded concealed seal of the above WitnessVout variant
    static CONCEALED_WITNESSVOUT: [u8; 32] = [
        0x3e, 0x90, 0x1d, 0x9d, 0xef, 0xb4, 0xbb, 0x11, 0x8d, 0x69, 0x23, 0x9c, 0xe, 0x41, 0xb9,
        0x80, 0xd, 0x29, 0xdc, 0x5a, 0x7d, 0x2b, 0xa9, 0xe2, 0x39, 0xc8, 0x83, 0x90, 0x6, 0x93,
        0x74, 0xca,
    ];

    // Hard coded outpoint of the above seals
    static OUTPOINT: [u8; 36] = [
        0x8e, 0xaf, 0xd3, 0x36, 0xd, 0x65, 0x25, 0x89, 0x52, 0xf4, 0xd9, 0x57, 0x5e, 0xac, 0x1b,
        0x1f, 0x18, 0xee, 0x18, 0x51, 0x29, 0x71, 0x82, 0x93, 0xb6, 0xd7, 0x62, 0x2b, 0x1e, 0xdd,
        0x1f, 0x20, 0x6, 0x0, 0x0, 0x0,
    ];

    #[test]
    #[ignore]
    fn test_encode_decode() {
        let _: Revealed = test_vec_decoding_roundtrip(REVEALED_TXOUTPOINT).unwrap();
        let _: Revealed = test_vec_decoding_roundtrip(REVEALED_WITNESSVOUT).unwrap();
    }

    /*
    #[test]
    #[ignore]
    fn test_wrong_encoding() {
        let err = "Revealed";
        test_garbage_exhaustive!(
            2..255;
            (REVEALED_TXOUTPOINT, Revealed, err),
            (REVEALED_WITNESSVOUT, Revealed, err)
        );
    }
     */

    #[test]
    #[ignore]
    fn test_concealed() {
        let revelaed = Revealed::strict_decode(&REVEALED_TXOUTPOINT[..]).unwrap();

        let concealed = revelaed.commit_conceal();

        // Strict encoding of Confidential data
        let mut confidential_encoded = vec![];
        concealed.strict_encode(&mut confidential_encoded).unwrap();

        assert_eq!(CONCEALED_TXOUTPOINT.to_vec(), confidential_encoded);
    }

    #[test]
    #[ignore]
    fn test_witness_conf() {
        let revelaed = Revealed::strict_decode(&REVEALED_WITNESSVOUT[..]).unwrap();

        let concealed = revelaed.commit_conceal();

        // Strict encoding Confidential data
        let mut confidential_encoded = vec![];
        concealed.strict_encode(&mut confidential_encoded).unwrap();

        assert_eq!(CONCEALED_WITNESSVOUT.to_vec(), confidential_encoded);
    }

    #[test]
    #[ignore]
    fn test_into_outpoint() {
        let revealed = Revealed::strict_decode(&REVEALED_TXOUTPOINT[..]).unwrap();

        let outpoint = Outpoint::try_from(revealed.clone()).unwrap();

        let coded = Outpoint::strict_decode(&OUTPOINT[..]).unwrap();

        assert_eq!(coded, outpoint);
    }

    #[test]
    #[ignore]
    #[should_panic(expected = "WitnessVoutError")]
    fn test_witness_to_outpoint() {
        // Conversion to Outpoint from WitnessVout variant should panic
        let revealed = Revealed::strict_decode(&REVEALED_WITNESSVOUT[..]).unwrap();
        bc::Outpoint::try_from(revealed).unwrap();
    }

    #[test]
    #[ignore]
    fn test_outpoint_reveal() {
        let revealed_txoutpoint = Revealed::strict_decode(&REVEALED_TXOUTPOINT[..]).unwrap();
        let revealed_witnessvout = Revealed::strict_decode(&REVEALED_WITNESSVOUT[..]).unwrap();

        // Data used for constructing above seals
        let txid =
            Txid::from_hex("201fdd1e2b62d7b6938271295118ee181f1bac5e57d9f4528925650d36d3af8e")
                .unwrap();

        let blinding: u64 = 13457965799463774082;

        let vout: u32 = 6;

        // This should produce two exact same Revealed Outpoint
        let outpoint_from_txoutpoint = revealed_txoutpoint.outpoint_or(txid);
        let outpoint_from_witnessvout = revealed_witnessvout.outpoint_or(txid);

        // Check integrity
        assert_eq!(outpoint_from_txoutpoint, outpoint_from_witnessvout);
        assert_eq!(revealed_txoutpoint.blinding, blinding);
        assert_eq!(outpoint_from_witnessvout.txid, txid);
        assert_eq!(outpoint_from_txoutpoint.vout, vout);
    }

    #[test]
    #[ignore]
    fn test_commitencode_seal() {
        let revealed_txoutpoint = Revealed::strict_decode(&REVEALED_TXOUTPOINT[..]).unwrap();
        let revelaed_wtinessvout = Revealed::strict_decode(&REVEALED_WITNESSVOUT[..]).unwrap();

        let mut commit1 = vec![];
        revealed_txoutpoint.commit_encode(&mut commit1);
        assert_eq!(commit1, CONCEALED_TXOUTPOINT);

        let mut commit2 = vec![];
        revelaed_wtinessvout.commit_encode(&mut commit2);
        assert_eq!(commit2, CONCEALED_WITNESSVOUT);
    }

    #[test]
    fn test_commitencoding_seals() {
        let mut rng = thread_rng();
        let txid = bitcoin::Txid::from_hex(
            "201fdd1e2b62d7b6938271295118ee181f1bac5e57d9f4528925650d36d3af8e",
        )
        .unwrap();
        let vout = rng.next_u32();
        let revealed_txout = Revealed::from(Outpoint::new(txid, vout));

        let revealed_witness = Revealed {
            method: CloseMethod::TapretFirst,
            txid: None,
            vout,
            blinding: rng.next_u64(),
        };

        let mut txout_orig = vec![];
        revealed_txout.clone().commit_encode(&mut txout_orig);

        let mut witness_orig = vec![];
        revealed_witness.clone().commit_encode(&mut witness_orig);

        let mut txout_new = vec![];
        revealed_txout
            .commit_conceal()
            .strict_encode(&mut txout_new)
            .unwrap();

        let mut witness_new = vec![];
        revealed_witness
            .commit_conceal()
            .strict_encode(&mut witness_new)
            .unwrap();

        assert_eq!(txout_orig, txout_new);
        assert_eq!(witness_orig, witness_new);
    }
}

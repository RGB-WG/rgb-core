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

use bitcoin::{OutPoint, Txid};
use core::convert::TryFrom;

use lnpbp::bp::blind::{OutpointHash, OutpointReveal};
use lnpbp::client_side_validation::{
    commit_strategy, CommitEncodeWithStrategy, Conceal,
};

pub type Confidential = OutpointHash;

/// Convenience type name useful for defining new seals
pub type SealDefinition = Revealed;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Display)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "snake_case")
)]
#[display(Debug)]
pub enum Revealed {
    /// Seal that is revealed
    TxOutpoint(OutpointReveal),
    /// Seal contained within the witness transaction
    WitnessVout { vout: u32, blinding: u64 },
}

impl Revealed {
    pub fn outpoint_reveal(&self, txid: Txid) -> OutpointReveal {
        match self.clone() {
            Revealed::TxOutpoint(op) => op,
            Revealed::WitnessVout { vout, blinding } => OutpointReveal {
                blinding,
                txid,
                vout,
            },
        }
    }
}

impl Conceal for Revealed {
    type Confidential = Confidential;

    fn conceal(&self) -> Confidential {
        match self.clone() {
            Revealed::TxOutpoint(outpoint) => outpoint.conceal(),
            Revealed::WitnessVout { vout, blinding } => OutpointReveal {
                blinding,
                txid: Txid::default(),
                vout,
            }
            .conceal(),
        }
    }
}

impl CommitEncodeWithStrategy for Revealed {
    type Strategy = commit_strategy::UsingConceal;
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Display, Error)]
#[display(Debug)]
pub struct WitnessVoutError;

impl TryFrom<Revealed> for OutPoint {
    type Error = WitnessVoutError;

    fn try_from(value: Revealed) -> Result<Self, Self::Error> {
        match value {
            Revealed::TxOutpoint(reveal) => Ok(reveal.into()),
            Revealed::WitnessVout { .. } => Err(WitnessVoutError),
        }
    }
}

mod strict_encoding {
    use super::*;
    use lnpbp::strict_encoding::{Error, StrictDecode, StrictEncode};
    use std::io;

    impl StrictEncode for Revealed {
        fn strict_encode<E: io::Write>(
            &self,
            mut e: E,
        ) -> Result<usize, Error> {
            Ok(match self {
                Revealed::TxOutpoint(outpoint) => {
                    strict_encode_list!(e; 0u8, outpoint)
                }
                Revealed::WitnessVout { vout, blinding } => {
                    strict_encode_list!(e; 1u8, vout, blinding)
                }
            })
        }
    }

    impl StrictDecode for Revealed {
        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
            let format = u8::strict_decode(&mut d)?;
            Ok(match format {
                0u8 => Revealed::TxOutpoint(OutpointReveal::strict_decode(d)?),
                1u8 => Revealed::WitnessVout {
                    vout: u32::strict_decode(&mut d)?,
                    blinding: u64::strict_decode(&mut d)?,
                },
                invalid => Err(Error::EnumValueNotKnown(
                    "seal::Revealed".to_string(),
                    invalid,
                ))?,
            })
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bitcoin::hashes::hex::FromHex;
    use lnpbp::client_side_validation::CommitEncode;
    use lnpbp::secp256k1zkp::rand::{thread_rng, RngCore};
    use lnpbp::strict_encoding::{StrictDecode, StrictEncode};
    use lnpbp::test_helpers::*;

    // Hard coded TxOutpoint variant of a Revealed Seal
    // Constructed with following data
    // txid = 201fdd1e2b62d7b6938271295118ee181f1bac5e57d9f4528925650d36d3af8e
    // blinding = 13457965799463774082
    // vout = 6
    static REVEALED_TXOUTPOINT: [u8; 45] = [
        0x0, 0x82, 0xe7, 0x64, 0x5c, 0x97, 0x4c, 0xc4, 0xba, 0x8e, 0xaf, 0xd3,
        0x36, 0xd, 0x65, 0x25, 0x89, 0x52, 0xf4, 0xd9, 0x57, 0x5e, 0xac, 0x1b,
        0x1f, 0x18, 0xee, 0x18, 0x51, 0x29, 0x71, 0x82, 0x93, 0xb6, 0xd7, 0x62,
        0x2b, 0x1e, 0xdd, 0x1f, 0x20, 0x6, 0x0, 0x0, 0x0,
    ];

    // Hard coded concealed seal of the above TxOutpoint variant
    static CONCEALED_TXOUTPOINT: [u8; 32] = [
        0x43, 0xea, 0xe3, 0x29, 0x3d, 0x22, 0xcb, 0x33, 0x37, 0x53, 0x78, 0x74,
        0x8, 0xe, 0xed, 0x5d, 0x7c, 0xff, 0xde, 0x4c, 0xee, 0x6e, 0x44, 0xc5,
        0x62, 0x7d, 0x73, 0x19, 0x61, 0x6e, 0x4, 0x87,
    ];

    // Hard coded WitnessVout variant of a Revealed Seal
    // Constructred with following data
    // vout = 6
    // blinding = 13457965799463774082
    static REVEALED_WITNESSVOUT: [u8; 13] = [
        0x1, 0x6, 0x0, 0x0, 0x0, 0x82, 0xe7, 0x64, 0x5c, 0x97, 0x4c, 0xc4, 0xba,
    ];

    // Hard coded concealed seal of the above WitnessVout variant
    static CONCEALED_WITNESSVOUT: [u8; 32] = [
        0x3e, 0x90, 0x1d, 0x9d, 0xef, 0xb4, 0xbb, 0x11, 0x8d, 0x69, 0x23, 0x9c,
        0xe, 0x41, 0xb9, 0x80, 0xd, 0x29, 0xdc, 0x5a, 0x7d, 0x2b, 0xa9, 0xe2,
        0x39, 0xc8, 0x83, 0x90, 0x6, 0x93, 0x74, 0xca,
    ];

    // Hard coded outpoint of the above seals
    static OUTPOINT: [u8; 36] = [
        0x8e, 0xaf, 0xd3, 0x36, 0xd, 0x65, 0x25, 0x89, 0x52, 0xf4, 0xd9, 0x57,
        0x5e, 0xac, 0x1b, 0x1f, 0x18, 0xee, 0x18, 0x51, 0x29, 0x71, 0x82, 0x93,
        0xb6, 0xd7, 0x62, 0x2b, 0x1e, 0xdd, 0x1f, 0x20, 0x6, 0x0, 0x0, 0x0,
    ];

    #[test]
    fn test_encode_decode() {
        test_encode!((REVEALED_TXOUTPOINT, Revealed));
        test_encode!((REVEALED_WITNESSVOUT, Revealed));
    }

    #[test]
    fn test_wrong_encoding() {
        let err = "seal::Revealed";
        test_garbage_exhaustive!(2..255; (REVEALED_TXOUTPOINT, Revealed, err), 
            (REVEALED_WITNESSVOUT, Revealed, err));
    }

    #[test]
    fn test_concealed() {
        let revelaed =
            Revealed::strict_decode(&REVEALED_TXOUTPOINT[..]).unwrap();

        let concealed = revelaed.conceal();

        // Strict encoding of Confidential data
        let mut confidential_encoded = vec![];
        concealed.strict_encode(&mut confidential_encoded).unwrap();

        assert_eq!(CONCEALED_TXOUTPOINT.to_vec(), confidential_encoded);
    }

    #[test]
    fn test_witness_conf() {
        let revelaed =
            Revealed::strict_decode(&REVEALED_WITNESSVOUT[..]).unwrap();

        let concealed = revelaed.conceal();

        // Strict encoding Confidential data
        let mut confidential_encoded = vec![];
        concealed.strict_encode(&mut confidential_encoded).unwrap();

        assert_eq!(CONCEALED_WITNESSVOUT.to_vec(), confidential_encoded);
    }

    #[test]
    fn test_into_outpoint() {
        let revealed =
            Revealed::strict_decode(&REVEALED_TXOUTPOINT[..]).unwrap();

        let outpoint = bitcoin::OutPoint::try_from(revealed.clone()).unwrap();

        let coded = bitcoin::OutPoint::strict_decode(&OUTPOINT[..]).unwrap();

        assert_eq!(coded, outpoint);
    }

    #[test]
    #[should_panic(expected = "WitnessVoutError")]
    fn test_witness_to_outpoint() {
        // Conversion to Outpoint from WitnessVout variant should panic
        let revealed =
            Revealed::strict_decode(&REVEALED_WITNESSVOUT[..]).unwrap();
        bitcoin::OutPoint::try_from(revealed).unwrap();
    }

    #[test]
    fn test_outpoint_reveal() {
        let revealed_txoutpoint =
            Revealed::strict_decode(&REVEALED_TXOUTPOINT[..]).unwrap();
        let revelaed_wtinessvout =
            Revealed::strict_decode(&REVEALED_WITNESSVOUT[..]).unwrap();

        // Data used for constructing above seals
        let txid = bitcoin::Txid::from_hex(
            "201fdd1e2b62d7b6938271295118ee181f1bac5e57d9f4528925650d36d3af8e",
        )
        .unwrap();

        let blinding: u64 = 13457965799463774082;

        let vout: u32 = 6;

        // This should produce two exact same Revealed Outpoint
        let outpoint_from_txoutpoint =
            revealed_txoutpoint.outpoint_reveal(txid);
        let outpoint_from_witnessvout =
            revelaed_wtinessvout.outpoint_reveal(txid);

        // Check integrity
        assert_eq!(outpoint_from_txoutpoint, outpoint_from_witnessvout);
        assert_eq!(outpoint_from_txoutpoint.blinding, blinding);
        assert_eq!(outpoint_from_witnessvout.txid, txid);
        assert_eq!(outpoint_from_txoutpoint.vout, vout);
    }

    #[test]
    fn test_commitencode_seal() {
        let revealed_txoutpoint =
            Revealed::strict_decode(&REVEALED_TXOUTPOINT[..]).unwrap();
        let revelaed_wtinessvout =
            Revealed::strict_decode(&REVEALED_WITNESSVOUT[..]).unwrap();

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
        let revealed_txout = Revealed::TxOutpoint(OutpointReveal::from(
            OutPoint::new(txid, vout),
        ));

        let revealed_witness = Revealed::WitnessVout {
            vout: vout,
            blinding: rng.next_u64(),
        };

        let mut txout_orig = vec![];
        revealed_txout.clone().commit_encode(&mut txout_orig);

        let mut witness_orig = vec![];
        revealed_witness.clone().commit_encode(&mut witness_orig);

        let mut txout_new = vec![];
        revealed_txout
            .conceal()
            .strict_encode(&mut txout_new)
            .unwrap();

        let mut witness_new = vec![];
        revealed_witness
            .conceal()
            .strict_encode(&mut witness_new)
            .unwrap();

        assert_eq!(txout_orig, txout_new);
        assert_eq!(witness_orig, witness_new);
    }
}

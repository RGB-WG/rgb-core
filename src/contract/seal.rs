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

//! Single-use-seal API specific for RGB implementation
//!
//! Based on LNP/BP client-side-validation single-use-seals API (see
//! [`lnpbp::seals`])
//!
//! Single-use-seals in RGB are used for holding assigned state, i.e. *state* +
//! *seal definition* = *assignment*. Closing of the single-use-seal invalidates
//! the assigned state.
//!
//! Single-use-seals in RGB can have multiple forms because of the
//! confidentiality options and ability to be linked to the witness transaction
//! closing previous seal in RGB state evolution graph.

use core::convert::TryFrom;

use bitcoin::secp256k1::rand::RngCore;
use bitcoin::{OutPoint, Txid};
use lnpbp::client_side_validation::{
    commit_strategy, CommitConceal, CommitEncodeWithStrategy,
};
use lnpbp::seals::{OutpointHash, OutpointReveal};

/// Market trait for different forms of seal definitions
pub trait Seal {}

impl Seal for OutPoint {}

/// Confidential seal data, equivalent to the [`OutpointHash`] type provided by
/// the LNP/BP client-side-validation library
pub type Confidential = OutpointHash;

impl Seal for Confidential {}

/// Convenience type name useful for defining new seals
pub type SealDefinition = Revealed;

/// Trait for types supporting conversion to a [`SealDefinition`]
pub trait ToSealDefinition {
    /// Constructs [`SealDefinition`] from the inner type data
    fn to_seal_definition(&self) -> SealDefinition;
}

/// Seal endpoint is a confidential seal which may be linked to the witness
/// transaction, but does not contain information about its id.
///
/// Seal endpoing can be either a pointer to the output in the witness
/// transaction, plus blinding factor value, or a confidential seal
/// [`seal::Confidential`] value pointing some external uknown transaction
/// output
///
/// Seal endpoint is required in situations where sender assigns state to the
/// witness transaction output on behalf of receiver
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Display,
    From,
    StrictEncode,
    StrictDecode,
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "snake_case")
)]
#[display(Debug)]
pub enum SealEndpoint {
    /// External transaction output in concealed form (see
    /// [`seal::Confidential`])
    #[from]
    TxOutpoint(OutpointHash),

    /// Seal contained within the witness transaction
    WitnessVout { vout: u32, blinding: u64 },
}

impl Seal for SealEndpoint {}

impl SealEndpoint {
    /// Cnostructs [`SealEndpoint`] for the witness transaction output using
    /// provided random number generator for creating blinding factor
    pub fn with_vout(vout: u32, rng: &mut impl RngCore) -> SealEndpoint {
        SealEndpoint::WitnessVout {
            vout,
            blinding: rng.next_u64(),
        }
    }
}

impl CommitConceal for SealEndpoint {
    type ConcealedCommitment = Confidential;

    fn commit_conceal(&self) -> Self::ConcealedCommitment {
        match *self {
            SealEndpoint::TxOutpoint(hash) => hash,
            SealEndpoint::WitnessVout { vout, blinding } => {
                SealDefinition::WitnessVout { vout, blinding }.commit_conceal()
            }
        }
    }
}

impl From<SealDefinition> for SealEndpoint {
    fn from(seal_definition: SealDefinition) -> Self {
        match seal_definition {
            Revealed::TxOutpoint(outpoint) => {
                SealEndpoint::TxOutpoint(outpoint.commit_conceal())
            }
            Revealed::WitnessVout { vout, blinding } => {
                SealEndpoint::WitnessVout { vout, blinding }
            }
        }
    }
}

/// Revealed seal data, i.e. seal definition containing explicit information
/// about the bitcoin transaction output
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Display,
    From,
    StrictEncode,
    StrictDecode,
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "snake_case")
)]
#[display(Debug)]
pub enum Revealed {
    /// Seal defined by external transaction output with additional blinding
    /// factor used in deterministic concealment and commitments
    #[from]
    TxOutpoint(OutpointReveal),

    /// Seal contained within the witness transaction
    WitnessVout { vout: u32, blinding: u64 },
}

impl Seal for Revealed {}

impl Revealed {
    /// Constructs seal corresponding to the output of the witness transaction
    /// using the provided random number generator for creating blinding factor
    /// value
    pub fn with_vout(vout: u32, rng: &mut impl RngCore) -> Revealed {
        Revealed::WitnessVout {
            vout,
            blinding: rng.next_u64(),
        }
    }

    /// Constructs [`lnpbp::seal::OutpointReveal`] from the revealed seal data.
    ///
    /// Unlike [`rgb::seal::Revealed`], the revealed outpoint of the LNP/BP
    /// client-side-validation library contains full txid of the witness
    /// transaction variant
    pub fn to_outpoint_reveal(&self, txid: Txid) -> OutpointReveal {
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

impl CommitConceal for Revealed {
    type ConcealedCommitment = Confidential;

    fn commit_conceal(&self) -> Self::ConcealedCommitment {
        match self.clone() {
            Revealed::TxOutpoint(outpoint) => outpoint.commit_conceal(),
            Revealed::WitnessVout { vout, blinding } => OutpointReveal {
                blinding,
                txid: Txid::default(),
                vout,
            }
            .commit_conceal(),
        }
    }
}

impl CommitEncodeWithStrategy for Revealed {
    type Strategy = commit_strategy::UsingConceal;
}

/// Error happening if the seal data holds an pointer to the witness
/// transaction output and thus can't be used alone for constructing full
/// bitcoin transaction ouput data which must include the witness transaction id
/// (unknown to the seal).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Display, Error)]
#[display("witness txid is unknown; unable to reconstruct full outpoint data")]
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

#[cfg(test)]
mod test {
    use super::*;
    use bitcoin::hashes::hex::FromHex;
    use lnpbp::client_side_validation::CommitEncode;
    use lnpbp::strict_encoding::{StrictDecode, StrictEncode};
    use secp256k1zkp::rand::{thread_rng, RngCore};

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
        let err = "Revealed";
        test_garbage_exhaustive!(
            2..255;
            (REVEALED_TXOUTPOINT, Revealed, err),
            (REVEALED_WITNESSVOUT, Revealed, err)
        );
    }

    #[test]
    fn test_concealed() {
        let revelaed =
            Revealed::strict_decode(&REVEALED_TXOUTPOINT[..]).unwrap();

        let concealed = revelaed.commit_conceal();

        // Strict encoding of Confidential data
        let mut confidential_encoded = vec![];
        concealed.strict_encode(&mut confidential_encoded).unwrap();

        assert_eq!(CONCEALED_TXOUTPOINT.to_vec(), confidential_encoded);
    }

    #[test]
    fn test_witness_conf() {
        let revelaed =
            Revealed::strict_decode(&REVEALED_WITNESSVOUT[..]).unwrap();

        let concealed = revelaed.commit_conceal();

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
            revealed_txoutpoint.to_outpoint_reveal(txid);
        let outpoint_from_witnessvout =
            revelaed_wtinessvout.to_outpoint_reveal(txid);

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

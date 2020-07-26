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

use crate::bp::blind::{OutpointHash, OutpointReveal};
use crate::client_side_validation::{commit_strategy, CommitEncodeWithStrategy, Conceal};

use bitcoin::{OutPoint, Txid};
use core::convert::TryFrom;

pub type Confidential = OutpointHash;

/// Convenience type name useful for defining new seals
pub type SealDefinition = Revealed;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Display)]
#[display_from(Debug)]
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
#[display_from(Debug)]
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
    use crate::strict_encoding::{Error, StrictDecode, StrictEncode};
    use std::io;

    impl StrictEncode for Revealed {
        type Error = Error;

        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
            Ok(match self {
                Revealed::TxOutpoint(outpoint) => strict_encode_list!(e; 0u8, outpoint),
                Revealed::WitnessVout { vout, blinding } => {
                    strict_encode_list!(e; 1u8, vout, blinding)
                }
            })
        }
    }

    impl StrictDecode for Revealed {
        type Error = Error;

        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
            let format = u8::strict_decode(&mut d)?;
            Ok(match format {
                0u8 => Revealed::TxOutpoint(OutpointReveal::strict_decode(d)?),
                1u8 => Revealed::WitnessVout {
                    vout: u32::strict_decode(&mut d)?,
                    blinding: u64::strict_decode(&mut d)?,
                },
                invalid => Err(Error::EnumValueNotKnown(
                    "seal::Confidential".to_string(),
                    invalid,
                ))?,
            })
        }
    }
}

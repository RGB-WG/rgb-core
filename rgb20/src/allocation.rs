// RGB20 Library: fungible digital assets for bitcoin & lightning
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

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display, Formatter};
use std::num::{ParseFloatError, ParseIntError};
use std::str::FromStr;

use bitcoin::blockdata::transaction::ParseOutPointError;
use bitcoin::hashes::hex::FromHex;
use bitcoin::{OutPoint, Txid};
use lnpbp::seals::{OutpointHash, OutpointReveal};
use rgb::{AtomicValue, SealDefinition, ToSealDefinition};

#[derive(Clone, Copy, Debug, Display, Error, From)]
#[display(doc_comments)]
#[from(ParseFloatError)]
#[from(ParseIntError)]
#[from(ParseOutPointError)]
#[from(bitcoin::hashes::hex::Error)]
#[from(lnpbp::bech32::Error)]
/// Error parsing data
pub struct ParseError;

#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    StrictEncode,
    StrictDecode,
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize,),
    serde(crate = "serde_crate")
)]
#[strict_encoding_crate(lnpbp::strict_encoding)]
pub struct AllocatedValue {
    pub value: AtomicValue,
    pub vout: u32,
    pub txid: Option<Txid>,
}

#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Display,
    StrictEncode,
    StrictDecode,
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize,),
    serde(crate = "serde_crate")
)]
#[display("{value}@{outpoint}")]
#[strict_encoding_crate(lnpbp::strict_encoding)]
pub struct OutpointValue {
    pub value: AtomicValue,
    pub outpoint: OutPoint,
}

#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Display,
    StrictEncode,
    StrictDecode,
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize,),
    serde(crate = "serde_crate")
)]
#[display("{value}@{seal_confidential}")]
#[strict_encoding_crate(lnpbp::strict_encoding)]
pub struct UtxobValue {
    pub value: AtomicValue,
    pub seal_confidential: OutpointHash,
}

impl ToSealDefinition for AllocatedValue {
    fn to_seal_definition(&self) -> SealDefinition {
        use bitcoin::secp256k1::rand::{self, RngCore};
        let mut rng = rand::thread_rng();
        // Not an amount blinding factor but outpoint blinding
        let entropy = rng.next_u64();
        match self.txid {
            Some(txid) => SealDefinition::TxOutpoint(OutpointReveal {
                blinding: entropy,
                txid,
                vout: self.vout,
            }),
            None => SealDefinition::WitnessVout {
                vout: self.vout,
                blinding: entropy,
            },
        }
    }
}

impl ToSealDefinition for OutpointValue {
    fn to_seal_definition(&self) -> SealDefinition {
        use bitcoin::secp256k1::rand::{self, RngCore};
        let mut rng = rand::thread_rng();
        // Not an amount blinding factor but outpoint blinding
        let entropy = rng.next_u64();
        SealDefinition::TxOutpoint(OutpointReveal {
            blinding: entropy,
            txid: self.outpoint.txid,
            vout: self.outpoint.vout,
        })
    }
}

impl Display for AllocatedValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}@", self.value)?;
        if let Some(txid) = self.txid {
            write!(f, "{}:", txid)?;
        }
        f.write_str(&self.vout.to_string())
    }
}

impl FromStr for AllocatedValue {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split(&['@', ':'][..]);
        match (split.next(), split.next(), split.next(), split.next()) {
            (Some(value), Some(txid), Some(vout), None) => Ok(Self {
                value: value.parse()?,
                vout: vout.parse()?,
                txid: Some(Txid::from_hex(txid)?),
            }),
            (Some(value), Some(vout), None, _) => Ok(Self {
                value: value.parse()?,
                vout: vout.parse()?,
                txid: None,
            }),
            _ => Err(ParseError),
        }
    }
}

impl FromStr for OutpointValue {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split(&['@', ':'][..]);
        match (split.next(), split.next(), split.next()) {
            (Some(value), Some(outpoint), None) => Ok(Self {
                value: value.parse()?,
                outpoint: outpoint.parse()?,
            }),
            _ => Err(ParseError),
        }
    }
}

impl FromStr for UtxobValue {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split(&['@', ':'][..]);
        match (split.next(), split.next(), split.next()) {
            (Some(value), Some(seal), None) => Ok(Self {
                value: value.parse()?,
                seal_confidential: seal.parse()?,
            }),
            _ => Err(ParseError),
        }
    }
}

// RGB20 Library: fungible digital assets for bitcoin & lightning
// Written in 2020-2021 by
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

//! Information about RGB20 asset allocations

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::{As, DisplayFromStr};
use std::fmt::{self, Display, Formatter};
use std::num::{ParseFloatError, ParseIntError};
use std::str::FromStr;

use bitcoin::blockdata::transaction::ParseOutPointError;
use bitcoin::hashes::hex::FromHex;
use bitcoin::{OutPoint, Txid};
use lnpbp::seals::{OutpointHash, OutpointReveal};
use rgb::{value, AtomicValue, NodeId, SealDefinition, ToSealDefinition};

#[derive(Clone, Copy, Debug, Display, Error, From)]
#[display(doc_comments)]
#[from(ParseFloatError)]
#[from(ParseIntError)]
#[from(ParseOutPointError)]
#[from(bitcoin::hashes::hex::Error)]
#[from(lnpbp::bech32::Error)]
/// Error parsing data
pub struct ParseError;

/// Information about specific allocated asset value, assigned to either
/// external bitcoin transaction outpoint or specific witness transaction output
/// number
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
    /// Assigned value of the asset
    pub value: AtomicValue,

    /// Transaction output number
    pub vout: u32,

    /// [`Txid`] of the external transaction, if the amount assigned not to the
    /// witness transaction output
    pub txid: Option<Txid>,
}

/// Information about asset value allocated to well-formed bitcoin transaction
/// output. Unlike [`AllocatedValue`] keeps the full transaction id even if the
/// output is contained within the witness transaction.
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
    /// Assigned value of the asset
    pub value: AtomicValue,

    /// Outpoint containing asset assignment
    pub outpoint: OutPoint,
}

/// Information about RGB20 asset assigned to a blinded transaction output
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
    /// Assigned value of the asset
    pub value: AtomicValue,

    /// Blinded transaction outpoint
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

/// Information about asset allocation source
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[derive(
    Clone, Copy, Getters, PartialEq, Debug, Display, StrictEncode, StrictDecode,
)]
#[strict_encoding_crate(lnpbp::strict_encoding)]
#[display("{revealed_amount}@{outpoint}&{node_id}#{index}")]
pub struct Allocation {
    /// Unique primary key is `node_id` + `index`
    node_id: NodeId,

    /// Index of the assignment of ownership right type within the node
    index: u16,

    /// Copy of the outpoint from corresponding entry in
    /// [`Asset::known_allocations`]
    #[cfg_attr(feature = "serde", serde(with = "As::<DisplayFromStr>"))]
    outpoint: OutPoint,

    /// Revealed confidential amount consisting of an explicit atomic amount
    /// and Pedersen commitment blinding factor
    revealed_amount: value::Revealed,
}

impl Allocation {
    /// Constructs asset allocation information from the provided function
    /// arguments
    #[inline]
    pub(crate) fn with(
        node_id: NodeId,
        index: u16,
        outpoint: OutPoint,
        value: value::Revealed,
    ) -> Allocation {
        Allocation {
            node_id,
            index,
            outpoint,
            revealed_amount: value,
        }
    }

    /// Convenience function returning atomic value of the asset inside the
    /// assignments. Equal to `Allocation::revealed_amount.value`
    #[inline]
    pub fn value(&self) -> AtomicValue {
        self.revealed_amount.value
    }
}

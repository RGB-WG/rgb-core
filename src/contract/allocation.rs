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

//! Allocations are a special case of assignments, where the state assigned to
//! the seal contains homomorphically-committed value (i.e. data representing
//! some additive values, like amount of asset – see [`rgb::value`] and
//! [`AtomicAmount`]).
//!
//! RGB Core library defines three data types for holding allocation data, which
//! differ in their support for witness-based assignments and blinding secret:
//!
//! | **Type name**      | **Which seal can produce** | **Witness** | **Blinding** | **Use case**                                  |
//! | ------------------ | -------------------------- | ----------- | ------------ | --------------------------------------------- |
//! | [`OutpointValue`]  | [`OutPoint`]               | No          | No           | Genesis creation                              |
//! | [`AllocatedValue`] | [`SealPoint`]              | Yes         | No           | State transition with self-owned rights       |
//! | [`UtxobValue`]     | [`OutpointHash`]           | Implicit    | Implicit     | State transition with externally-owned rights |

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::{As, DisplayFromStr};
use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use bitcoin::blockdata::transaction::ParseOutPointError;
use bitcoin::OutPoint;
use lnpbp::seals::{OutpointHash, OutpointReveal};

use crate::seal::SealPoint;
use crate::{
    value, AtomicValue, NodeId, NodeOutput, SealDefinition, ToSealDefinition,
};

/// Error parsing allocation data
#[derive(
    Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, Error, From,
)]
#[display(doc_comments)]
pub enum ParseError {
    /// Seal parse error
    #[display(inner)]
    #[from]
    Seal(lnpbp::seals::ParseError),

    /// the value for the allocation must be an 64-bit decimal integer
    WrongValue,

    /// wrong structure of the transaction outpoint data
    #[from(ParseOutPointError)]
    WrongOutpoint,

    /// wrong structure of allocation string representation: it must be
    /// represented as `<atomic_value>@<seal_definition>
    WrongStructure,
}

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

    /// Seal definition
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub seal: SealPoint,
}

impl ToSealDefinition for AllocatedValue {
    fn to_seal_definition(&self) -> SealDefinition {
        use bitcoin::secp256k1::rand::{self, RngCore};
        let mut rng = rand::thread_rng();
        // Not an amount blinding factor but outpoint blinding
        let entropy = rng.next_u64();
        match self.seal.txid {
            Some(txid) => SealDefinition::TxOutpoint(OutpointReveal {
                blinding: entropy,
                txid,
                vout: self.seal.vout,
            }),
            None => SealDefinition::WitnessVout {
                vout: self.seal.vout,
                blinding: entropy,
            },
        }
    }
}

impl Display for AllocatedValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}@", self.value)?;
        Display::fmt(&self.seal, f)
    }
}

impl FromStr for AllocatedValue {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split('@');
        match (split.next(), split.next(), split.next()) {
            (Some(value), Some(seal), None) => Ok(AllocatedValue {
                value: value.parse().map_err(|_| ParseError::WrongValue)?,
                seal: seal.parse()?,
            }),
            _ => Err(ParseError::WrongStructure),
        }
    }
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

impl FromStr for OutpointValue {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split('@');
        match (split.next(), split.next(), split.next()) {
            (Some(value), Some(outpoint), None) => Ok(Self {
                value: value.parse().map_err(|_| ParseError::WrongValue)?,
                outpoint: outpoint
                    .parse()
                    .map_err(|_| ParseError::WrongOutpoint)?,
            }),
            _ => Err(ParseError::WrongStructure),
        }
    }
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

impl FromStr for UtxobValue {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split('@');
        match (split.next(), split.next(), split.next()) {
            (Some(value), Some(seal), None) => Ok(UtxobValue {
                value: value.parse().map_err(|_| ParseError::WrongValue)?,
                seal_confidential: seal.parse()?,
            }),
            _ => Err(ParseError::WrongStructure),
        }
    }
}

/// Information about an allocation, represented by RGB contract node output,
/// seal definition and assigned value
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
    pub fn with(
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

    /// Returns [`NodeOutput`] containing current allocation
    #[inline]
    pub fn node_output(&self) -> NodeOutput {
        NodeOutput {
            node_id: self.node_id,
            output_no: self.index,
        }
    }

    /// Returns [`OutpointValue`] combining full bitcoin transaction output as
    /// seal definition and [`AtomicValue`] of the assignment
    #[inline]
    pub fn outpoint_value(&self) -> OutpointValue {
        OutpointValue {
            value: self.revealed_amount.value,
            outpoint: self.outpoint,
        }
    }
}

/// Allocation maps are used by schema-specific APIs node constructors. They
/// allow creation of type-safe arguments listing each of the seals exactly
/// once, and providing [`AtomicAmount`] that has to be assigned to each of the
/// seals.
pub type AllocationMap<S> = BTreeMap<S, AtomicValue>;

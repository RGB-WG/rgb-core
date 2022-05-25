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
//! the seal contains homomorphicly-committed value (i.e. data representing
//! some additive values, like amount of asset – see [`rgb::value`] and
//! [`AtomicAmount`]).
//!
//! # Allocation types
//!
//! RGB Core library defines three data types for holding allocation data, which
//! differ in their support for witness-based assignments and blinding secret:
//!
//! | **Type name**      | **Which seal can produce** | **Witness** | **Blinding** | **Use case**                                  |
//! | ------------------ | -------------------------- | ----------- | ------------ | --------------------------------------------- |
//! | [`OutpointValue`]  | [`OutPoint`]               | No          | No           | Genesis creation                              |
//! | [`AllocatedValue`] | [`SealPoint`]              | Yes         | No           | State transition with self-owned rights       |
//! | [`UtxobValue`]     | [`OutpointHash`]           | Implicit    | Implicit     | State transition with externally-owned rights |
//!
//! # Allocation maps
//!
//! In most of the cases functions constructing state transitions consume
//! allocation data with different structure, depending on specific schema
//! requirements. For this purpose this module defines a set of helper type
//! aliases (**allocation maps**):
//!
//! | **Type name**          | **Seals can be repeated** | **Seal blinding** | **Can use witness?** | **Seals**      | **Underlying type**                                 | **Use cases**           |
//! | ---------------------- | ------------------------- | ----------------- | -------------------- | -------------- | --------------------------------------------------- | ----------------------- |
//! | [`OutpointValueVec`]   | Yes                       | Not important     | No                   | OutPoint       | `Vec<`[`OutpointValue`]`>`                          | Genesis, ownership      |
//! | [`OutpointValueMap`]   | No                        | Not important     | No                   | OutPoint       | `BTreeMap<`[`OutPoint`]`, `[`AtomicValue`]`>`       | Genesis, control rights |
//! | [`AllocationValueVec`] | Yes                       | Not important     | Yes                  | SealPoint      | `Vec<`[`AllocatedValue`]`>`                         | Change                  |
//! | [`AllocationValueMap`] | No                        | Not important     | Yes                  | SealPoint      | `BTreeMap<`[`SealPoint`]`, `[`AtomicValue`]`>`      | Control rights          |
//! | [`SealValueMap`]       | By using blinding         | Present           | Yes                  | SealDefinition | `BTreeMap<`[`SealDefinition`]`, `[`AtomicValue`]`>` | Zero balancing          |
//! | [`EndpointValueMap`]   | By using blinding         | Predefined        | Yes                  | SealEndpoint   | `BTreeMap<`[`SealEndpoint`]`, `[`AtomicValue`]`>`   | Payment                 |
//!
//! Allocation maps are used by schema-specific APIs node constructors. They
//! allow creation of type-safe arguments listing each of the seals exactly
//! once, and providing [`AtomicValue`] that has to be assigned to each of the
//! seals.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::{As, DisplayFromStr};
use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use bitcoin::blockdata::transaction::ParseOutPointError;
use bitcoin::secp256k1::rand::thread_rng;
use bitcoin::OutPoint;
use bp::seals;
use bp::seals::txout::blind::RevealedSeal;
use bp::seals::txout::ExplicitSeal;

use crate::{
    seal, value, Assignment, AssignmentVec, AtomicValue, IntoRevealedSeal,
    NodeId, NodeOutput, SealEndpoint,
};

/// Error parsing allocation data
#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum ParseError {
    /// Blind seal parse error
    #[display(inner)]
    #[from]
    BlindSeal(seals::txout::blind::ParseError),

    /// Explicit seal parse error
    #[display(inner)]
    #[from]
    ExplicitSeal(seals::txout::explicit::ParseError),

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
pub struct AllocatedValue {
    /// Assigned value of the asset
    pub value: AtomicValue,

    /// Seal definition
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub seal: ExplicitSeal,
}

impl IntoRevealedSeal for AllocatedValue {
    fn into_revealed_seal(self) -> RevealedSeal {
        RevealedSeal::from(self.seal)
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
pub struct OutpointValue {
    /// Assigned value of the asset
    pub value: AtomicValue,

    /// Outpoint containing asset assignment
    pub outpoint: OutPoint,
}

impl IntoRevealedSeal for OutpointValue {
    fn into_revealed_seal(self) -> RevealedSeal {
        seal::Revealed::from(self.outpoint)
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
pub struct UtxobValue {
    /// Assigned value of the asset
    pub value: AtomicValue,

    /// Blinded transaction outpoint
    pub seal_confidential: seal::Confidential,
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

/// Allocation map using vec of non-blinded seal definitions which can't assign
/// to a witness transaction output. Seal definition may be repeating (i.e.
/// single seal may receive multiple allocations)
pub type OutpointValueVec = Vec<OutpointValue>;

/// Allocation map using unique set of non-blinded seal definitions, which can't
/// assign to a witness transaction output.
pub type OutpointValueMap = BTreeMap<OutPoint, AtomicValue>;

/// Allocation map using vec of non-blinded seal definitions, which may be
/// repeating (i.e. single seal may receive multiple allocations)
pub type AllocationValueVec = Vec<AllocatedValue>;

/// Allocation map using unique set of non-blinded seal definitions
pub type AllocationValueMap = BTreeMap<ExplicitSeal, AtomicValue>;

/// Allocation map using unique set of seal definitions
pub type SealValueMap = BTreeMap<seal::Revealed, AtomicValue>;

/// Allocation map using unique set of blinded consignment endpoints
pub type EndpointValueMap = BTreeMap<SealEndpoint, AtomicValue>;

/// Methods common to all kinds of **allocation map** data types
pub trait AllocationMap {
    /// Returns sum of all atomic values inside the allocation map
    fn sum(&self) -> AtomicValue;

    /// Turns allocation map into [`AssignmentVec`]
    fn into_assignments(self) -> AssignmentVec;
}

impl AllocationMap for OutpointValueVec {
    fn sum(&self) -> u64 {
        self.iter().map(|v| v.value).sum()
    }

    fn into_assignments(self) -> AssignmentVec {
        self.into_seal_value_map().into_assignments()
    }
}

impl AllocationMap for OutpointValueMap {
    fn sum(&self) -> u64 {
        self.values().sum()
    }

    fn into_assignments(self) -> AssignmentVec {
        self.into_seal_value_map().into_assignments()
    }
}

impl AllocationMap for AllocationValueVec {
    fn sum(&self) -> u64 {
        self.iter().map(|v| v.value).sum()
    }

    fn into_assignments(self) -> AssignmentVec {
        self.into_seal_value_map().into_assignments()
    }
}

impl AllocationMap for AllocationValueMap {
    fn sum(&self) -> u64 {
        self.values().sum()
    }

    fn into_assignments(self) -> AssignmentVec {
        self.into_seal_value_map().into_assignments()
    }
}

impl AllocationMap for SealValueMap {
    fn sum(&self) -> u64 {
        self.values().sum()
    }

    fn into_assignments(self) -> AssignmentVec {
        let mut rng = thread_rng();
        AssignmentVec::DiscreteFiniteField(
            self.into_iter()
                .map(|(seal, value)| Assignment::Revealed {
                    seal_definition: seal,
                    assigned_state: value::Revealed::with_amount(
                        value, &mut rng,
                    ),
                })
                .collect(),
        )
    }
}

impl AllocationMap for EndpointValueMap {
    fn sum(&self) -> u64 {
        self.values().sum()
    }

    fn into_assignments(self) -> AssignmentVec {
        let mut rng = thread_rng();
        AssignmentVec::DiscreteFiniteField(
            self.into_iter()
                .map(|(seal, value)| {
                    let assigned_state =
                        value::Revealed::with_amount(value, &mut rng);
                    match seal {
                        SealEndpoint::ConcealedUtxo(confidential) => {
                            Assignment::ConfidentialSeal {
                                seal_definition: confidential,
                                assigned_state,
                            }
                        }
                        SealEndpoint::WitnessVout {
                            method,
                            vout,
                            blinding,
                        } => Assignment::Revealed {
                            seal_definition: seal::Revealed {
                                method,
                                txid: None,
                                vout,
                                blinding,
                            },
                            assigned_state,
                        },
                    }
                })
                .collect(),
        )
    }
}

/// Conversion into [`SealValueMap`] which has all required data for
/// constructing assignments (complete revealed seal definitions with assigned
/// blinding factors to them).
pub trait IntoSealValueMap {
    /// Converts given **allocation map** into [`SealValueMap`]
    fn into_seal_value_map(self) -> SealValueMap;
}

impl IntoSealValueMap for OutpointValueVec {
    fn into_seal_value_map(self) -> SealValueMap {
        self.into_iter()
            .map(|outpoint_value| {
                (
                    seal::Revealed::from(outpoint_value.outpoint),
                    outpoint_value.value,
                )
            })
            .collect()
    }
}

impl IntoSealValueMap for OutpointValueMap {
    fn into_seal_value_map(self) -> SealValueMap {
        self.into_iter()
            .map(|(outpoint, value)| (seal::Revealed::from(outpoint), value))
            .collect()
    }
}

impl IntoSealValueMap for AllocationValueVec {
    fn into_seal_value_map(self) -> SealValueMap {
        self.into_iter()
            .map(|allocated_value| {
                (allocated_value.seal.into(), allocated_value.value)
            })
            .collect()
    }
}

impl IntoSealValueMap for AllocationValueMap {
    fn into_seal_value_map(self) -> SealValueMap {
        self.into_iter()
            .map(|(seal, value)| (seal.into(), value))
            .collect()
    }
}

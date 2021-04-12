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

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

use bitcoin::{OutPoint, Txid};
use rgb::{ContractId, Genesis, Node, NodeId};

use crate::asset::Error;
use crate::schema::{self, FieldType};

/// Nomination is a set of records keeping asset meta-information related to the
/// names and other aspects of asset representation.
///
/// Nomination stores values for
/// - Asset name
/// - Asset ticker
/// - Ricardian contract
/// - Decimal percision
/// taken from asset genesis and renomination state transitions.
///
/// This is purely data structure; for tracking information about renomination
/// _operation_ (operation of changing asset names and other nomination values)
/// please see [`Renomination`].
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[derive(
    Clone, Getters, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display,
)]
#[display("{ticker}")]
#[derive(StrictEncode, StrictDecode)]
#[strict_encoding_crate(lnpbp::strict_encoding)]
pub struct Nomination {
    /// Asset ticker, up to 8 characters
    ticker: String,

    /// Full asset name
    name: String,

    /// Text of Ricardian contract
    ricardian_contract: Option<String>,

    /// Number of digits after the asset decimal point
    decimal_precision: u8,
}

impl TryFrom<Genesis> for Nomination {
    type Error = Error;

    fn try_from(genesis: Genesis) -> Result<Self, Self::Error> {
        Nomination::try_from(&genesis)
    }
}

impl TryFrom<&Genesis> for Nomination {
    type Error = Error;

    fn try_from(genesis: &Genesis) -> Result<Self, Self::Error> {
        if genesis.schema_id() != schema::schema().schema_id() {
            Err(Error::WrongSchemaId)?;
        }
        let genesis_meta = genesis.metadata();

        Ok(Nomination {
            ticker: genesis_meta
                .string(*FieldType::Ticker)
                .first()
                .ok_or(Error::UnsatisfiedSchemaRequirement)?
                .clone(),
            name: genesis_meta
                .string(*FieldType::Name)
                .first()
                .ok_or(Error::UnsatisfiedSchemaRequirement)?
                .clone(),
            ricardian_contract: genesis_meta
                .string(*FieldType::RicardianContract)
                .first()
                .cloned(),
            decimal_precision: *genesis_meta
                .u8(*FieldType::Precision)
                .first()
                .ok_or(Error::UnsatisfiedSchemaRequirement)?,
        })
    }
}

/// Renomination operation details.
///
/// Renominations
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[derive(
    Clone, Getters, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display,
)]
#[display("{no}:{node_id}")]
#[derive(StrictEncode, StrictDecode)]
#[strict_encoding_crate(lnpbp::strict_encoding)]
pub struct Renomination {
    /// Unique primary key; equals to the state transition id that performs
    /// renomination operation
    node_id: NodeId,

    /// Sequential number of the epoch
    ///
    /// NB: There is no zero epoch and the first is an epoch closing genesis
    /// epoch seal
    no: usize,

    /// Contract ID to which this renomination is related to
    contract_id: ContractId,

    /// Indicates transaction output/seal which had an assigned renomination
    /// right and which closing created this renomination.
    closes: OutPoint,

    /// Seal controlling next renomination operation.
    ///
    /// This can be set to `None` in case if further renominations are
    /// prohibited
    seal: Option<OutPoint>,

    /// Witness transaction id, which should be present in the commitment
    /// medium (bitcoin blockchain or state channel) to make the operation
    /// valid
    witness: Txid,

    /// Actual asset nomination metadata
    #[cfg_attr(feature = "serde", serde(flatten))]
    nomination: Nomination,
}

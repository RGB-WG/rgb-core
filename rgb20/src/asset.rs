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

use chrono::{DateTime, NaiveDateTime, Utc};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::{As, DisplayFromStr};
use std::collections::BTreeMap;
use std::convert::{TryFrom, TryInto};

use amplify::Wrapper;
use bitcoin::{OutPoint, Txid};
use lnpbp::Chain;
use rgb::prelude::*;
use rgb::seal::WitnessVoutError;

use super::schema::{self, FieldType, OwnedRightsType};
use crate::{
    Allocation, Epoch, FractionalAmount, Issue, PreciseAmount, Supply,
    SupplyMeasure,
};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Display, From, Error)]
#[display(doc_comments)]
pub enum Error {
    /// Can't read asset data: provided information does not match schema:
    /// {_0}
    #[from]
    Schema(schema::Error),

    /// Genesis defines a seal referencing witness transaction while there
    /// can't be a witness transaction for genesis
    #[from(WitnessVoutError)]
    GenesisSeal,

    /// Epoch seal definition for node {0} contains confidential data
    EpochSealConfidential(NodeId),

    /// Burn & replace seal definition for node {0} contains confidential data
    BurnSealConfidential(NodeId),

    /// Inflation assignment (seal or state) for node {0} contains confidential
    /// data
    InflationAssignmentConfidential(NodeId),
}

// TODO #31: Add support for renominations, burn & replacements
/// Detailed RGB20 asset information
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[derive(
    Clone, Getters, PartialEq, Debug, Display, StrictEncode, StrictDecode,
)]
#[display("{ticker} ({id})")]
#[strict_encoding_crate(lnpbp::strict_encoding)]
pub struct Asset {
    /// Bech32-representation of the asset genesis
    genesis: String,

    /// Asset ID, which is equal to Contract ID and genesis ID
    ///
    /// It can be used as a unique primary kep
    id: ContractId,

    /// Asset ticker, up to 8 characters
    ticker: String,

    /// Full asset name
    name: String,

    /// Text of Ricardian contract
    ricardian_contract: Option<String>,

    /// Chain with which the asset is issued
    #[cfg_attr(feature = "serde", serde(with = "As::<DisplayFromStr>"))]
    chain: Chain,

    /// Number of digits after the asset decimal point
    decimal_precision: u8,

    /// Asset creation data
    date: DateTime<Utc>,

    /// All issues known from the available data (stash and/or provided
    /// consignments)
    ///
    /// Primary issue is always the first one; the rest are provided in
    /// arbitrary order
    known_issues: Vec<Issue>,

    /// Burn & replacement epochs, organized according to the witness txid.
    ///
    /// Witness transaction must be mined for the epoch to be real.
    /// One of the inputs of this transaction MUST spend UTXO defined as a
    /// seal closed by this epoch ([`Epoch::closes`])
    epochs: BTreeMap<Txid, Epoch>,

    /// Detailed information about the asset supply (aggregated from the issue
    /// and burning information kept inside the epochs data)
    #[cfg_attr(feature = "serde", serde(flatten))]
    supply: Supply,

    /// Specifies outpoints which when spent may indicate inflation happening
    /// up to specific amount.
    ///
    /// NB: Not of all inflation controlling points may be known
    #[cfg_attr(
        feature = "serde",
        serde(with = "As::<BTreeMap<DisplayFromStr, DisplayFromStr>>")
    )]
    // TODO #32: Transform into method iterating and collecting this
    // information      from `known_issues`
    known_inflation: BTreeMap<OutPoint, AtomicValue>,

    /// Specifies outpoints controlling certain amounts of assets.
    ///
    /// NB: Information here does not imply that the outputs are owned by the
    /// current user or the owning transactions are mined/exist; this must be
    /// determined by the wallet and depends on specific medium (blockchain,
    /// LN)
    known_allocations: Vec<Allocation>,
}

impl Asset {
    #[inline]
    pub fn with(
        genesis: String,
        id: ContractId,
        ticker: String,
        name: String,
        ricardian_contract: Option<String>,
        supply: Supply,
        chain: Chain,
        decimal_precision: u8,
        date: DateTime<Utc>,
        known_issues: Vec<Issue>,
        known_inflation: BTreeMap<bitcoin::OutPoint, AtomicValue>,
        known_allocations: Vec<Allocation>,
    ) -> Asset {
        Asset {
            genesis,
            id,
            ticker,
            name,
            ricardian_contract,
            supply,
            chain,
            decimal_precision,
            date,
            known_issues,
            known_inflation,
            known_allocations,
            epochs: empty!(),
        }
    }

    pub fn accounting_supply(
        &self,
        measure: SupplyMeasure,
    ) -> FractionalAmount {
        let value = match measure {
            SupplyMeasure::KnownCirculating => *self.supply.known_circulating(),
            SupplyMeasure::TotalCirculating => {
                match self.supply.total_circulating() {
                    None => return FractionalAmount::NAN,
                    Some(supply) => supply,
                }
            }
            SupplyMeasure::IssueLimit => *self.supply.issue_limit(),
        };
        PreciseAmount::transmutate_into(value, self.decimal_precision)
    }

    #[inline]
    pub fn known_atomic_value(&self) -> AtomicValue {
        self.known_allocations.iter().map(Allocation::value).sum()
    }

    pub fn known_filtered_atomic_value<F>(&self, filter: F) -> AtomicValue
    where
        F: Fn(&Allocation) -> bool,
    {
        self.known_allocations
            .iter()
            .filter(|allocation| filter(*allocation))
            .map(Allocation::value)
            .sum()
    }

    pub fn known_accounting_value(&self) -> FractionalAmount {
        self.known_allocations
            .iter()
            .map(Allocation::value)
            .map(|atomic| {
                PreciseAmount::transmutate_into(atomic, self.decimal_precision)
            })
            .sum()
    }

    pub fn known_filtered_accounting_value<F>(
        &self,
        filter: F,
    ) -> FractionalAmount
    where
        F: Fn(&Allocation) -> bool,
    {
        self.known_allocations
            .iter()
            .filter(|allocation| filter(*allocation))
            .map(Allocation::value)
            .map(|atomic| {
                PreciseAmount::transmutate_into(atomic, self.decimal_precision)
            })
            .sum()
    }
}

impl Asset {
    #[inline]
    pub fn allocations(&self, outpoint: OutPoint) -> Vec<Allocation> {
        self.known_allocations
            .iter()
            .filter(|a| *a.outpoint() == outpoint)
            .copied()
            .collect()
    }

    pub fn add_allocation(
        &mut self,
        outpoint: OutPoint,
        node_id: NodeId,
        index: u16,
        value: value::Revealed,
    ) -> bool {
        let new_allocation = Allocation::with(node_id, index, outpoint, value);
        if !self.known_allocations.contains(&new_allocation) {
            self.known_allocations.push(new_allocation);
            true
        } else {
            false
        }
    }

    pub fn remove_allocation(
        &mut self,
        outpoint: OutPoint,
        node_id: NodeId,
        index: u16,
        value: value::Revealed,
    ) -> bool {
        let old_allocation = Allocation::with(node_id, index, outpoint, value);
        if let Some(index) = self
            .known_allocations
            .iter()
            .position(|a| *a == old_allocation)
        {
            self.known_allocations.remove(index);
            true
        } else {
            false
        }
    }
}

impl TryFrom<Genesis> for Asset {
    type Error = Error;

    fn try_from(genesis: Genesis) -> Result<Self, Self::Error> {
        if genesis.schema_id() != schema::schema().schema_id() {
            Err(schema::Error::WrongSchemaId)?;
        }
        let genesis_meta = genesis.metadata();
        let decimal_precision = *genesis_meta
            .u8(*FieldType::Precision)
            .first()
            .ok_or(schema::Error::NotAllFieldsPresent)?;
        let supply = *genesis_meta
            .u64(*FieldType::IssuedSupply)
            .first()
            .ok_or(schema::Error::NotAllFieldsPresent)?;
        let mut known_inflation = BTreeMap::<_, _>::default();
        let mut issue_limit = 0;

        for assignment in
            genesis.owned_rights_by_type(*OwnedRightsType::Inflation)
        {
            for state in assignment.to_data_assignment_vec() {
                match state {
                    Assignment::Revealed {
                        seal_definition,
                        assigned_state,
                    } => {
                        known_inflation.insert(
                            seal_definition.try_into()?,
                            assigned_state
                                .u64()
                                .ok_or(schema::Error::NotAllFieldsPresent)?,
                        );
                    }
                    Assignment::ConfidentialSeal { assigned_state, .. } => {
                        if issue_limit < core::u64::MAX {
                            issue_limit += assigned_state
                                .u64()
                                .ok_or(schema::Error::NotAllFieldsPresent)?
                        };
                    }
                    _ => {
                        issue_limit = core::u64::MAX;
                    }
                }
            }
        }

        let issue = Issue::try_from(&genesis)?;
        let node_id = NodeId::from_inner(genesis.contract_id().into_inner());
        let mut known_allocations = Vec::<Allocation>::new();
        for assignment in genesis.owned_rights_by_type(*OwnedRightsType::Assets)
        {
            assignment
                .to_value_assignment_vec()
                .into_iter()
                .enumerate()
                .for_each(|(index, assign)| {
                    if let Assignment::Revealed {
                        seal_definition:
                            seal::Revealed::TxOutpoint(outpoint_reveal),
                        assigned_state,
                    } = assign
                    {
                        known_allocations.push(Allocation::with(
                            node_id,
                            index as u16,
                            outpoint_reveal.into(),
                            assigned_state,
                        ))
                    }
                });
        }
        Ok(Self {
            genesis: genesis.to_string(),
            id: genesis.contract_id(),
            chain: genesis.chain().clone(),
            ticker: genesis_meta
                .string(*FieldType::Ticker)
                .first()
                .ok_or(schema::Error::NotAllFieldsPresent)?
                .clone(),
            name: genesis_meta
                .string(*FieldType::Name)
                .first()
                .ok_or(schema::Error::NotAllFieldsPresent)?
                .clone(),
            ricardian_contract: genesis_meta
                .string(*FieldType::RicardianContract)
                .first()
                .cloned(),
            supply: Supply::with(supply, None, issue_limit),
            decimal_precision,
            date: DateTime::from_utc(
                NaiveDateTime::from_timestamp(
                    *genesis_meta
                        .i64(*FieldType::Timestamp)
                        .first()
                        .ok_or(schema::Error::NotAllFieldsPresent)?,
                    0,
                ),
                Utc,
            ),
            known_inflation,
            known_issues: vec![issue],
            // we assume that each genesis allocation with revealed amount
            // and known seal (they are always revealed together) belongs to us
            known_allocations,
            epochs: empty!(),
        })
    }
}

impl TryFrom<Consignment> for Asset {
    type Error = Error;

    fn try_from(consignment: Consignment) -> Result<Self, Self::Error> {
        // 1. Parse genesis
        let asset: Asset = consignment.genesis.try_into()?;

        // 2. Parse secondary issues

        // 3. Parse epochs & burn/replace operations

        // 4. Parse renominations

        unimplemented!()
    }
}

impl Asset {
    #[allow(dead_code)]
    fn append_epoch(
        &mut self,
        consignment: &Consignment,
        epoch_id: NodeId,
    ) -> Result<(), Error> {
        // 1. It must correctly extend known state, i.e. close UTXO for a seal
        //    defined by a state transition already belonging to the asset
        unimplemented!()
    }

    #[allow(dead_code)]
    fn append_burn_or_replace(
        &mut self,
        consignment: &Consignment,
        epoch_id: NodeId,
        bor_id: NodeId,
    ) -> Result<(), Error> {
        unimplemented!()
    }
}

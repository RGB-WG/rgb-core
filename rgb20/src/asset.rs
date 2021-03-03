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

use chrono::NaiveDateTime;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_with::{As, DisplayFromStr};
use std::collections::BTreeMap;
use std::convert::{TryFrom, TryInto};
use std::ops::{Add, AddAssign};

use amplify::Wrapper;
use lnpbp::Chain;
use rgb::prelude::*;
use rgb::seal::WitnessVoutError;

use super::schema::{self, FieldType, OwnedRightsType};

pub type AccountingValue = f64;

/// Accounting amount keeps track of the asset precision
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Debug,
    Display,
    Default,
    StrictEncode,
    StrictDecode,
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[strict_encoding_crate(lnpbp::strict_encoding)]
#[display("{0}~{1}")]
pub struct AccountingAmount(AtomicValue, u8);

impl AccountingAmount {
    const DIVIDER: [u64; 20] = [
        1,
        10,
        100,
        1_000,
        10_000,
        100_000,
        1_000_000,
        10_000_000,
        100_000_000,
        1_000_000_000,
        10_000_000_000,
        100_000_000_000,
        1_000_000_000_000,
        10_000_000_000_000,
        100_000_000_000_000,
        1_000_000_000_000_000,
        10_000_000_000_000_000,
        100_000_000_000_000_000,
        1_000_000_000_000_000_000,
        10_000_000_000_000_000_000,
    ];

    #[inline]
    pub fn transmutate_from(
        decimal_precision: u8,
        accounting_value: AccountingValue,
    ) -> AtomicValue {
        AccountingAmount::from_fractioned_accounting_value(
            decimal_precision,
            accounting_value,
        )
        .atomic_value()
    }

    #[inline]
    pub fn transmutate_into(
        decimal_precision: u8,
        atomic_value: AtomicValue,
    ) -> AccountingValue {
        AccountingAmount::from_fractioned_atomic_value(
            decimal_precision,
            atomic_value,
        )
        .accounting_value()
    }

    #[inline]
    pub fn from_asset_accounting_value(
        asset: &Asset,
        accounting_value: AccountingValue,
    ) -> Self {
        Self::from_fractioned_accounting_value(
            asset.decimal_precision,
            accounting_value,
        )
    }

    #[inline]
    pub fn from_fractioned_atomic_value(
        decimal_precision: u8,
        atomic_value: AtomicValue,
    ) -> Self {
        Self(atomic_value, decimal_precision)
    }

    #[inline]
    pub fn from_fractioned_accounting_value(
        decimal_precision: u8,
        accounting_value: AccountingValue,
    ) -> Self {
        let full = (accounting_value.trunc() as u64)
            * Self::DIVIDER[decimal_precision as usize];
        let fract = accounting_value.fract() as u64;
        Self(full + fract, decimal_precision)
    }

    #[inline]
    pub fn from_asset_atomic_value(
        asset: &Asset,
        atomic_value: AtomicValue,
    ) -> Self {
        Self(atomic_value, asset.decimal_precision)
    }

    #[inline]
    pub fn accounting_value(&self) -> AccountingValue {
        self.0 as f64 / Self::DIVIDER[self.1 as usize] as f64
    }

    #[inline]
    pub fn atomic_value(&self) -> AtomicValue {
        self.0
    }

    #[inline]
    pub fn decimal_precision(&self) -> u8 {
        self.1
    }
}

impl Add for AccountingAmount {
    type Output = AccountingAmount;
    fn add(self, rhs: Self) -> Self::Output {
        if self.decimal_precision() != rhs.decimal_precision() {
            panic!("Addition of amounts with different fractional bits")
        } else {
            AccountingAmount::from_fractioned_atomic_value(
                self.decimal_precision(),
                self.atomic_value() + rhs.atomic_value(),
            )
        }
    }
}

impl AddAssign for AccountingAmount {
    fn add_assign(&mut self, rhs: Self) {
        if self.decimal_precision() != rhs.decimal_precision() {
            panic!("Addition of amounts with different fractional bits")
        } else {
            self.0 += rhs.0
        }
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[display(Debug)]
#[repr(u8)]
pub enum SupplyMeasure {
    KnownCirculating = 0,
    TotalCirculating = 1,
    IssueLimit = 2,
}

// TODO: Add support for renominations, burn & replacements
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
    genesis: String,
    id: ContractId, // This is a unique primary key
    ticker: String,
    name: String,
    description: Option<String>,
    #[cfg_attr(feature = "serde", serde(flatten))]
    supply: Supply,
    #[cfg_attr(feature = "serde", serde(with = "As::<DisplayFromStr>"))]
    chain: Chain,
    decimal_precision: u8,
    date: NaiveDateTime,
    known_issues: Vec<Issue>,
    /// Specifies outpoints which when spent may indicate inflation happening
    /// up to specific amount.
    #[cfg_attr(
        feature = "serde",
        serde(with = "As::<BTreeMap<DisplayFromStr, DisplayFromStr>>")
    )]
    known_inflation: BTreeMap<bitcoin::OutPoint, AtomicValue>,
    /// Specifies outpoints controlling certain amounts of assets
    known_allocations: Vec<Allocation>,
}

impl Asset {
    #[inline]
    pub fn with(
        genesis: String,
        id: ContractId,
        ticker: String,
        name: String,
        description: Option<String>,
        supply: Supply,
        chain: Chain,
        decimal_precision: u8,
        date: NaiveDateTime,
        known_issues: Vec<Issue>,
        known_inflation: BTreeMap<bitcoin::OutPoint, AtomicValue>,
        known_allocations: Vec<Allocation>,
    ) -> Asset {
        Asset {
            genesis,
            id,
            ticker,
            name,
            description,
            supply,
            chain,
            decimal_precision,
            date,
            known_issues,
            known_inflation,
            known_allocations,
        }
    }

    pub fn accounting_supply(&self, measure: SupplyMeasure) -> AccountingValue {
        let value = match measure {
            SupplyMeasure::KnownCirculating => self.supply.known_circulating,
            SupplyMeasure::TotalCirculating => {
                match self.supply.total_circulating() {
                    None => return AccountingValue::NAN,
                    Some(supply) => supply,
                }
            }
            SupplyMeasure::IssueLimit => self.supply.issue_limit,
        };
        AccountingAmount::transmutate_into(self.decimal_precision, value)
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

    pub fn known_accounting_value(&self) -> AccountingValue {
        self.known_allocations
            .iter()
            .map(Allocation::value)
            .map(|atomic| {
                AccountingAmount::transmutate_into(
                    self.decimal_precision,
                    atomic,
                )
            })
            .sum()
    }

    pub fn known_filtered_accounting_value<F>(
        &self,
        filter: F,
    ) -> AccountingValue
    where
        F: Fn(&Allocation) -> bool,
    {
        self.known_allocations
            .iter()
            .filter(|allocation| filter(*allocation))
            .map(Allocation::value)
            .map(|atomic| {
                AccountingAmount::transmutate_into(
                    self.decimal_precision,
                    atomic,
                )
            })
            .sum()
    }
}

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[derive(
    Clone, Copy, Getters, PartialEq, Debug, Display, StrictEncode, StrictDecode,
)]
#[strict_encoding_crate(lnpbp::strict_encoding)]
#[display("{revealed_amount}@{node_id}#{index}>{outpoint}")]
pub struct Allocation {
    /// Unique primary key is `node_id` + `index`
    node_id: NodeId,

    /// Index of the assignment of ownership right type within the node
    index: u16,

    /// Copy of the outpoint from corresponding entry in
    /// [`Asset::known_allocations`]
    #[cfg_attr(feature = "serde", serde(with = "As::<DisplayFromStr>"))]
    outpoint: bitcoin::OutPoint,

    /// Revealed confidential amount consisting of an explicit atomic amount
    /// and Pedersen commitment blinding factor
    revealed_amount: value::Revealed,
}

impl Allocation {
    #[inline]
    pub fn with(
        node_id: NodeId,
        index: u16,
        outpoint: bitcoin::OutPoint,
        value: value::Revealed,
    ) -> Allocation {
        Allocation {
            node_id,
            index,
            outpoint,
            revealed_amount: value,
        }
    }

    #[inline]
    pub fn value(&self) -> AtomicValue {
        self.revealed_amount.value
    }
}

#[derive(
    Clone,
    Copy,
    Getters,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Display,
    Default,
    StrictEncode,
    StrictDecode,
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[strict_encoding_crate(lnpbp::strict_encoding)]
#[display("circulating {known_circulating}, max {issue_limit}")]
pub struct Supply {
    /// Sum of all issued amounts
    known_circulating: AtomicValue,

    /// Specifies if all issuances are known (i.e. there are data for issue
    /// state transitions for all already spent `inflation`
    /// single-use-seals). In this case `known_circulating` will be equal to
    /// `total_circulating`. The parameter is option since the fact that the
    /// UTXO is spend may be unknown without blockchain access
    is_issued_known: Option<bool>,

    /// We always know total supply, b/c even for assets without defined cap
    /// the cap *de facto* equals to u64::MAX
    issue_limit: AtomicValue,
}

impl Supply {
    #[inline]
    pub fn with(
        known_circulating: AtomicValue,
        is_issued_known: Option<bool>,
        issue_limit: AtomicValue,
    ) -> Supply {
        Supply {
            known_circulating,
            is_issued_known,
            issue_limit,
        }
    }

    #[inline]
    pub fn total_circulating(&self) -> Option<AtomicValue> {
        if self.is_issued_known.unwrap_or(false) {
            Some(self.known_circulating)
        } else {
            None
        }
    }
}

#[derive(
    Clone,
    Copy,
    Getters,
    Debug,
    PartialEq,
    Eq,
    Hash,
    Display,
    StrictEncode,
    StrictDecode,
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[strict_encoding_crate(lnpbp::strict_encoding)]
#[display("{id} -> {amount}")]
pub struct Issue {
    /// Unique primary key; equals to the state transition id that performs
    /// issuance (i.e. of `issue` type)
    id: NodeId,

    /// In db we can store it as a simple u64 field converting it on read/write
    /// using `decimal_precision` parameter of the asset
    amount: AtomicValue,

    /// Indicates transaction output which had an assigned inflation right and
    /// which spending produced this issue. `None` signifies that the issue
    /// was produced by genesis (i.e. it is a primary issue)
    #[cfg_attr(
        feature = "serde",
        serde(with = "As::<Option<DisplayFromStr>>")
    )]
    origin: Option<bitcoin::OutPoint>,
}

impl Issue {
    pub fn with(
        id: NodeId,
        amount: AtomicValue,
        origin: Option<bitcoin::OutPoint>,
    ) -> Issue {
        Issue { id, amount, origin }
    }

    #[inline]
    pub fn is_primary(&self) -> bool {
        self.origin.is_none()
    }

    #[inline]
    pub fn is_secondary(&self) -> bool {
        self.origin.is_some()
    }
}

impl Asset {
    #[inline]
    pub fn add_issue(&self, _issue: Transition) -> Supply {
        unimplemented!()
    }

    #[inline]
    pub fn allocations(&self, outpoint: bitcoin::OutPoint) -> Vec<Allocation> {
        self.known_allocations
            .iter()
            .filter(|a| a.outpoint == outpoint)
            .copied()
            .collect()
    }

    pub fn add_allocation(
        &mut self,
        outpoint: bitcoin::OutPoint,
        node_id: NodeId,
        index: u16,
        value: value::Revealed,
    ) -> bool {
        let new_allocation = Allocation {
            node_id,
            index,
            outpoint,
            revealed_amount: value,
        };
        if !self.known_allocations.contains(&new_allocation) {
            self.known_allocations.push(new_allocation);
            true
        } else {
            false
        }
    }

    pub fn remove_allocation(
        &mut self,
        outpoint: bitcoin::OutPoint,
        node_id: NodeId,
        index: u16,
        value: value::Revealed,
    ) -> bool {
        let old_allocation = Allocation {
            node_id,
            index,
            outpoint,
            revealed_amount: value,
        };
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
            for state in assignment.to_custom_state() {
                match state {
                    OwnedState::Revealed {
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
                    OwnedState::ConfidentialSeal { assigned_state, .. } => {
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

        let node_id = NodeId::from_inner(genesis.contract_id().into_inner());
        let issue = Issue {
            id: genesis.node_id(),
            amount: supply.clone(),
            origin: None, // This is a primary issue, so no origin here
        };
        let mut known_allocations = Vec::<Allocation>::new();
        for assignment in genesis.owned_rights_by_type(*OwnedRightsType::Assets)
        {
            assignment
                .to_discrete_state()
                .into_iter()
                .enumerate()
                .for_each(|(index, assign)| {
                    if let OwnedState::Revealed {
                        seal_definition:
                            seal::Revealed::TxOutpoint(outpoint_reveal),
                        assigned_state,
                    } = assign
                    {
                        known_allocations.push(Allocation {
                            node_id,
                            index: index as u16,
                            outpoint: outpoint_reveal.into(),
                            revealed_amount: assigned_state,
                        })
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
            description: genesis_meta
                .string(*FieldType::ContractText)
                .first()
                .cloned(),
            supply: Supply {
                known_circulating: supply,
                is_issued_known: None,
                issue_limit,
            },
            decimal_precision,
            date: NaiveDateTime::from_timestamp(
                *genesis_meta
                    .i64(*FieldType::Timestamp)
                    .first()
                    .ok_or(schema::Error::NotAllFieldsPresent)?,
                0,
            ),
            known_inflation,
            known_issues: vec![issue],
            // we assume that each genesis allocation with revealed amount
            // and known seal (they are always revealed together) belongs to us
            known_allocations,
        })
    }
}

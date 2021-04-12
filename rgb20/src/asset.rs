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

//! Data structures and APIs for working with RGB20 assets

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

use super::schema::{self, FieldType, OwnedRightsType, TransitionType};
use crate::{
    BurnReplace, Epoch, FractionalAmount, Issue, PreciseAmount, Supply,
    SupplyMeasure,
};

/// Errors generated during RGB20 asset information parsing from the underlying
/// genesis or consignment data
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Display, From, Error)]
#[display(doc_comments)]
pub enum Error {
    /// can't read asset data, since the provided information does not satisfy
    /// schema requirements
    UnsatisfiedSchemaRequirement,

    /// genesis schema id does not match any of RGB20 schemata
    WrongSchemaId,

    /// genesis defines a seal referencing witness transaction while there
    /// can't be a witness transaction for genesis
    #[from(WitnessVoutError)]
    GenesisSeal,

    /// epoch seal definition for node {0} contains confidential data
    EpochSealConfidential(NodeId),

    /// nurn & replace seal definition for node {0} contains confidential data
    BurnSealConfidential(NodeId),

    /// inflation assignment (seal or state) for node {0} contains confidential
    /// data
    InflationAssignmentConfidential(NodeId),

    /// Internal data inconsistency, as returned by the [`rgb::GraphAPI`]
    /// methods
    #[display(inner)]
    #[from]
    Inconsistency(rgb::ConsistencyError),

    /// not of all epochs referenced in burn or burn & replace operation
    /// history are known from the consignment
    NotAllEpochsExposed,
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

    /// Single-use-seal controlling the beginning of the first epoch
    epoch_opening_seal: Option<OutPoint>,

    /// Burn & replacement epochs, organized according to the witness txid.
    ///
    /// Witness transaction must be mined for the epoch to be real.
    /// One of the inputs of this transaction MUST spend UTXO defined as a
    /// seal closed by this epoch ([`Epoch::closes`])
    epochs: Vec<Epoch>,

    /// Detailed information about the asset supply (aggregated from the issue
    /// and burning information kept inside the epochs data)
    #[cfg_attr(feature = "serde", serde(flatten))]
    supply: Supply,

    /// Specifies outpoints controlling certain amounts of assets.
    ///
    /// NB: Information here does not imply that the outputs are owned by the
    /// current user or the owning transactions are mined/exist; this must be
    /// determined by the wallet and depends on specific medium (blockchain,
    /// LN)
    known_allocations: Vec<Allocation>,
}

impl Asset {
    /// Returns information (in atomic value units) about specific measure of
    /// the asset supply, if known, or `None` otherwise
    pub fn precise_supply(
        &self,
        measure: SupplyMeasure,
    ) -> Option<AtomicValue> {
        Some(match measure {
            SupplyMeasure::KnownCirculating => *self.supply.known_circulating(),
            SupplyMeasure::TotalCirculating => {
                match self.supply.total_circulating() {
                    None => return None,
                    Some(supply) => supply,
                }
            }
            SupplyMeasure::IssueLimit => *self.supply.issue_limit(),
        })
    }

    /// Returns information in form of a float number about specific measure of
    /// the asset supply, if known, or [`f64::NAN`] otherwise
    pub fn fractional_supply(
        &self,
        measure: SupplyMeasure,
    ) -> FractionalAmount {
        let value = match self.precise_supply(measure) {
            None => return FractionalAmount::NAN,
            Some(supply) => supply,
        };
        PreciseAmount::transmutate_into(value, self.decimal_precision)
    }

    /// Returns sum of all known allocations, in atomic value units
    #[inline]
    pub fn known_value(&self) -> AtomicValue {
        self.known_allocations.iter().map(Allocation::value).sum()
    }

    /// Returns sum of known allocation after applying `filter` function. Useful
    /// for filtering UTXOs owned by the current wallet. The returned value is
    /// in atomic units (see [`AtomicValue`]
    pub fn known_filtered_value<F>(&self, filter: F) -> AtomicValue
    where
        F: Fn(&Allocation) -> bool,
    {
        self.known_allocations
            .iter()
            .filter(|allocation| filter(*allocation))
            .map(Allocation::value)
            .sum()
    }

    /// Returns sum of all known allocations, as a floating point value (see
    /// [`FractionalAmount`])
    pub fn known_amount(&self) -> FractionalAmount {
        self.known_allocations
            .iter()
            .map(Allocation::value)
            .map(|atomic| {
                PreciseAmount::transmutate_into(atomic, self.decimal_precision)
            })
            .sum()
    }

    /// Returns sum of known allocation after applying `filter` function. Useful
    /// for filtering UTXOs owned by the current wallet. The returned amount is
    /// a floating point number (see [`FractionalAmount`])
    pub fn known_filtered_amount<F>(&self, filter: F) -> FractionalAmount
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

    /// Returns outpoints which when spent may indicate inflation happening
    /// up to specific amount.
    ///
    /// NB: Not of all inflation controlling points may be known
    pub fn known_inflation(
        &self,
    ) -> BTreeMap<OutPoint, (AtomicValue, Vec<u16>)> {
        let mut inflation_list = BTreeMap::new();
        for issue in self.known_issues() {
            for (seal, data) in issue.inflation_assignments() {
                inflation_list.insert(*seal, data.clone());
            }
        }

        inflation_list
    }

    #[inline]
    /// Lists all known allocations for the given bitcoin transaction
    /// [`OutPoint`]
    pub fn outpoint_allocations(&self, outpoint: OutPoint) -> Vec<Allocation> {
        self.known_allocations
            .iter()
            .filter(|a| *a.outpoint() == outpoint)
            .copied()
            .collect()
    }

    /// Adds new allocation to the list of known allocations
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

    /// Adds issue to the list of known issues. This is an internal function
    /// which should not be used directly; instead construct the asset structure
    /// from the [`Consignment`] using [`Asset::try_from`] method.
    fn add_issue(
        &mut self,
        consignment: &Consignment,
        transition: &Transition,
        witness: Txid,
    ) -> Result<(), Error> {
        let closed_seals = consignment.seals_closed_with(
            transition.node_id(),
            *OwnedRightsType::Inflation,
            witness,
        )?;
        let issue = Issue::with(self.id, closed_seals, transition, witness)?;
        self.known_issues.push(issue);
        Ok(())
    }

    /// Adds an epoch to the list of known epochs. This is an internal function
    /// which should not be used directly; instead construct the asset structure
    /// from the [`Consignment`] using [`Asset::try_from`] method.
    fn add_epoch(
        &mut self,
        consignment: &Consignment,
        transition: &Transition,
        no: usize,
        operations: Vec<BurnReplace>,
        witness: Txid,
    ) -> Result<(), Error> {
        let id = transition.node_id();
        // 1. It must correctly extend known state, i.e. close UTXO for a seal
        //    defined by a state transition already belonging to the asset
        let closed_seal = consignment
            .seals_closed_with(id, *OwnedRightsType::OpenEpoch, witness)?
            .into_iter()
            .next()
            .ok_or(Error::Inconsistency(
                rgb::ConsistencyError::NoSealsClosed(
                    *OwnedRightsType::OpenEpoch,
                    id,
                ),
            ))?;
        let epoch = Epoch::with(
            self.id,
            no,
            closed_seal,
            transition,
            operations,
            witness,
        )?;
        self.epochs.insert(no as usize, epoch);
        Ok(())
    }
}

impl TryFrom<Genesis> for Asset {
    type Error = Error;

    fn try_from(genesis: Genesis) -> Result<Self, Self::Error> {
        if genesis.schema_id() != schema::schema().schema_id() {
            Err(Error::WrongSchemaId)?;
        }
        let genesis_meta = genesis.metadata();
        let decimal_precision = *genesis_meta
            .u8(*FieldType::Precision)
            .first()
            .ok_or(Error::UnsatisfiedSchemaRequirement)?;
        let supply = *genesis_meta
            .u64(*FieldType::IssuedSupply)
            .first()
            .ok_or(Error::UnsatisfiedSchemaRequirement)?;
        let mut issue_limit = 0;

        // Check if issue limit can be known
        for assignment in
            genesis.owned_rights_by_type(*OwnedRightsType::Inflation)
        {
            for state in assignment.to_data_assignment_vec() {
                match state {
                    Assignment::Revealed { assigned_state, .. }
                    | Assignment::ConfidentialSeal { assigned_state, .. } => {
                        if issue_limit < core::u64::MAX {
                            issue_limit += assigned_state
                                .u64()
                                .ok_or(Error::UnsatisfiedSchemaRequirement)?
                        };
                    }

                    _ => issue_limit = core::u64::MAX,
                }
            }
        }

        let epoch_opening_seal = genesis
            .revealed_seals_by_type(*OwnedRightsType::OpenEpoch)
            .map_err(|_| Error::EpochSealConfidential(genesis.node_id()))?
            .first()
            .copied()
            .map(|seal| seal.try_into())
            .transpose()?;

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
        Ok(Asset {
            genesis: genesis.to_string(),
            id: genesis.contract_id(),
            chain: genesis.chain().clone(),
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
            supply: Supply::with(supply, None, issue_limit),
            decimal_precision,
            date: DateTime::from_utc(
                NaiveDateTime::from_timestamp(
                    *genesis_meta
                        .i64(*FieldType::Timestamp)
                        .first()
                        .ok_or(Error::UnsatisfiedSchemaRequirement)?,
                    0,
                ),
                Utc,
            ),
            known_issues: vec![issue],
            // we assume that each genesis allocation with revealed amount
            // and known seal (they are always revealed together) belongs to us
            known_allocations,
            epochs: empty!(),
            epoch_opening_seal,
        })
    }
}

impl TryFrom<Consignment> for Asset {
    type Error = Error;

    fn try_from(consignment: Consignment) -> Result<Self, Self::Error> {
        // 1. Parse genesis
        let mut asset: Asset = consignment.genesis.clone().try_into()?;

        // 2. Parse burn & replacement operations
        let mut epoch_operations: BTreeMap<NodeId, Vec<BurnReplace>> = empty!();
        for transition in consignment.endpoint_transitions_by_types(&[
            *TransitionType::BurnAndReplace,
            *TransitionType::Burn,
        ]) {
            let mut ops = consignment
                .chain_iter(transition.node_id(), *OwnedRightsType::BurnReplace)
                .collect::<Vec<_>>();
            ops.reverse();
            if let Some((epoch, _)) = ops.pop() {
                let epoch_id = epoch.node_id();
                let mut operations = vec![];
                for (no, (transition, witness)) in ops.into_iter().enumerate() {
                    let id = transition.node_id();
                    let closed_seal = consignment
                        .seals_closed_with(
                            id,
                            *OwnedRightsType::BurnReplace,
                            witness,
                        )?
                        .into_iter()
                        .next()
                        .ok_or(Error::Inconsistency(
                            rgb::ConsistencyError::NoSealsClosed(
                                *OwnedRightsType::BurnReplace,
                                id,
                            ),
                        ))?;
                    operations.push(BurnReplace::with(
                        asset.id,
                        epoch_id,
                        no,
                        closed_seal,
                        transition,
                        witness,
                    )?)
                }
                epoch_operations.insert(epoch_id, operations);
            }
        }

        // 3. Parse epochs
        let epoch_transition = consignment
            .endpoint_transitions_by_type(*TransitionType::Epoch)
            .into_iter()
            .next();
        if let Some(epoch_transition) = epoch_transition {
            let mut chain = consignment
                .chain_iter(
                    epoch_transition.node_id(),
                    *OwnedRightsType::OpenEpoch,
                )
                .collect::<Vec<_>>();
            chain.reverse();
            for (no, (transition, witness)) in chain.into_iter().enumerate() {
                let epoch_id = transition.node_id();
                asset.add_epoch(
                    &consignment,
                    transition,
                    no,
                    epoch_operations.remove(&epoch_id).unwrap_or_default(),
                    witness,
                )?;
            }
        }

        if !epoch_operations.is_empty() {
            return Err(Error::NotAllEpochsExposed);
        }

        // 4. Parse secondary issues
        for (transition, witness) in
            consignment.transition_witness_iter(&[*TransitionType::Issue])
        {
            asset.add_issue(&consignment, transition, witness)?;
        }

        // 5. Parse renominations
        // TODO: Parse renominations

        // 6. Parse allocations
        for (transaction, witness) in consignment.transition_witness_iter(&[
            *TransitionType::Issue,
            *TransitionType::BurnAndReplace,
            *TransitionType::Transfer,
            *TransitionType::RightsSplit,
        ]) {
            for assignments in
                transaction.owned_rights_by_type(*OwnedRightsType::Assets)
            {
                for (index, (seal, state)) in assignments
                    .to_value_assignment_vec()
                    .into_iter()
                    .filter_map(Assignment::into_revealed)
                    .enumerate()
                {
                    asset.add_allocation(
                        seal.to_outpoint_reveal(witness).into(),
                        transaction.node_id(),
                        index as u16,
                        state,
                    );
                }
            }
        }

        Ok(asset)
    }
}

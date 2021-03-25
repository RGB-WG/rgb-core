// RGB standard library
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

use chrono::Utc;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;

use bitcoin::OutPoint;
use lnpbp::Chain;
use rgb::prelude::*;
use rgb::secp256k1zkp;

use super::schema::{self, FieldType, OwnedRightsType, TransitionType};
use super::{Allocation, Asset};

use crate::asset;

/// Errors happening during RGB-20 asset state transitions
#[derive(
    Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error,
)]
#[display(doc_comments)]
pub enum Error {
    /// input {0} is not related to the contract
    UnrelatedInput(OutPoint),

    /// sum of inputs and outputs is not equal
    InputsNotEqualOutputs,
}

impl Asset {
    pub fn issue(
        chain: Chain,
        ticker: String,
        name: String,
        description: Option<String>,
        precision: u8,
        allocation: Vec<(OutPoint, AtomicValue)>,
        inflation: BTreeMap<OutPoint, AtomicValue>,
        renomination: Option<OutPoint>,
        epoch: Option<OutPoint>,
    ) -> Result<(Asset, Genesis), asset::Error> {
        let now = Utc::now().timestamp();
        let mut metadata = type_map! {
            FieldType::Ticker => field!(String, ticker.to_uppercase()),
            FieldType::Name => field!(String, name),
            FieldType::Precision => field!(U8, precision),
            FieldType::Timestamp => field!(I64, now)
        };
        if let Some(description) = description {
            metadata.insert(
                *FieldType::RicardianContract,
                field!(String, description),
            );
        }

        let mut issued_supply = 0u64;
        let allocations = allocation
            .into_iter()
            .map(|(outpoint, value)| {
                issued_supply += value;
                (SealDefinition::TxOutpoint(outpoint.into()), value)
            })
            .collect();
        let mut owned_rights = BTreeMap::new();
        owned_rights.insert(
            *OwnedRightsType::Assets,
            Assignments::zero_balanced(
                vec![value::Revealed {
                    value: issued_supply,
                    blinding: secp256k1zkp::key::ONE_KEY.into(),
                }],
                allocations,
                vec![],
            ),
        );
        metadata.insert(*FieldType::IssuedSupply, field!(U64, issued_supply));

        if !inflation.is_empty() {
            owned_rights.insert(
                *OwnedRightsType::Inflation,
                Assignments::CustomData(
                    inflation
                        .into_iter()
                        .map(|(outpoint, value)| OwnedState::Revealed {
                            seal_definition: SealDefinition::TxOutpoint(
                                outpoint.into(),
                            ),
                            assigned_state: data::Revealed::U64(value),
                        })
                        .collect(),
                ),
            );
        }

        if let Some(outpoint) = renomination {
            owned_rights.insert(
                *OwnedRightsType::Renomination,
                Assignments::Declarative(vec![OwnedState::Revealed {
                    seal_definition: SealDefinition::TxOutpoint(
                        outpoint.into(),
                    ),
                    assigned_state: data::Void,
                }]),
            );
        }

        if let Some(outpoint) = epoch {
            owned_rights.insert(
                *OwnedRightsType::BurnReplace,
                Assignments::Declarative(vec![OwnedState::Revealed {
                    seal_definition: SealDefinition::TxOutpoint(
                        outpoint.into(),
                    ),
                    assigned_state: data::Void,
                }]),
            );
        }

        let genesis = Genesis::with(
            schema::schema().schema_id(),
            chain,
            metadata.into(),
            owned_rights,
            bset![],
            vec![],
        );

        let asset = Asset::try_from(genesis.clone())?;

        Ok((asset, genesis))
    }

    pub fn inflate(
        self,
        closing: BTreeSet<OutPoint>,
        next_inflation: BTreeMap<SealDefinition, AtomicValue>,
        allocations: BTreeMap<SealDefinition, AtomicValue>,
    ) -> Result<Transition, Error> {
        unimplemented!()
    }

    pub fn epoch(
        self,
        closing: OutPoint,
        next_epoch: Option<SealDefinition>,
        burning_seal: Option<SealDefinition>,
    ) -> Result<Transition, Error> {
        unimplemented!()
    }

    pub fn burn(
        self,
        closing: OutPoint,
        burned_value: AtomicValue,
        burned_utxos: BTreeSet<OutPoint>,
        next_burn: Option<SealDefinition>,
    ) -> Result<Transition, Error> {
        unimplemented!()
    }

    /// Function creates a fungible asset-specific state transition (i.e. RGB-20
    /// schema-based) given an asset information, inputs and desired outputs
    pub fn transfer(
        self,
        inputs: BTreeSet<OutPoint>,
        payment: BTreeMap<SealEndpoint, AtomicValue>,
        change: BTreeMap<SealDefinition, AtomicValue>,
    ) -> Result<Transition, Error> {
        // Collecting all input allocations
        let mut input_allocations = Vec::<Allocation>::new();
        for outpoint in inputs {
            let found = self.allocations(outpoint);
            if found.len() == 0 {
                Err(Error::UnrelatedInput(outpoint))?
            }
            input_allocations.extend(found);
        }
        // Computing sum of inputs
        let total_inputs = input_allocations
            .iter()
            .fold(0u64, |acc, alloc| acc + alloc.revealed_amount().value);

        let metadata = type_map! {};
        let mut total_outputs = 0;
        let allocations_ours = change
            .into_iter()
            .map(|(seal, value)| {
                total_outputs += value;
                (seal, value)
            })
            .collect();
        let allocations_theirs = payment
            .into_iter()
            .map(|(seal_proto, value)| {
                total_outputs += value;
                (seal_proto, value)
            })
            .collect();

        if total_inputs != total_outputs {
            Err(Error::InputsNotEqualOutputs)?
        }

        let input_amounts = input_allocations
            .iter()
            .map(|alloc| *alloc.revealed_amount())
            .collect();
        let assignments = type_map! {
            OwnedRightsType::Assets =>
            Assignments::zero_balanced(input_amounts, allocations_ours, allocations_theirs)
        };

        let mut parent = ParentOwnedRights::default();
        for alloc in input_allocations {
            parent
                .entry(*alloc.node_id())
                .or_insert(bmap! {})
                .entry(*OwnedRightsType::Assets)
                .or_insert(vec![])
                .push(*alloc.index());
        }

        let transition = Transition::with(
            *TransitionType::Transfer,
            metadata.into(),
            parent,
            assignments.into(),
            bset![].into(),
            vec![],
        );

        Ok(transition)
    }
}

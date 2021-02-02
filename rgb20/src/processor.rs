// RGB standard library
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

use chrono::Utc;
use std::collections::BTreeMap;
use std::convert::TryFrom;

use bitcoin::OutPoint;
use lnpbp::Chain;
use rgb::prelude::*;
use rgb::secp256k1zkp;

use super::schema::{self, FieldType, OwnedRightsType, TransitionType};
use super::{AccountingAmount, Allocation, Asset, ConsealCoins, SealCoins};

use crate::asset;

/// Erors happening during RGB-20 asset transfer operation
#[derive(
    Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error,
)]
#[display(doc_comments)]
pub enum TransferError {
    /// RGB-20 asset transfer error: unknown input {0}
    UnknownInput(OutPoint),

    /// RGB-20 asset transfer error: sum of inputs and outputs is not equal
    InputsNotEqualOutputs,
}

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
        metadata.insert(*FieldType::ContractText, field!(String, description));
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
                seal_definition: SealDefinition::TxOutpoint(outpoint.into()),
                assigned_state: data::Void,
            }]),
        );
    }

    if let Some(outpoint) = epoch {
        owned_rights.insert(
            *OwnedRightsType::BurnReplace,
            Assignments::Declarative(vec![OwnedState::Revealed {
                seal_definition: SealDefinition::TxOutpoint(outpoint.into()),
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

/// Function creates a fungible asset-specific state transition (i.e. RGB-20
/// schema-based) given an asset information, inputs and desired outputs
pub fn transfer(
    asset: &mut Asset,
    inputs: Vec<OutPoint>,
    ours: Vec<SealCoins>,
    theirs: Vec<ConsealCoins>,
) -> Result<Transition, TransferError> {
    // Collecting all input allocations
    let mut input_allocations = Vec::<Allocation>::new();
    for seal in &inputs {
        let found = asset.allocations(seal).clone();
        if found.len() == 0 {
            Err(TransferError::UnknownInput(*seal))?
        }
        input_allocations.extend(found);
    }
    // Computing sum of inputs
    let total_inputs = input_allocations
        .iter()
        .fold(0u64, |acc, alloc| acc + alloc.confidential_amount().value);

    let metadata = type_map! {};
    let mut total_outputs = 0;
    let allocations_ours = ours
        .into_iter()
        .map(|outcoins| {
            let amount = AccountingAmount::transmutate(
                *asset.fractional_bits(),
                outcoins.coins,
            );
            total_outputs += amount;
            (outcoins.seal_definition(), amount)
        })
        .collect();
    let allocations_theirs = theirs
        .into_iter()
        .map(|outcoincealed| {
            let amount = AccountingAmount::transmutate(
                *asset.fractional_bits(),
                outcoincealed.coins,
            );
            total_outputs += amount;
            (outcoincealed.seal_confidential, amount)
        })
        .collect();

    if total_inputs != total_outputs {
        Err(TransferError::InputsNotEqualOutputs)?
    }

    let input_amounts = input_allocations
        .iter()
        .map(|alloc| alloc.confidential_amount().clone())
        .collect();
    let assignments = type_map! {
        OwnedRightsType::Assets =>
        Assignments::zero_balanced(input_amounts, allocations_ours, allocations_theirs)
    };

    let mut parent = ParentOwnedRights::new();
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
        assignments,
        bset![],
        vec![],
    );

    Ok(transition)
}

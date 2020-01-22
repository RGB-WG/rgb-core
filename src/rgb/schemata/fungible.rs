// LNP/BP Rust Library
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


use std::{
    sync::Once,
    convert::TryFrom,
    collections::HashMap
};

use bitcoin::{
    OutPoint,
    util::uint::Uint256
};

use super::{
    Network,
    Schemata,
    super::state,
    super::schema::{
        *,
        Bits::*,
        Occurences::*,
        StateFormat::*,
        script::{
            Scripting,
            StandardProcedure::*,
            Procedure::*,
            Extensions::*
        }
    }
};
use crate::rgb::{SealError, BoundState};

#[non_exhaustive]
#[derive(Clone, PartialEq, PartialOrd, Debug, Display)]
#[display_from(Debug)]
pub enum Error {
    SealError(state::SealError)
}

impl From<state::SealError> for Error {
    fn from(error: SealError) -> Self {
        Self::SealError(error)
    }
}


/// Schema for fungible assets with possible secondary issuance and history pruning (standard RGB-1)
pub struct Rgb1();

impl Rgb1 {
    const PRIM_ISSUE_TS: usize = 0;
    const SEC_ISSUE_TS: usize = 0;
    const TRANSFER_TS: usize = 0;
    const PRINE_TS: usize = 0;

    const ISSUE_SEAL: usize = 0;
    const BALANCE_SEAL: usize = 1;
    const PRUNE_SEAL: usize = 2;

    fn balances_to_bound_state(balances: HashMap<OutPoint, state::Amount>) -> Result<state::State, Error> {
        let seals_count = balances.len();
        Ok(state::State::from_inner(
            balances.into_iter().try_fold(
                Vec::<BoundState>::with_capacity(seals_count),
                |mut bound_state, (outpoint, balance)| -> Result<Vec<BoundState>, Error> {
                    bound_state.push(state::BoundState {
                        id: state::SealId(Self::BALANCE_SEAL as u16),
                        seal: state::Seal::try_from(outpoint)?,
                        val: state::state::Value::Balance(balance)
                    });
                    Ok(bound_state)
                }
            )?
        ))
    }

    pub fn issue(network: Network, ticker: &str, name: &str, descr: Option<&str>,
                 balances: HashMap<OutPoint, state::Amount>, precision: u8,
                 supply: Option<Uint256>, dust: Option<Uint256>) -> Result<state::Transition, Error> {
        // TODO: Add ability to control secondary issuance and pruning

        // TODO: Add validation against the schema
        //let schema = Self::get_schema();
        //let ts_schema = &schema.transitions[PRIM_ISSUE_TS];

        let mut meta = state::Meta::from_inner(vec![
            state::MetaField { id: state::FieldId(0), val: state::fields::Value::Str(String::from(ticker)) },
            state::MetaField { id: state::FieldId(1), val: state::fields::Value::Str(String::from(name)) },
            state::MetaField { id: state::FieldId(5), val: state::fields::Value::U8(precision) },
            state::MetaField { id: state::FieldId(7), val: state::fields::Value::U8(network.into()) },
        ]);
        if let Some(descr) = descr {
            meta.as_mut().push(
                state::MetaField { id: state::FieldId(2), val: state::fields::Value::Str(String::from(descr)) }
            );
        }
        if let Some(supply) = supply {
            meta.as_mut().push(
                state::MetaField { id: state::FieldId(3), val: state::fields::Value::U256(supply) }
            );
        }
        if let Some(dust) = dust {
            meta.as_mut().push(
                state::MetaField { id: state::FieldId(5), val: state::fields::Value::U256(dust) }
            );
        }

        let state = Self::balances_to_bound_state(balances)?;

        Ok(state::Transition { meta, state, script: None })
    }

    pub fn transfer(balances: HashMap<OutPoint, state::Amount>) -> Result<state::Transition, Error> {
        let state = Self::balances_to_bound_state(balances)?;

        Ok(state::Transition { meta: state::Meta::default(), state, script: None })
    }
}

impl Schemata for Rgb1 {
    fn get_schema() -> &'static Schema {
        static ONCE: Once = Once::new();
        let mut schema: &'static Option<Schema> = &None;

        ONCE.call_once(|| {
            schema = Box::leak(Box::new(Some(Schema {
                seals: map!{
                    Self::ISSUE_SEAL => NoState,
                    Self::BALANCE_SEAL => Amount,
                    Self::PRUNE_SEAL => NoState
                },
                transitions: vec![
                    // Genesis state: primary issue
                    Transition {
                        closes: None,
                        fields: vec![
                            // Ticker
                            Field(FieldFormat::String(16), Once),
                            // Title
                            Field(FieldFormat::String(256), Once),
                            // Description
                            Field(FieldFormat::String(1024), NoneOrOnce),
                            // Total supply
                            Field(FieldFormat::Unsigned { bits: Bit256, min: None, max: None }, NoneOrOnce),
                            // Fractional bits
                            Field(FieldFormat::Unsigned { bits: Bit8, min: None, max: None }, Once),
                            // Dust limit
                            Field(FieldFormat::Unsigned { bits: Bit256, min: None, max: None }, NoneOrOnce),
                            // Network
                            Field(FieldFormat::Enum { values: Network::all_u8() }, Once),
                        ],
                        binds: map!{
                            Self::BALANCE_SEAL => OnceOrUpTo(None),
                            Self::ISSUE_SEAL => NoneOrOnce,
                            Self::PRUNE_SEAL => NoneOrOnce
                        },
                        scripting: Scripting {
                            validation: Standard(Rgb1Genesis),
                            extensions: ScriptsDenied
                        }
                    },
                    // Issuance transition: secondary issue
                    Transition {
                        closes: Some(map! {
                            Self::ISSUE_SEAL => Once
                        }),
                        fields: vec![],
                        binds: map!{
                            Self::BALANCE_SEAL => OnceOrUpTo(None),
                            Self::ISSUE_SEAL => NoneOrUpTo(None)
                        },
                        scripting: Scripting {
                            validation: Standard(Rgb1Issue),
                            extensions: ScriptsDenied
                        }
                    },
                    // Amount transition: asset transfers
                    Transition {
                        closes: Some(map!{
                            Self::BALANCE_SEAL => OnceOrUpTo(None)
                        }),
                        fields: vec![],
                        binds: map!{
                            Self::BALANCE_SEAL => NoneOrUpTo(None)
                        },
                        scripting: Scripting {
                            validation: Standard(Rgb1Transfer),
                            extensions: ScriptsDenied
                        }
                    },
                    // Pruning transition: asset re-issue
                    Transition {
                        closes: Some(map!{
                            Self::PRUNE_SEAL => NoneOrOnce
                        }),
                        fields: vec![],
                        binds: map!{
                            Self::BALANCE_SEAL => OnceOrUpTo(None),
                            Self::PRUNE_SEAL => Once
                        },
                        scripting: Scripting {
                            validation: Standard(Rgb1Prune),
                            extensions: ScriptsDenied
                        }
                    }
                ]
            })));
        });

        schema.as_ref().expect("This must be always initialized")
    }
}

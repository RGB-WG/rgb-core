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


use core::option::NoneError;
use std::{
    sync::Once,
    collections::HashMap
};
use rand::{thread_rng, Rng};

use super::Schemata;
use crate::bp::Network;
use crate::rgb::{
    self,
    state, data, seal, metadata,
    schema::{
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

#[non_exhaustive]
#[derive(Debug, Display, From)]
#[display_from(Debug)]
pub enum Error {
    SealError,

    #[derive_from]
    SealBlingingError(rand::Error)
}

impl From<NoneError> for Error {
    fn from(_: NoneError) -> Self {
        Self::SealError
    }
}


pub type Balances = HashMap<bitcoin::OutPoint, data::amount::Commitment>;

/// Schema for fungible assets with possible secondary issuance and history pruning (standard RGB-1)
pub struct Rgb1();

impl Rgb1 {
    const PRIM_ISSUE_TS: usize = 0;
    const SEC_ISSUE_TS: usize = 1;
    const TRANSFER_TS: usize = 2;
    const PRUNE_TS: usize = 3;

    const ISSUE_SEAL: usize = 0;
    const BALANCE_SEAL: usize = 1;
    const PRUNE_SEAL: usize = 2;

    const TICKER_FIELD: usize = 0;
    const TITLE_FIELD: usize = 1;
    const DESCRIPTION_FIELD: usize = 2;
    const TOTAL_SUPPLY_FIELD: usize = 3;
    const FRACTIONAL_BITS_FIELD: usize = 4;
    const DUST_LIMIT_FIELD: usize = 5;
    const NETWORK_FIELD: usize = 6;

    fn balances_to_bound_state(balances: Balances, change: HashMap<u16, data::amount::Commitment>) -> Result<state::State, Error> {
        let seals_count = balances.len() + change.len();
        let mut state: Vec<state::Partial> = balances.into_iter().try_fold(
            Vec::<state::Partial>::with_capacity(seals_count),
            |mut bound_state, (outpoint, balance)| -> Result<Vec<state::Partial>, Error> {
                let mut entropy = [0u64; 1];
                thread_rng().try_fill(&mut entropy)?;
                bound_state.push(state::Partial::State(state::Bound {
                    id: seal::Type(Self::BALANCE_SEAL as u16),
                    seal: rgb::Seal::maybe_from_outpoint(outpoint, entropy[0])?,
                    val: rgb::Data::Balance(balance)
                }));
                Ok(bound_state)
            }
        )?;
        state.extend(change.into_iter().map(|(vout, amount)| {
            state::Partial::State(state::Bound {
                id: seal::Type(Self::BALANCE_SEAL as u16),
                seal: rgb::Seal::witness(vout),
                val: rgb::Data::Balance(amount)
            })
        }).collect::<Vec<state::Partial>>());
        Ok(rgb::State::from_inner(state))
    }

    pub fn issue(network: Network, ticker: &str, name: &str, descr: Option<&str>,
                 balances: Balances, precision: u8,
                 supply: Option<u64>, dust: Option<u64>) -> Result<rgb::Transition, Error> {
        // TODO: Add ability to control secondary issuance and pruning

        // TODO: Add validation against the schema
        //let schema = Self::get_schema();
        //let ts_schema = &schema.transitions[PRIM_ISSUE_TS];

        let mut meta = rgb::Metadata::from_inner(vec![
            metadata::Field { id: metadata::Type(Self::TICKER_FIELD as u16), val: metadata::Value::Str(String::from(ticker)) },
            metadata::Field { id: metadata::Type(Self::TITLE_FIELD as u16), val: metadata::Value::Str(String::from(name)) },
            metadata::Field { id: metadata::Type(Self::FRACTIONAL_BITS_FIELD as u16), val: metadata::Value::U8(precision) },
            metadata::Field { id: metadata::Type(Self::NETWORK_FIELD as u16), val: metadata::Value::U32(network.into()) },
        ]);
        if let Some(descr) = descr {
            meta.as_mut().push(
                metadata::Field { id: metadata::Type(Self::DESCRIPTION_FIELD as u16), val: metadata::Value::Str(String::from(descr)) }
            );
        }
        if let Some(supply) = supply {
            // TODO: why is this optional?
            meta.as_mut().push(
                metadata::Field { id: metadata::Type(Self::TOTAL_SUPPLY_FIELD as u16), val: metadata::Value::U64(supply) }
            );
        }
        if let Some(dust) = dust {
            meta.as_mut().push(
                metadata::Field { id: metadata::Type(Self::DUST_LIMIT_FIELD as u16), val: metadata::Value::U64(dust) }
            );
        }

        let state = Self::balances_to_bound_state(balances, HashMap::new())?;

        Ok(rgb::Transition { id: Self::PRIM_ISSUE_TS, meta, state, script: None })
    }

    pub fn transfer(balances: Balances, change: HashMap<u16, data::amount::Commitment>) -> Result<rgb::Transition, Error> {
        let state = Self::balances_to_bound_state(balances, change)?;

        Ok(rgb::Transition { id: Self::TRANSFER_TS, meta: rgb::Metadata::default(), state, script: None })
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
                transitions: map!{
                    // Genesis state: primary issue
                    Self::PRIM_ISSUE_TS => Transition {
                        closes: None,
                        fields: map!{
                            // Ticker
                            Self::TICKER_FIELD => Field(FieldFormat::String(16), Once),
                            // Title
                            Self::TITLE_FIELD => Field(FieldFormat::String(256), Once),
                            // Description
                            Self::DESCRIPTION_FIELD => Field(FieldFormat::String(1024), NoneOrOnce),
                            // Total supply
                            Self::TOTAL_SUPPLY_FIELD => Field(FieldFormat::Unsigned { bits: Bit64, min: None, max: None }, NoneOrOnce),
                            // Fractional bits
                            Self::FRACTIONAL_BITS_FIELD => Field(FieldFormat::Unsigned { bits: Bit8, min: None, max: None }, Once),
                            // Dust limit
                            Self::DUST_LIMIT_FIELD => Field(FieldFormat::Unsigned { bits: Bit64, min: None, max: None }, NoneOrOnce),
                            // Network
                            Self::NETWORK_FIELD => Field(FieldFormat::Unsigned { bits: Bit32, min: None, max: None }, Once)
                        },
                        binds: map!{
                            Self::BALANCE_SEAL => OnceOrUpTo(None),
                            Self::ISSUE_SEAL => NoneOrOnce,
                            Self::PRUNE_SEAL => NoneOrOnce
                        }.into(),
                        scripting: Scripting {
                            validation: Standard(Rgb1Genesis),
                            extensions: ScriptsDenied
                        }
                    },
                    // Issuance transition: secondary issue
                    Self::SEC_ISSUE_TS => Transition {
                        closes: Some(map! {
                            Self::ISSUE_SEAL => Once
                        }.into()),
                        fields: map!{},
                        binds: map!{
                            Self::BALANCE_SEAL => OnceOrUpTo(None),
                            Self::ISSUE_SEAL => NoneOrUpTo(None)
                        }.into(),
                        scripting: Scripting {
                            validation: Standard(Rgb1Issue),
                            extensions: ScriptsDenied
                        }
                    },
                    // Amount transition: asset transfers
                    Self::TRANSFER_TS => Transition {
                        closes: Some(map!{
                            Self::BALANCE_SEAL => OnceOrUpTo(None)
                        }.into()),
                        fields: map!{},
                        binds: map!{
                            Self::BALANCE_SEAL => NoneOrUpTo(None)
                        }.into(),
                        scripting: Scripting {
                            validation: Standard(Rgb1Transfer),
                            extensions: ScriptsDenied
                        }
                    },
                    // Pruning transition: asset re-issue
                    Self::PRUNE_TS => Transition {
                        closes: Some(map!{
                            Self::PRUNE_SEAL => NoneOrOnce
                        }.into()),
                        fields: map!{},
                        binds: map!{
                            Self::BALANCE_SEAL => OnceOrUpTo(None),
                            Self::PRUNE_SEAL => Once
                        }.into(),
                        scripting: Scripting {
                            validation: Standard(Rgb1Prune),
                            extensions: ScriptsDenied
                        }
                    }
                }
            })));
        });

        schema.as_ref().expect("This must be always initialized")
    }
}

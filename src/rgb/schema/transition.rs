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


use std::io;
use std::collections::HashMap;

use super::{
    types::*,
    field::*,
    schema::SchemaError,
    script::Scripting,
};
use crate::rgb::{data, state, seal};
use crate::csv::{serialize::Commitment, Error};
use crate::common::wrapper::Wrapper;

#[derive(Clone, Debug, Display)]
#[display_from(Debug)]
pub struct Transition {
    pub closes: Option<SealsSchema>,
    pub fields: HashMap<usize, Field>,
    pub binds: SealsSchema,
    pub scripting: Scripting,
}

impl Commitment for Transition {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        self.closes.commitment_serialize(&mut e)?;
        self.fields.commitment_serialize(&mut e)?;
        self.binds.commitment_serialize(&mut e)?;
        self.scripting.commitment_serialize(&mut e)
    }

    fn commitment_deserialize<D: io::Read>(d: D) -> Result<Self, Error> {
        unimplemented!()
        /*
        let closes = commitment_deserialize::<Option<HashMap<usize, Occurences<u32>>>>(&mut d)?;
        let fields: Vec<Field> = commitment_deserialize(&mut d)?;
        let binds = commitment_deserialize::<HashMap<usize, Occurences<u32>>>(&mut d)?;
        let scripting: Scripting = commitment_deserialize(&mut d)?;
        Ok(Self { closes, fields, binds, scripting })
        */
    }
}

wrapper!(SealsSchema, _SealsSchemaPhantom, HashMap<usize, Occurences<u32>>, doc="");

impl Commitment for SealsSchema {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        self.as_ref().commitment_serialize(&mut e)
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let data: HashMap<usize, Occurences<u32>> = Commitment::commitment_deserialize(&mut d)?;
        Ok(data.into())
    }
}

impl SealsSchema {
    pub fn validate(&self, seals: &HashMap<usize, StateFormat>, state: Vec<&state::Partial>) -> Result<Vec<data::amount::Commitment>, SchemaError> {
        let mut output_commitments = Vec::new();

        // find invalid created seals
        for (index, partial) in state.iter().enumerate() {
            match partial {
                state::Partial::State(state::Bound{ id, val, .. }) => {
                    let usize_id = id.0 as usize;

                    // check if it's expected in this transition
                    self.get(&usize_id).ok_or(SchemaError::InvalidBoundSealId(*id))?;

                    // match with the provided data type
                    match (seals.get(&usize_id), val) {
                        (Some(StateFormat::NoState), data::Data::None) => {},
                        (Some(StateFormat::Amount), data::Data::Balance(commitment)) => {
                            data::amount::verify_bullet_proof(commitment).map_err(|_| SchemaError::InvalidOutputBalanceBulletProof(index))?;

                            output_commitments.push(commitment.clone());
                        },
                        (Some(StateFormat::Data), data::Data::Binary(_data)) => {
                            unimplemented!(); // TODO
                        },

                        (None, data) => return Err(SchemaError::InvalidBoundSealId(*id)),
                        (Some(state_format), data) => return Err(SchemaError::InvalidBoundSealValue(*id, *state_format, data.clone())),
                    }
                },
                state::Partial::Commitment(_) => unimplemented!(), // TODO
            }
        }
        // check created seals
        for (seal_type, occurences) in self.iter() {
            let count = state
                .iter()
                .filter(|m| {
                    match m {
                        state::Partial::State(state::Bound { id: seal_type, .. }) => true,
                        _ => false,
                    }
                })
                .count();

            occurences.check_count(count as u32)
                .map_err(|e| SchemaError::InvalidBoundSeal(seal::Type(*seal_type as u16), Box::new(SchemaError::OccurencesNotMet(e))))?;
        }

        Ok(output_commitments)
    }
}

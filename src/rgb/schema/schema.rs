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
    io,
    collections::HashMap
};

use bitcoin::hashes::{Hash, sha256t};

use super::{
    types::*,
    transition::*
};
use crate::rgb::{self, metadata, seal, data, state};
use crate::rgb::schema::script;
use crate::csv::{ConsensusCommit, serialize, Error};


#[derive(Clone, Debug, Display)]
#[display_from(Debug)]
pub enum ValidationError {
    InvalidValue(metadata::Value),
    MinMaxBoundsOnLargeInt,

    OccurencesNotMet(OccurencesError),

    UnknownField(metadata::Type),
    InvalidField(metadata::Type, Box<ValidationError>),

    InvalidTransitionId(usize),

    InvalidBoundSeal(seal::Type, Box<ValidationError>),
    InvalidBoundSealId(seal::Type),
    InvalidBoundSealValue(seal::Type, StateFormat, data::Data),
    InvalidOutputBalanceBulletProof(usize),
}

#[derive(Clone, Debug, Default)]
pub struct PartialValidation {
    pub closed_seals: Option<HashMap<usize, Occurences<u32>>>,
    pub total_output_amount: Option<data::PedersenCommitment>,
}

#[derive(Clone, Debug, Display)]
#[display_from(Debug)]
pub struct Schema {
    pub seals: HashMap<usize, StateFormat>,
    pub transitions: HashMap<usize, Transition>,
}

impl Schema {
    pub fn schema_id(&self) -> SchemaId {
        self.consensus_commit().expect("Schema with commit failures must nor be serialized")
    }

    pub fn begin_validation(&self, ts: &rgb::Transition) -> Result<PartialValidation, ValidationError> {
        let transition_schema = self.transitions.get(&ts.id).ok_or(ValidationError::InvalidTransitionId(ts.id))?;

        // we only support standard scripting with no extensions at the moment
        match transition_schema.scripting {
            script::Scripting { validation: script::Procedure::Standard(procedure), extensions: script::Extensions::ScriptsDenied } => procedure.validate(ts.script.as_ref())?,
            _ => panic!(format!("Unimplemented validation of: {:?}", transition_schema.scripting)),
        }

        // TODO: unsafe casting that will be removed if we switch to maps indexed by u16s

        // find invalid unknown fields
        for metadata::Field { id, .. } in ts.meta.iter() {
            transition_schema.fields.get(&(id.0 as usize)).ok_or(ValidationError::UnknownField(*id))?;
        }
        // check known fields
        for (field_type, field) in &transition_schema.fields {
            field.validate(metadata::Type(*field_type as u16), &ts.meta)?;
        }

        // find invalid created seals
        let mut output_commitments = Vec::new();
        for (index, partial) in ts.state.iter().enumerate() {
            match partial {
                state::Partial::State(state::Bound{ id, val, .. }) => {
                    let usize_id = id.0 as usize;

                    // check if it's expected in this transition
                    transition_schema.binds.get(&usize_id).ok_or(ValidationError::InvalidBoundSealId(*id))?;

                    // match with the provided data type
                    match (self.seals.get(&usize_id), val) {
                        (Some(StateFormat::NoState), data::Data::None) => {},
                        (Some(StateFormat::Amount), data::Data::Balance(commitment)) => {
                            data::amount::verify_bullet_proof(commitment).map_err(|_| ValidationError::InvalidOutputBalanceBulletProof(index))?;

                            output_commitments.push(commitment.clone());
                        },
                        (Some(StateFormat::Data), data::Data::Binary(_data)) => {
                            unimplemented!(); // TODO
                        },

                        (None, data) => return Err(ValidationError::InvalidBoundSealId(*id)),
                        (Some(state_format), data) => return Err(ValidationError::InvalidBoundSealValue(*id, *state_format, data.clone())),
                    }
                },
                state::Partial::Commitment(_) => unimplemented!(), // TODO
            }
        }
        // check created seals
        for (seal_type, occurences) in &transition_schema.binds {
            let count = ts.state
                .iter()
                .filter_map(|m| {
                    match m {
                        state::Partial::State(state::Bound { id: seal_type, .. }) => Some(()),
                        _ => None
                    }
                })
                .count();

            occurences.check_count(count as u32)
                .map_err(|e| ValidationError::InvalidBoundSeal(seal::Type(*seal_type as u16), Box::new(ValidationError::OccurencesNotMet(e))))?;
        }

        let total_output_amount = match output_commitments {
            x if x.is_empty() => None,
            data => Some(data.into_iter().fold(data::amount::zero_pedersen_commitment(), |acc, x| x + acc)),
        };

        Ok(PartialValidation::default())
    }
}

impl serialize::Commitment for Schema {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        self.seals.commitment_serialize(&mut e)?;
        self.transitions.commitment_serialize(&mut e)
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, Error> {
        Ok(Self {
            seals: <HashMap<usize, StateFormat>>::commitment_deserialize(&mut d)?,
            transitions: <HashMap<usize, Transition>>::commitment_deserialize(&mut d)?,
        })
    }
}

network_serialize_from_commitment!(Schema);

static MIDSTATE_SHEMAID: [u8; 32] = [
    25, 205, 224, 91, 171, 217, 131, 31, 140, 104, 5, 155, 127, 82, 14, 81, 58, 245, 79, 165, 114,
    243, 110, 60, 133, 174, 103, 187, 103, 230, 9, 106
];

tagged_hash!(SchemaId, SchemaIdTag, MIDSTATE_SHEMAID, doc="");

impl ConsensusCommit for Schema {
    type CommitmentHash = SchemaId;
}

#[cfg(test)]
#[allow(unused_imports)]
mod test {
    use crate::rgb;
    use crate::rgb::metadata;
    use crate::rgb::state::State;
    use crate::rgb::schema::*;
    use crate::rgb::schema::types::*;
    use crate::rgb::schema::script::*;
    use crate::rgb::script::*;
    use crate::rgb::schema::*;

    #[test]
    fn schema_test() {
        const TRANSITION_VAL: usize = 0;
        const FIELD_VAL: usize = 5;

        let schema_transition = Transition {
            closes: None,
            fields: map!{
                FIELD_VAL => Field(FieldFormat::String(10), Occurences::Once)
            },
            binds: map!{},
            scripting: Scripting {
                validation: Procedure::Standard(StandardProcedure::Rgb1Genesis),
                extensions: Extensions::ScriptsDenied,
            }
        };
        let schema = Schema {
            seals: map!{},
            transitions: map!{
                TRANSITION_VAL => schema_transition
            }
        };

        let meta = metadata::Metadata::from_inner(vec![
            metadata::Field{ id: metadata::Type(FIELD_VAL as u16), val: metadata::Value::Str("test".into()) },
        ]);
        let transition = rgb::Transition {
            id: 0,
            meta,
            state: State::from_inner(vec![]),
            script: None
        };

        println!("{:#?}", schema);
        println!("{:#?}", transition);

        println!("{:?}", schema.begin_validation(&transition));
    }
}

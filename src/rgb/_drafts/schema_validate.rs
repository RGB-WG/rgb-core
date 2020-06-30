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

impl StandardProcedure {
    pub fn validate(&self, _transition_script: Option<&rgb::Script>) -> Result<(), SchemaError> {
        // TODO: validate the script
        Ok(())
    }
}

impl SealsSchema {
    pub fn validate(
        &self,
        seals: &HashMap<usize, StateFormat>,
        state: Vec<&state::Partial>,
    ) -> Result<Vec<data::amount::Commitment>, SchemaError> {
        let mut output_commitments = Vec::new();

        // find invalid created seals
        for (index, partial) in state.iter().enumerate() {
            match partial {
                state::Partial::State(state::Bound { id, val, .. }) => {
                    let usize_id = id.0 as usize;

                    // check if it's expected in this transition
                    self.get(&usize_id)
                        .ok_or(SchemaError::InvalidBoundSealId(*id))?;

                    // match with the provided data type
                    match (seals.get(&usize_id), val) {
                        (Some(StateFormat::NoState), data::Data::None) => {}
                        (Some(StateFormat::Amount), data::Data::Balance(commitment)) => {
                            data::amount::verify_bullet_proof(commitment)
                                .map_err(|_| SchemaError::InvalidOutputBalanceBulletProof(index))?;

                            output_commitments.push(commitment.clone());
                        }
                        (Some(StateFormat::Data), data::Data::Binary(_data)) => {
                            unimplemented!(); // TODO
                        }

                        (None, data) => return Err(SchemaError::InvalidBoundSealId(*id)),
                        (Some(state_format), data) => {
                            return Err(SchemaError::InvalidBoundSealValue(
                                *id,
                                *state_format,
                                data.clone(),
                            ))
                        }
                    }
                }
                state::Partial::Commitment(_) => unimplemented!(), // TODO
            }
        }
        // check created seals
        for (seal_type, occurences) in self.iter() {
            let count = state
                .iter()
                .filter(|m| match m {
                    state::Partial::State(state::Bound { id: seal_type, .. }) => true,
                    _ => false,
                })
                .count();

            occurences.check_count(count as u32).map_err(|e| {
                SchemaError::InvalidBoundSeal(
                    seal::Type(*seal_type as u16),
                    Box::new(SchemaError::OccurencesNotMet(e)),
                )
            })?;
        }

        Ok(output_commitments)
    }
}

impl Schema {
    pub fn schema_id(&self) -> SchemaId {
        self.consensus_commit()
            .expect("Schema with commit failures must nor be serialized")
    }

    pub fn validate_transition(
        &self,
        ts: &rgb::Transition,
    ) -> Result<PartialValidation, SchemaError> {
        let transition_schema = self
            .transitions
            .get(&ts.id)
            .ok_or(SchemaError::InvalidTransitionId(ts.id))?;

        // we only support standard scripting with no extensions at the moment
        match transition_schema.scripting {
            script::Scripting {
                validation: script::Procedure::Standard(procedure),
                extensions: script::Extensions::ScriptsDenied,
            } => procedure.validate(ts.script.as_ref())?,
            _ => panic!(format!(
                "Unimplemented validation of: {:?}",
                transition_schema.scripting
            )),
        }

        // TODO: unsafe casting that will be removed if we switch to maps indexed by u16s

        // find invalid unknown fields
        for metadata::Field { id, .. } in ts.meta.iter() {
            transition_schema
                .fields
                .get(&(id.0 as usize))
                .ok_or(SchemaError::UnknownField(*id))?;
        }
        // check known fields
        for (field_type, field) in &transition_schema.fields {
            field.validate(metadata::Type(*field_type as u16), &ts.meta)?;
        }

        let output_commitments = transition_schema
            .binds
            .validate(&self.seals, ts.state.iter().collect())?
            .into_iter()
            .map(|cmt| cmt.commitment)
            .collect();
        println!("output_commitments = {:?}", output_commitments);
        //let total_output_amount = output_commitments.into_iter().fold(data::amount::zero_pedersen_commitment(), |acc, x| x + acc);

        Ok(PartialValidation {
            should_close: transition_schema.closes.clone(),
            output_commitments,
        })
    }
}

#[derive(Clone, Debug)]
pub struct PartialValidation {
    pub should_close: Option<SealsSchema>,
    pub output_commitments: Vec<data::PedersenCommitment>,
}

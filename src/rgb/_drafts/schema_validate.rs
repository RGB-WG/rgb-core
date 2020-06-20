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

impl FieldFormat {
    pub fn validate(&self, value: &Value) -> Result<(), SchemaError> {
        match (self, value) {
            (
                Self::Unsigned {
                    bits: Bits::Bit256,
                    min: None,
                    max: None,
                },
                Value::U256(_),
            ) => Ok(()),
            (
                Self::Unsigned {
                    bits: Bits::Bit256, ..
                },
                Value::U256(_),
            ) => Err(SchemaError::MinMaxBoundsOnLargeInt),
            (
                Self::Unsigned {
                    bits: Bits::Bit128,
                    min: None,
                    max: None,
                },
                Value::U128(_),
            ) => Ok(()),
            (
                Self::Unsigned {
                    bits: Bits::Bit128, ..
                },
                Value::U128(_),
            ) => Err(SchemaError::MinMaxBoundsOnLargeInt),
            (
                Self::Unsigned {
                    bits: Bits::Bit64,
                    min,
                    max,
                },
                Value::U64(val),
            ) if *val >= min.unwrap_or(0) && *val <= max.unwrap_or(u64::MAX) => Ok(()),
            (
                Self::Unsigned {
                    bits: Bits::Bit32,
                    min,
                    max,
                },
                Value::U32(val),
            ) if *val as u64 >= min.unwrap_or(0)
                && *val as u64 <= max.unwrap_or(u32::MAX as u64) =>
            {
                Ok(())
            }
            (
                Self::Unsigned {
                    bits: Bits::Bit16,
                    min,
                    max,
                },
                Value::U16(val),
            ) if *val as u64 >= min.unwrap_or(0)
                && *val as u64 <= max.unwrap_or(u16::MAX as u64) =>
            {
                Ok(())
            }
            (
                Self::Unsigned {
                    bits: Bits::Bit8,
                    min,
                    max,
                },
                Value::U8(val),
            ) if *val as u64 >= min.unwrap_or(0)
                && *val as u64 <= max.unwrap_or(u8::MAX as u64) =>
            {
                Ok(())
            }
            (
                Self::Integer {
                    bits: Bits::Bit64,
                    min,
                    max,
                },
                Value::I64(val),
            ) if *val >= min.unwrap_or(0) && *val <= max.unwrap_or(i64::MAX) => Ok(()),
            (
                Self::Integer {
                    bits: Bits::Bit32,
                    min,
                    max,
                },
                Value::I32(val),
            ) if *val as i64 >= min.unwrap_or(0)
                && *val as i64 <= max.unwrap_or(i32::MAX as i64) =>
            {
                Ok(())
            }
            (
                Self::Integer {
                    bits: Bits::Bit16,
                    min,
                    max,
                },
                Value::I16(val),
            ) if *val as i64 >= min.unwrap_or(0)
                && *val as i64 <= max.unwrap_or(i16::MAX as i64) =>
            {
                Ok(())
            }
            (
                Self::Integer {
                    bits: Bits::Bit8,
                    min,
                    max,
                },
                Value::I8(val),
            ) if *val as i64 >= min.unwrap_or(0)
                && *val as i64 <= max.unwrap_or(i8::MAX as i64) =>
            {
                Ok(())
            }
            (
                Self::Float {
                    bits: Bits::Bit64,
                    min,
                    max,
                },
                Value::F64(val),
            ) if *val >= min.unwrap_or(0.0) && *val <= max.unwrap_or(f64::MAX) => Ok(()),
            (
                Self::Float {
                    bits: Bits::Bit32,
                    min,
                    max,
                },
                Value::F32(val),
            ) if *val as f64 >= min.unwrap_or(0.0)
                && *val as f64 <= max.unwrap_or(f32::MAX as f64) =>
            {
                Ok(())
            }

            (Self::Enum { values }, Value::U8(val)) if values.contains(val) => Ok(()),
            (Self::String(max_len), Value::Str(string)) if string.len() <= *max_len as usize => {
                Ok(())
            }
            (Self::Bytes(max_len), Value::Bytes(bytes)) if bytes.len() <= *max_len as usize => {
                Ok(())
            }

            // TODO: other types when added to metadata::Value
            _ => Err(SchemaError::InvalidValue(value.clone())),
        }
    }
}

impl Field {
    pub fn validate(&self, field_type: Type, metadata: &Metadata) -> Result<(), SchemaError> {
        let count = metadata
            .iter()
            .filter_map(|m| {
                if m.id == field_type {
                    Some(&m.val)
                } else {
                    None
                }
            })
            .try_fold(0, |acc, val| {
                self.0.validate(&val).and_then(|_| Ok(acc + 1))
            })
            .map_err(|e| SchemaError::InvalidField(field_type, Box::new(e)))?;

        self.1.check_count(count).map_err(|e| {
            SchemaError::InvalidField(field_type, Box::new(SchemaError::OccurencesNotMet(e)))
        })
    }
}

#[cfg(test)]
#[allow(unused_imports)]
mod test {
    use super::super::types::*;
    use super::{Field, FieldFormat};
    use crate::rgb::metadata::{self, Metadata, Type, Value};

    #[test]
    fn test_validate_unsigned_256() {
        let field_format = FieldFormat::Unsigned {
            bits: Bits::Bit256,
            min: None,
            max: None,
        };
        let value = Value::U256(Default::default());
        field_format.validate(&value).unwrap();
    }
    #[test]
    #[should_panic(expected = "MinMaxBoundsOnLargeInt")]
    fn test_validate_unsigned_256_bounds() {
        let field_format = FieldFormat::Unsigned {
            bits: Bits::Bit256,
            min: Some(0),
            max: None,
        };
        let value = Value::U256(Default::default());
        field_format.validate(&value).unwrap();
    }

    #[test]
    fn test_validate_unsigned_64() {
        let field_format = FieldFormat::Unsigned {
            bits: Bits::Bit64,
            min: None,
            max: None,
        };
        let value = Value::U64(42424242);
        field_format.validate(&value).unwrap();
    }
    #[test]
    #[should_panic(expected = "InvalidValue(U64(42))")]
    fn test_validate_unsigned_64_min() {
        let field_format = FieldFormat::Unsigned {
            bits: Bits::Bit64,
            min: Some(69),
            max: None,
        };
        let value = Value::U64(42);
        field_format.validate(&value).unwrap();
    }
    #[test]
    fn test_validate_unsigned_64_min_max() {
        let field_format = FieldFormat::Unsigned {
            bits: Bits::Bit64,
            min: Some(42),
            max: Some(69),
        };
        let value = Value::U64(50);
        field_format.validate(&value).unwrap();
    }
    #[test]
    #[should_panic(expected = "InvalidValue(U32(42424242))")]
    fn test_validate_unsigned_64_wrong_type() {
        let field_format = FieldFormat::Unsigned {
            bits: Bits::Bit64,
            min: None,
            max: None,
        };
        let value = Value::U32(42424242);
        field_format.validate(&value).unwrap();
    }

    #[test]
    fn test_validate_enum() {
        let field_format = FieldFormat::Enum {
            values: vec![0, 1, 2, 3],
        };
        let value = Value::U8(2);
        field_format.validate(&value).unwrap();
    }
    #[test]
    #[should_panic(expected = "InvalidValue(U8(42))")]
    fn test_validate_enum_missing() {
        let field_format = FieldFormat::Enum {
            values: vec![0, 1, 2, 3],
        };
        let value = Value::U8(42);
        field_format.validate(&value).unwrap();
    }

    #[test]
    fn test_validate_string() {
        let field_format = FieldFormat::String(5);
        let value = Value::Str("test".into());
        field_format.validate(&value).unwrap();
    }
    #[test]
    #[should_panic(expected = "InvalidValue(Str(\"testtest\"))")]
    fn test_validate_string_too_long() {
        let field_format = FieldFormat::String(5);
        let value = Value::Str("testtest".into());
        field_format.validate(&value).unwrap();
    }

    #[test]
    fn test_validate_bytes() {
        let field_format = FieldFormat::Bytes(5);
        let value = Value::Bytes(vec![0x00, 0x11].into_boxed_slice());
        field_format.validate(&value).unwrap();
    }
    #[test]
    #[should_panic(expected = "InvalidValue(Bytes([0, 0, 0, 0]))")]
    fn test_validate_bytes_too_long() {
        let field_format = FieldFormat::Bytes(3);
        let value = Value::Bytes(vec![0x00; 4].into_boxed_slice());
        field_format.validate(&value).unwrap();
    }

    #[test]
    fn test_validate_metadata_empty() {
        let field = Field(
            FieldFormat::Unsigned {
                bits: Bits::Bit64,
                min: None,
                max: None,
            },
            Occurences::NoneOrOnce,
        );
        let metadata = Metadata::from_inner(vec![]);
        field.validate(Type(0), &metadata).unwrap()
    }

    #[test]
    fn test_validate_metadata_simple() {
        let field = Field(
            FieldFormat::Unsigned {
                bits: Bits::Bit64,
                min: None,
                max: None,
            },
            Occurences::NoneOrOnce,
        );
        let metadata = Metadata::from_inner(vec![metadata::Field {
            id: Type(0),
            val: Value::U64(42),
        }]);
        field.validate(Type(0), &metadata).unwrap()
    }

    #[test]
    #[should_panic(
        expected = "InvalidField(Type(0), OccurencesNotMet(OccurencesError { expected: NoneOrOnce, found: 2 })"
    )]
    fn test_validate_metadata_fail_too_many() {
        let field = Field(
            FieldFormat::Unsigned {
                bits: Bits::Bit64,
                min: None,
                max: None,
            },
            Occurences::NoneOrOnce,
        );
        let metadata = Metadata::from_inner(vec![
            metadata::Field {
                id: Type(0),
                val: Value::U64(0),
            },
            metadata::Field {
                id: Type(0),
                val: Value::U64(42),
            },
        ]);
        field.validate(Type(0), &metadata).unwrap()
    }

    #[test]
    #[should_panic(expected = "InvalidField(Type(0), InvalidValue(U32(42)))")]
    fn test_validate_metadata_fail_invalid_value() {
        let field = Field(
            FieldFormat::Unsigned {
                bits: Bits::Bit64,
                min: None,
                max: None,
            },
            Occurences::NoneOrOnce,
        );
        let metadata = Metadata::from_inner(vec![metadata::Field {
            id: Type(0),
            val: Value::U32(42),
        }]);
        field.validate(Type(0), &metadata).unwrap()
    }
}

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

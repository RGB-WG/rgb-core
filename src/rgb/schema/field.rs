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

use super::types::*;
use super::schema::ValidationError;
use crate::rgb::metadata::{Metadata, Type, Value};
use crate::csv::serialize::*;


#[derive(Clone, Debug, Display)]
#[display_from(Debug)]
pub enum FieldFormat {
    Unsigned { bits: Bits, min: Option<u64>, max: Option<u64> },
    Integer { bits: Bits, min: Option<i64>, max: Option<i64> },
    Float { bits: Bits, min: Option<f64>, max: Option<f64> },
    Enum { values: Vec<u8> },
    String(u16),
    Bytes(u16),
    Digest(u16, DigestAlgorithm),
    ECPoint(ECPointSerialization),
    Signature(SignatureAlgorithm),
}

impl FieldFormat {
    pub fn validate(&self, value: &Value) -> Result<(), ValidationError> {
        match (self, value) {
            (FieldFormat::Unsigned { bits: Bits::Bit256, min: None, max: None }, Value::U256(_)) => Ok(()),
            (FieldFormat::Unsigned { bits: Bits::Bit256, .. }, Value::U256(_)) => Err(ValidationError::MinMaxBoundsOnLargeInt),
            (FieldFormat::Unsigned { bits: Bits::Bit128, min: None, max: None }, Value::U128(_)) => Ok(()),
            (FieldFormat::Unsigned { bits: Bits::Bit128, .. }, Value::U128(_)) => Err(ValidationError::MinMaxBoundsOnLargeInt),
            (FieldFormat::Unsigned { bits: Bits::Bit64, min, max }, Value::U64(val)) if *val >= min.unwrap_or(0) && *val <= max.unwrap_or(u64::MAX) => Ok(()),
            (FieldFormat::Unsigned { bits: Bits::Bit32, min, max }, Value::U32(val)) if *val as u64 >= min.unwrap_or(0) && *val as u64 <= max.unwrap_or(u32::MAX as u64) => Ok(()),
            (FieldFormat::Unsigned { bits: Bits::Bit16, min, max }, Value::U16(val)) if *val as u64 >= min.unwrap_or(0) && *val as u64 <= max.unwrap_or(u16::MAX as u64) => Ok(()),
            (FieldFormat::Unsigned { bits: Bits::Bit8, min, max }, Value::U8(val)) if *val as u64 >= min.unwrap_or(0) && *val as u64 <= max.unwrap_or(u8::MAX as u64) => Ok(()),
            (FieldFormat::Integer { bits: Bits::Bit64, min, max }, Value::I64(val)) if *val >= min.unwrap_or(0) && *val <= max.unwrap_or(i64::MAX) => Ok(()),
            (FieldFormat::Integer { bits: Bits::Bit32, min, max }, Value::I32(val)) if *val as i64 >= min.unwrap_or(0) && *val as i64 <= max.unwrap_or(i32::MAX as i64) => Ok(()),
            (FieldFormat::Integer { bits: Bits::Bit16, min, max }, Value::I16(val)) if *val as i64 >= min.unwrap_or(0) && *val as i64 <= max.unwrap_or(i16::MAX as i64) => Ok(()),
            (FieldFormat::Integer { bits: Bits::Bit8, min, max }, Value::I8(val)) if *val as i64 >= min.unwrap_or(0) && *val as i64 <= max.unwrap_or(i8::MAX as i64) => Ok(()),
            (FieldFormat::Float { bits: Bits::Bit64, min, max }, Value::F64(val)) if *val >= min.unwrap_or(0.0) && *val <= max.unwrap_or(f64::MAX) => Ok(()),
            (FieldFormat::Float { bits: Bits::Bit32, min, max }, Value::F32(val)) if *val as f64 >= min.unwrap_or(0.0) && *val as f64 <= max.unwrap_or(f32::MAX as f64) => Ok(()),

            (FieldFormat::Enum{ values }, Value::U8(val)) if values.contains(val) => Ok(()),
            (FieldFormat::String(max_len), Value::Str(string)) if string.len() <= *max_len as usize => Ok(()),
            (FieldFormat::Bytes(max_len), Value::Bytes(bytes)) if bytes.len() <= *max_len as usize => Ok(()),

            // TODO: other types when added to metadata::Value

            _ => Err(ValidationError::InvalidValue(value.clone()))
        }
    }
}

impl Commitment for FieldFormat {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(match self {
            Self::Unsigned { bits, min, max } => commitment_serialize_list!(e; 0x00u8, bits, min, max),
            Self::Integer { bits, min, max } => commitment_serialize_list!(e; 0x01u8, bits, min, max),
            Self::Float { bits, min, max } => unimplemented!(), // TODO: commitment_serialize_list!(e; 0x02u8, bits, min, max),
            Self::Enum { values } => commitment_serialize_list!(e; 0x10u8, values),
            Self::String(size) => commitment_serialize_list!(e; 0x20u8, size),
            Self::Bytes(size) => commitment_serialize_list!(e; 0x21u8, size),
            Self::Digest(bits, algo) => commitment_serialize_list!(e; 0x80u8, bits, algo),
            Self::ECPoint(algo) => commitment_serialize_list!(e; 0x81u8, algo),
            Self::Signature(algo) => commitment_serialize_list!(e; 0x82u8, algo),
            _ => panic!("New field formats can't appear w/o this library to be aware of")
        })
    }

    fn commitment_deserialize<D: io::Read>(d: D) -> Result<Self, Error> {
        unimplemented!()
    }
}


#[derive(Clone, Debug, Display)]
#[display_from(Debug)]
pub struct Field(pub FieldFormat, pub Occurences<u8>);

impl Field {
    pub fn validate(&self, field_type: Type, metadata: &Metadata) -> Result<(), ValidationError> {
        let count: u8 = metadata
            .iter()
            .filter_map(|m| {
                if m.id == field_type {
                    Some(&m.val)
                } else {
                    None
                }
            })
            .try_fold(0, |acc, val| self.0.validate(&val).and_then(|_| Ok(acc + 1)))?;

        match (self.1, count) {
            (Occurences::Once, 1) => Ok(()),
            (Occurences::NoneOrOnce, 0..=1 ) => Ok(()),
            (Occurences::OnceOrUpTo(None), 1 ..= u8::MAX) => Ok(()),
            (Occurences::OnceOrUpTo(Some(max)), x) if x > 0 && x <= max => Ok(()),
            (Occurences::NoneOrUpTo(None), 0 ..= u8::MAX) => Ok(()),
            (Occurences::NoneOrUpTo(Some(max)), x) if x <= max => Ok(()),
            _ => Err(ValidationError::InvalidFieldOccurences),
        }
    }
}

impl Commitment for Field {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        self.0.commitment_serialize(&mut e)?;
        self.1.commitment_serialize(&mut e)
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, Error> {
        Ok(Self(
            FieldFormat::commitment_deserialize(&mut d)?,
            Occurences::<u8>::commitment_deserialize(&mut d)?
        ))
    }
}

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


use std::{io, ops::Deref};

use bitcoin::util::uint::*;

use crate::csv::serialize;


#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Display)]
#[display_from(Debug)]
pub struct FieldId(pub u16);

impl serialize::commitment::Commitment for FieldId {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, serialize::Error> {
        self.0.commitment_serialize(&mut e)
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, serialize::Error> {
        Ok(FieldId(u16::commitment_deserialize(&mut d)?))
    }
}


#[non_exhaustive]
#[derive(Clone, PartialEq, PartialOrd, Debug, Display)]
#[display_from(Debug)]
pub enum Value {
    U8(u8), U16(u16), U32(u32), U64(u64), U128(Uint128), U256(Uint256),
    I8(i8), I16(i16), I32(i32), I64(i64),
    F32(f32), F64(f64),
    Bytes(Box<[u8]>),
    Str(String),
    // TODO: Add other supported field types according to the schema
}

const TAG_U8: u8 = 0x01u8;
const TAG_U16: u8 = 0x02u8;
const TAG_U32: u8 = 0x04u8;
const TAG_U64: u8 = 0x08u8;
const TAG_U128: u8 = 0x0Fu8;
const TAG_U256: u8 = 0x1Fu8;
const TAG_I8: u8 = 0x21u8;
const TAG_I16: u8 = 0x22u8;
const TAG_I32: u8 = 0x24u8;
const TAG_I64: u8 = 0x28u8;
const TAG_F32: u8 = 0x44u8;
const TAG_F64: u8 = 0x48u8;
const TAG_BYTES: u8 = 0x60u8;
const TAG_STR: u8 = 0x61u8;

impl serialize::commitment::Commitment for Value {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, serialize::Error> {
        use Value::*;
        Ok(match self {
            U8(v) => TAG_U8.commitment_serialize(&mut e)? + v.commitment_serialize(&mut e)?,
            U16(v) => TAG_U16.commitment_serialize(&mut e)? + v.commitment_serialize(&mut e)?,
            U32(v) => TAG_U32.commitment_serialize(&mut e)? + v.commitment_serialize(&mut e)?,
            U64(v) => TAG_U64.commitment_serialize(&mut e)? + v.commitment_serialize(&mut e)?,
            U128(v) => TAG_U128.commitment_serialize(&mut e)? + v.commitment_serialize(&mut e)?,
            U256(v) => TAG_U256.commitment_serialize(&mut e)? + v.commitment_serialize(&mut e)?,
            I8(v) => TAG_I8.commitment_serialize(&mut e)? + v.commitment_serialize(&mut e)?,
            I16(v) => TAG_I16.commitment_serialize(&mut e)? + v.commitment_serialize(&mut e)?,
            I32(v) => TAG_I32.commitment_serialize(&mut e)? + v.commitment_serialize(&mut e)?,
            I64(v) => TAG_I64.commitment_serialize(&mut e)? + v.commitment_serialize(&mut e)?,
            F32(v) => TAG_F32.commitment_serialize(&mut e)? + v.commitment_serialize(&mut e)?,
            F64(v) => TAG_F64.commitment_serialize(&mut e)? + v.commitment_serialize(&mut e)?,
            Bytes(bytes) => {
                TAG_BYTES.commitment_serialize(&mut e)? + bytes.deref().commitment_serialize(&mut e)?
            },
            Str(string) => {
                TAG_STR.commitment_serialize(&mut e)? + string.as_str().commitment_serialize(&mut e)?
            },
            _ => panic!("Unsupported metafield type; can't do a commitment serialization of the data"),
        })
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, serialize::Error> {
        use Value::*;
        Ok(match u8::commitment_deserialize(&mut d)? {
            TAG_U8 => U8(u8::commitment_deserialize(&mut d)?),
            TAG_U16 => U16(u16::commitment_deserialize(&mut d)?),
            TAG_U32 => U32(u32::commitment_deserialize(&mut d)?),
            TAG_U64 => U64(u64::commitment_deserialize(&mut d)?),
            TAG_U128 => U128(Uint128::commitment_deserialize(&mut d)?),
            TAG_U256 => U256(Uint256::commitment_deserialize(&mut d)?),
            TAG_I8 => I8(i8::commitment_deserialize(&mut d)?),
            TAG_I16 => I16(i16::commitment_deserialize(&mut d)?),
            TAG_I32 => I32(i32::commitment_deserialize(&mut d)?),
            TAG_I64 => I64(i64::commitment_deserialize(&mut d)?),
            TAG_F32 => F32(f32::commitment_deserialize(&mut d)?),
            TAG_F64 => F64(f64::commitment_deserialize(&mut d)?),
            TAG_BYTES => Bytes(Box::from(<&[u8]>::commitment_deserialize(&mut d)?)),
            TAG_STR => Str(String::from(<&str>::commitment_deserialize(&mut d)?)),
            _ => panic!("Unsupported metafield type; can't do a commitment deserialization of the data"),
        })
    }
}


pub struct MetaField {
    pub id: FieldId,
    pub val: Value,
}

impl serialize::commitment::Commitment for MetaField {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, serialize::Error> {
        Ok(self.id.commitment_serialize(&mut e)? + self.val.commitment_serialize(&mut e)?)
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, serialize::Error> {
        Ok(Self {
            id: FieldId::commitment_deserialize(&mut d)?,
            val: Value::commitment_deserialize(&mut d)?
        })
    }
}

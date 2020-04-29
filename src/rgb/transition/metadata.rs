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

use crate::rgb::schema::FieldId;
use bitcoin::hashes::{ripemd160, sha256};
use bitcoin::secp256k1;

#[derive(Clone, Debug, Display)]
#[display_from(Debug)]
#[non_exhaustive]
pub enum Value {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    // TODO: Add support later once bitcoin library will start supporting
    //       consensus-encoding of the native rust `u128` type
    // U128(u128),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    // TODO: Add support later once bitcoin library will start supporting
    //       consensus-encoding of the native rust `i128` type
    // I128(i128),
    F32(f32),
    F64(f64),
    Bytes(Vec<u8>),
    String(String),
    Ripemd160(ripemd160::Hash),
    Sha256(sha256::Hash),
    Secp256k1Pubkey(secp256k1::PublicKey),
    Secp256k1Signature(secp256k1::Signature),
}

#[derive(Clone, Debug, Display)]
#[display_from(Debug)]
pub struct Field {
    pub id: FieldId,
    pub val: Value,
}

// TODO: Automate this with #derive macros
mod strict_encoding {
    use super::*;
    use crate::strict_encoding::{Error, StrictDecode, StrictEncode};
    use num_derive::{FromPrimitive, ToPrimitive};
    use num_traits::{FromPrimitive, ToPrimitive};
    use std::io;

    #[derive(FromPrimitive, ToPrimitive)]
    #[repr(u8)]
    enum EncodingTag {
        U8 = 0b_0000_0000_u8,
        U16 = 0b_0000_0001_u8,
        U32 = 0b_0000_0010_u8,
        U64 = 0b_0000_0011_u8,
        // U128 = 0b_0000_0100_u8,
        I8 = 0b_0000_1000_u8,
        I16 = 0b_0000_1001_u8,
        I32 = 0b_0000_1010_u8,
        I64 = 0b_0000_1011_u8,
        // I128 = 0b_0000_1100_u8,
        F32 = 0b_0001_0010_u8,
        F64 = 0b_0001_0011_u8,
        Bytes = 0b_0010_0000_u8,
        String = 0b_0010_0001_u8,
        Ripemd160 = 0b_0100_0000_u8,
        Sha256 = 0b_0100_1000_u8,
        Secp256k1Pubkey = 0b_1000_0001_u8,
        Secp256k1Signature = 0b_1000_0010_u8,
    }
    impl_enum_strict_encoding!(EncodingTag);

    impl StrictEncode for Value {
        type Error = Error;

        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
            Ok(match self {
                Value::U8(val) => strict_encode_list!(e; EncodingTag::U8, val),
                Value::U16(val) => strict_encode_list!(e; EncodingTag::U16, val),
                Value::U32(val) => strict_encode_list!(e; EncodingTag::U32, val),
                Value::U64(val) => strict_encode_list!(e; EncodingTag::U64, val),
                // Value::U128(val) => strict_encode_list!(e; EncodingTag::U128, val),
                Value::I8(val) => strict_encode_list!(e; EncodingTag::I8, val),
                Value::I16(val) => strict_encode_list!(e; EncodingTag::I16, val),
                Value::I32(val) => strict_encode_list!(e; EncodingTag::I32, val),
                Value::I64(val) => strict_encode_list!(e; EncodingTag::I64, val),
                // Value::I128(val) => strict_encode_list!(e; EncodingTag::I128, val),
                Value::F32(val) => strict_encode_list!(e; EncodingTag::F32, val),
                Value::F64(val) => strict_encode_list!(e; EncodingTag::F64, val),
                Value::Bytes(val) => strict_encode_list!(e; EncodingTag::Bytes, val),
                Value::String(val) => strict_encode_list!(e; EncodingTag::String, val),
                Value::Ripemd160(val) => strict_encode_list!(e; EncodingTag::Ripemd160, val),
                Value::Sha256(val) => strict_encode_list!(e; EncodingTag::Sha256, val),
                Value::Secp256k1Pubkey(val) => {
                    strict_encode_list!(e; EncodingTag::Secp256k1Pubkey, val)
                }
                Value::Secp256k1Signature(val) => {
                    strict_encode_list!(e; EncodingTag::Secp256k1Signature, val)
                }
            })
        }
    }

    impl StrictDecode for Value {
        type Error = Error;

        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
            let format = EncodingTag::strict_decode(&mut d)?;
            Ok(match format {
                EncodingTag::U8 => Value::U8(u8::strict_decode(&mut d)?),
                EncodingTag::U16 => Value::U16(u16::strict_decode(&mut d)?),
                EncodingTag::U32 => Value::U32(u32::strict_decode(&mut d)?),
                EncodingTag::U64 => Value::U64(u64::strict_decode(&mut d)?),
                // EncodingTag::U128 => Value::U128(u128::strict_decode(&mut d)?),
                EncodingTag::I8 => Value::I8(i8::strict_decode(&mut d)?),
                EncodingTag::I16 => Value::I16(i16::strict_decode(&mut d)?),
                EncodingTag::I32 => Value::I32(i32::strict_decode(&mut d)?),
                EncodingTag::I64 => Value::I64(i64::strict_decode(&mut d)?),
                // EncodingTag::I128 => Value::I128(i128::strict_decode(&mut d)?),
                EncodingTag::F32 => Value::F32(f32::strict_decode(&mut d)?),
                EncodingTag::F64 => Value::F64(f64::strict_decode(&mut d)?),
                EncodingTag::Bytes => Value::Bytes(Vec::strict_decode(&mut d)?),
                EncodingTag::String => Value::String(String::strict_decode(&mut d)?),
                EncodingTag::Ripemd160 => Value::Ripemd160(ripemd160::Hash::strict_decode(&mut d)?),
                EncodingTag::Sha256 => Value::Sha256(sha256::Hash::strict_decode(&mut d)?),
                EncodingTag::Secp256k1Pubkey => {
                    Value::Secp256k1Pubkey(secp256k1::PublicKey::strict_decode(&mut d)?)
                }
                EncodingTag::Secp256k1Signature => {
                    Value::Secp256k1Signature(secp256k1::Signature::strict_decode(&mut d)?)
                }
            })
        }
    }

    impl StrictEncode for Field {
        type Error = Error;

        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
            Ok(strict_encode_list!(e; self.id, self.val))
        }
    }

    impl StrictDecode for Field {
        type Error = Error;

        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
            Ok(Self {
                id: FieldId::strict_decode(&mut d)?,
                val: Value::strict_decode(&mut d)?,
            })
        }
    }
}

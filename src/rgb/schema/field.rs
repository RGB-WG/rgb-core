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

use super::{elliptic_curve, Bits, DigestAlgorithm, EllipticCurve};
use std::collections::HashSet;

pub type FieldType = usize; // Here we can use usize since encoding/decoding makes sure that it's u16

#[derive(Clone, Debug, Display)]
#[display_from(Debug)]
#[non_exhaustive]
pub enum FieldFormat {
    Unsigned(Bits, u128, u128),
    Integer(Bits, i128, i128),
    Float(Bits, f64, f64),
    Enum(HashSet<u8>),
    String(u16),
    Bytes(u16),
    Digest(u16, DigestAlgorithm),
    PublicKey(EllipticCurve, elliptic_curve::PointSerialization),
    Signature(elliptic_curve::SignatureAlgorithm),
}

mod strict_encoding {
    use super::*;
    use crate::strict_encoding::{Error, StrictDecode, StrictEncode};
    use num_derive::{FromPrimitive, ToPrimitive};
    use num_traits::{FromPrimitive, ToPrimitive};

    #[derive(FromPrimitive, ToPrimitive)]
    #[repr(u8)]
    enum EncodingTag {
        Unsigned = 0,
        Integer = 1,
        Float = 2,
        Enum = 3,
        String = 4,
        Bytes = 5,
        Digest = 6,
        PublicKey = 7,
        Signature = 8,
    }
    impl_enum_strict_encoding!(EncodingTag);

    impl StrictEncode for FieldFormat {
        type Error = Error;

        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
            Ok(match self {
                Self::Unsigned(bits, min, max) => {
                    let (min, max) = (min.to_le_bytes().to_vec(), max.to_le_bytes().to_vec());
                    let len = (EncodingTag::Unsigned).strict_encode(&mut e)?
                        + bits.strict_encode(&mut e)?;
                    e.write_all(&min)?;
                    e.write_all(&max)?;
                    len + ::core::mem::size_of_val(&min) * 2
                }
                Self::Integer(bits, min, max) => {
                    let (min, max) = (min.to_le_bytes().to_vec(), max.to_le_bytes().to_vec());
                    let len = (EncodingTag::Integer).strict_encode(&mut e)?
                        + bits.strict_encode(&mut e)?;
                    e.write_all(&min)?;
                    e.write_all(&max)?;
                    len + ::core::mem::size_of_val(&min) * 2
                }
                Self::Float(bits, min, max) => {
                    let (min, max) = (min.to_le_bytes().to_vec(), max.to_le_bytes().to_vec());
                    let len =
                        (EncodingTag::Float).strict_encode(&mut e)? + bits.strict_encode(&mut e)?;
                    e.write_all(&min)?;
                    e.write_all(&max)?;
                    len + ::core::mem::size_of_val(&min) * 2
                }
                Self::Enum(values) => strict_encode_list!(e; EncodingTag::Enum, values),
                Self::String(size) => strict_encode_list!(e; EncodingTag::String, size),
                Self::Bytes(size) => strict_encode_list!(e; EncodingTag::Bytes, size),
                Self::Digest(bits, algo) => strict_encode_list!(e; EncodingTag::Digest, bits, algo),
                Self::PublicKey(curve, ser) => {
                    strict_encode_list!(e; EncodingTag::PublicKey, curve, ser)
                }
                Self::Signature(algo) => strict_encode_list!(e; EncodingTag::Signature, algo),
            })
        }
    }

    impl StrictDecode for FieldFormat {
        type Error = Error;

        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
            let format = EncodingTag::strict_decode(&mut d)?;
            Ok(match format {
                EncodingTag::Unsigned => {
                    let bits = Bits::strict_decode(&mut d)?;
                    let (min, max) = match bits {
                        Bits::Bit8 => {
                            let mut min = [0u8; 1];
                            let mut max = [0u8; 1];
                            d.read_exact(&mut min)?;
                            d.read_exact(&mut max)?;
                            (
                                u8::from_le_bytes(min) as u128,
                                u8::from_le_bytes(max) as u128,
                            )
                        }
                        Bits::Bit16 => {
                            let mut min = [0u8; 2];
                            let mut max = [0u8; 2];
                            d.read_exact(&mut min)?;
                            d.read_exact(&mut max)?;
                            (
                                u16::from_le_bytes(min) as u128,
                                u16::from_le_bytes(max) as u128,
                            )
                        }
                        Bits::Bit32 => {
                            let mut min = [0u8; 4];
                            let mut max = [0u8; 4];
                            d.read_exact(&mut min)?;
                            d.read_exact(&mut max)?;
                            (
                                u32::from_le_bytes(min) as u128,
                                u32::from_le_bytes(max) as u128,
                            )
                        }
                        Bits::Bit64 => {
                            let mut min = [0u8; 8];
                            let mut max = [0u8; 8];
                            d.read_exact(&mut min)?;
                            d.read_exact(&mut max)?;
                            (
                                u64::from_le_bytes(min) as u128,
                                u64::from_le_bytes(max) as u128,
                            )
                        }
                        Bits::Bit128 => {
                            let mut min = [0u8; 16];
                            let mut max = [0u8; 16];
                            d.read_exact(&mut min)?;
                            d.read_exact(&mut max)?;
                            (u128::from_le_bytes(min), u128::from_le_bytes(max))
                        }
                    };
                    FieldFormat::Unsigned(bits, min, max)
                }
                EncodingTag::Integer => {
                    let bits = Bits::strict_decode(&mut d)?;
                    let (min, max) = match bits {
                        Bits::Bit8 => {
                            let mut min = [0u8; 1];
                            let mut max = [0u8; 1];
                            d.read_exact(&mut min)?;
                            d.read_exact(&mut max)?;
                            (
                                i8::from_le_bytes(min) as i128,
                                i8::from_le_bytes(max) as i128,
                            )
                        }
                        Bits::Bit16 => {
                            let mut min = [0u8; 2];
                            let mut max = [0u8; 2];
                            d.read_exact(&mut min)?;
                            d.read_exact(&mut max)?;
                            (
                                i16::from_le_bytes(min) as i128,
                                i16::from_le_bytes(max) as i128,
                            )
                        }
                        Bits::Bit32 => {
                            let mut min = [0u8; 4];
                            let mut max = [0u8; 4];
                            d.read_exact(&mut min)?;
                            d.read_exact(&mut max)?;
                            (
                                i32::from_le_bytes(min) as i128,
                                i32::from_le_bytes(max) as i128,
                            )
                        }
                        Bits::Bit64 => {
                            let mut min = [0u8; 8];
                            let mut max = [0u8; 8];
                            d.read_exact(&mut min)?;
                            d.read_exact(&mut max)?;
                            (
                                i64::from_le_bytes(min) as i128,
                                i64::from_le_bytes(max) as i128,
                            )
                        }
                        Bits::Bit128 => {
                            let mut min = [0u8; 16];
                            let mut max = [0u8; 16];
                            d.read_exact(&mut min)?;
                            d.read_exact(&mut max)?;
                            (i128::from_le_bytes(min), i128::from_le_bytes(max))
                        }
                    };
                    FieldFormat::Integer(bits, min, max)
                }
                EncodingTag::Float => {
                    let bits = Bits::strict_decode(&mut d)?;
                    let (min, max) = match bits {
                        Bits::Bit32 => {
                            let mut min = [0u8; 4];
                            let mut max = [0u8; 4];
                            d.read_exact(&mut min)?;
                            d.read_exact(&mut max)?;
                            (
                                f32::from_le_bytes(min) as f64,
                                f32::from_le_bytes(max) as f64,
                            )
                        }
                        Bits::Bit64 => {
                            let mut min = [0u8; 8];
                            let mut max = [0u8; 8];
                            d.read_exact(&mut min)?;
                            d.read_exact(&mut max)?;
                            (f64::from_le_bytes(min), f64::from_le_bytes(max))
                        }
                        _ => Err(Error::DataIntegrityError(
                            "Unsupported float field bit size".to_string(),
                        ))?,
                    };
                    FieldFormat::Float(bits, min, max)
                }
                EncodingTag::Enum => FieldFormat::Enum(HashSet::<u8>::strict_decode(&mut d)?),
                EncodingTag::String => FieldFormat::String(u16::strict_decode(&mut d)?),
                EncodingTag::Bytes => FieldFormat::Bytes(u16::strict_decode(&mut d)?),
                EncodingTag::Digest => FieldFormat::Digest(
                    u16::strict_decode(&mut d)?,
                    DigestAlgorithm::strict_decode(&mut d)?,
                ),
                EncodingTag::PublicKey => FieldFormat::PublicKey(
                    EllipticCurve::strict_decode(&mut d)?,
                    elliptic_curve::PointSerialization::strict_decode(&mut d)?,
                ),
                EncodingTag::Signature => FieldFormat::Signature(
                    elliptic_curve::SignatureAlgorithm::strict_decode(&mut d)?,
                ),
            })
        }
    }
}

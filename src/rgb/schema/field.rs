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

use super::{elliptic_curve, Bits, DigestAlgorithm, EllipticCurve};
use std::collections::BTreeSet;
use std::io;

pub type FieldType = usize; // Here we can use usize since encoding/decoding makes sure that it's u16

#[derive(Clone, Debug, Display)]
#[display_from(Debug)]
#[non_exhaustive]
pub enum FieldFormat {
    Unsigned(Bits, u128, u128),
    Integer(Bits, i128, i128),
    Float(Bits, f64, f64),
    Enum(BTreeSet<u8>),
    String(u16),
    Bytes(u16),
    Digest(u16, DigestAlgorithm),
    PublicKey(EllipticCurve, elliptic_curve::PointSerialization),
    Signature(elliptic_curve::SignatureAlgorithm),
}

mod strict_encoding {
    use super::*;
    use crate::strict_encoding::{Error, StrictDecode, StrictEncode};
    use core::fmt::Debug;
    use core::ops::{Add, Bound, RangeBounds, RangeInclusive, Sub};
    use num_derive::{FromPrimitive, ToPrimitive};
    use num_traits::{Bounded, FromPrimitive, ToPrimitive};

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
            fn get_bounds<T>(
                provided: impl RangeBounds<T>,
                allowed: RangeInclusive<T>,
                exclusive: bool,
            ) -> Result<(T, T), Error>
            where
                T: Copy
                    + Bounded
                    + PartialOrd
                    + Debug
                    + Add<Output = T>
                    + Sub<Output = T>
                    + From<u8>,
            {
                let min = match provided.start_bound() {
                    Bound::Excluded(bound) | Bound::Included(bound) if !allowed.contains(bound) => {
                        Err(Error::DataIntegrityError(format!(
                            "Lower bound {:?} of the allowed range for \
                                 FieldFormat is outside of the possible values \
                                 of used number type",
                            bound,
                        )))?
                    }
                    Bound::Included(bound) => *bound,
                    Bound::Excluded(_) if !exclusive => Err(Error::DataIntegrityError(
                        "Excluded upper bound for the allowed range in \
                         FieldFormat does not make sense for float type"
                            .to_string(),
                    ))?,
                    Bound::Excluded(bound) => *bound + T::from(1),
                    Bound::Unbounded => *allowed.start(),
                };
                let max = match provided.end_bound() {
                    Bound::Excluded(bound) | Bound::Included(bound) if !allowed.contains(bound) => {
                        Err(Error::DataIntegrityError(format!(
                            "Upper bound {:?} of the allowed range for \
                                 FieldFormat is outside of the possible values \
                                 of used number type",
                            bound,
                        )))?
                    }
                    Bound::Included(bound) => *bound,
                    Bound::Excluded(_) if !exclusive => Err(Error::DataIntegrityError(
                        "Excluded upper bound for the allowed range in \
                         FieldFormat does not make sense for float type"
                            .to_string(),
                    ))?,
                    Bound::Excluded(bound) => *bound - T::from(1),
                    Bound::Unbounded => *allowed.end(),
                };
                Ok((min, max))
            }

            Ok(match self {
                FieldFormat::Unsigned(bits, min, max) => {
                    let allowed_bounds = match bits {
                        Bits::Bit8 => (core::u8::MIN as u128)..=(core::u8::MAX as u128),
                        Bits::Bit16 => (core::u16::MIN as u128)..=(core::u16::MAX as u128),
                        Bits::Bit32 => (core::u32::MIN as u128)..=(core::u32::MAX as u128),
                        Bits::Bit64 => (core::u64::MIN as u128)..=(core::u64::MAX as u128),
                        Bits::Bit128 => core::u128::MIN..=core::u128::MAX,
                    };
                    let (min, max) = get_bounds(min..max, allowed_bounds, true)?;
                    let (min, max) = (min.to_le_bytes().to_vec(), max.to_le_bytes().to_vec());
                    let len = (EncodingTag::Unsigned).strict_encode(&mut e)?
                        + bits.strict_encode(&mut e)?;
                    e.write_all(&min)?;
                    e.write_all(&max)?;
                    len + ::core::mem::size_of_val(&min) * 2
                }

                FieldFormat::Integer(bits, min, max) => {
                    let allowed_bounds = match bits {
                        Bits::Bit8 => (core::i8::MIN as i128)..=(core::i8::MAX as i128),
                        Bits::Bit16 => (core::i16::MIN as i128)..=(core::i16::MAX as i128),
                        Bits::Bit32 => (core::i32::MIN as i128)..=(core::i32::MAX as i128),
                        Bits::Bit64 => (core::i64::MIN as i128)..=(core::i64::MAX as i128),
                        Bits::Bit128 => core::i128::MIN..=core::i128::MAX,
                    };
                    let (min, max) = get_bounds(min..max, allowed_bounds, true)?;
                    let (min, max) = (min.to_le_bytes().to_vec(), max.to_le_bytes().to_vec());
                    let len = (EncodingTag::Integer).strict_encode(&mut e)?
                        + bits.strict_encode(&mut e)?;
                    e.write_all(&min)?;
                    e.write_all(&max)?;
                    len + ::core::mem::size_of_val(&min) * 2
                }

                FieldFormat::Float(bits, min, max) => {
                    let allowed_bounds = match bits {
                        Bits::Bit32 => (core::f32::MIN as f64)..=(core::f32::MAX as f64),
                        Bits::Bit64 => core::f64::MIN..=core::f64::MAX,
                        unsupported_bits => Err(Error::ValueOutOfRange(
                            "The provided number of bits for the floating number \
                             is not supported by the platform"
                                .to_string(),
                            32..64,
                            unsupported_bits.to_u64().unwrap(),
                        ))?,
                    };
                    let (min, max) = get_bounds(min..max, allowed_bounds, false)?;
                    let (min, max) = (min.to_le_bytes().to_vec(), max.to_le_bytes().to_vec());
                    let len =
                        (EncodingTag::Float).strict_encode(&mut e)? + bits.strict_encode(&mut e)?;
                    e.write_all(&min)?;
                    e.write_all(&max)?;
                    len + ::core::mem::size_of_val(&min) * 2
                }

                FieldFormat::Enum(values) => strict_encode_list!(e; EncodingTag::Enum, values),
                FieldFormat::String(size) => strict_encode_list!(e; EncodingTag::String, size),
                FieldFormat::Bytes(size) => strict_encode_list!(e; EncodingTag::Bytes, size),
                FieldFormat::Digest(bits, algo) => {
                    strict_encode_list!(e; EncodingTag::Digest, bits, algo)
                }
                FieldFormat::PublicKey(curve, ser) => {
                    strict_encode_list!(e; EncodingTag::PublicKey, curve, ser)
                }
                FieldFormat::Signature(algo) => {
                    strict_encode_list!(e; EncodingTag::Signature, algo)
                }
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
                EncodingTag::Enum => FieldFormat::Enum(BTreeSet::<u8>::strict_decode(&mut d)?),
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

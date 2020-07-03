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

use std::collections::BTreeSet;
use std::io;

use num_derive::{FromPrimitive, ToPrimitive};

use super::{elliptic_curve, script, Bits, DigestAlgorithm, EllipticCurve};

#[derive(Clone, PartialEq, Debug, Display)]
#[display_from(Debug)]
pub struct StateSchema {
    pub format: StateFormat,
    pub abi: script::AssignmentAbi,
}

#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Display, ToPrimitive, FromPrimitive,
)]
#[non_exhaustive]
#[repr(u8)]
#[display_from(Debug)]
pub enum StateType {
    Declarative = 0,
    DiscreteFiniteField = 1,
    CustomData = 2,
}

#[derive(Clone, PartialEq, Debug, Display)]
#[non_exhaustive]
#[display_from(Debug)]
pub enum StateFormat {
    Declarative,
    DiscreteFiniteField(DiscreteFiniteFieldFormat),
    CustomData(DataFormat),
}

#[derive(Clone, PartialEq, Debug, Display, ToPrimitive, FromPrimitive)]
#[display_from(Debug)]
#[non_exhaustive]
#[repr(u8)]
/// Today we support only a single format of confidential data, because of the
/// limitations of the underlying secp256k1-zkp library: it works only with
/// u64 numbers. Nevertheless, homomorphic commitments can be created to
/// everything that has up to 256 bits and commutative arithmetics, so in the
/// future we plan to support more types. We reserve this possibility by
/// internally encoding [ConfidentialFormat] with the same type specification
/// details as used for [DateFormat]
pub enum DiscreteFiniteFieldFormat {
    Unsigned64bit,
}

#[derive(Clone, PartialEq, Debug, Display)]
#[display_from(Debug)]
#[non_exhaustive]
pub enum DataFormat {
    Unsigned(Bits, u128, u128),
    Integer(Bits, i128, i128),
    Float(Bits, f64, f64),
    Enum(BTreeSet<u8>),
    String(u16),
    Bytes(u16),
    Digest(DigestAlgorithm),
    PublicKey(EllipticCurve, elliptic_curve::PointSerialization),
    Signature(elliptic_curve::SignatureAlgorithm),
}

// Convenience methods
impl DataFormat {
    #[inline]
    pub fn u8() -> Self {
        Self::Unsigned(Bits::Bit8, 0, core::u8::MAX as u128)
    }

    #[inline]
    pub fn u16() -> Self {
        Self::Unsigned(Bits::Bit16, 0, core::u16::MAX as u128)
    }

    #[inline]
    pub fn u32() -> Self {
        Self::Unsigned(Bits::Bit32, 0, core::u32::MAX as u128)
    }

    #[inline]
    pub fn u64() -> Self {
        Self::Unsigned(Bits::Bit64, 0, core::u64::MAX as u128)
    }

    // TODO: Add support later once bitcoin library will start supporting
    //       consensus-encoding of the native rust `u128` type
    //#[inline]
    //pub fn u128() -> Self {
    //    Self::Unsigned(Bits::Bit128, 0, core::u128::MAX)
    // }

    #[inline]
    pub fn i8() -> Self {
        Self::Integer(Bits::Bit8, 0, core::i8::MAX as i128)
    }

    #[inline]
    pub fn i16() -> Self {
        Self::Integer(Bits::Bit16, 0, core::i16::MAX as i128)
    }

    #[inline]
    pub fn i32() -> Self {
        Self::Integer(Bits::Bit32, 0, core::i32::MAX as i128)
    }

    #[inline]
    pub fn i64() -> Self {
        Self::Integer(Bits::Bit64, 0, core::i64::MAX as i128)
    }

    // TODO: Add support later once bitcoin library will start supporting
    //       consensus-encoding of the native rust `u128` type
    //#[inline]
    //pub fn i128() -> Self {
    //    Self::Integer(Bits::Bit128, 0, core::i128::MAX)
    //}

    #[inline]
    pub fn f32() -> Self {
        Self::Float(Bits::Bit32, 0.0, core::f32::MAX as f64)
    }

    #[inline]
    pub fn f64() -> Self {
        Self::Float(Bits::Bit64, 0.0, core::f64::MAX)
    }
}

mod strict_encoding {
    use super::*;
    use crate::strict_encoding::{Error, StrictDecode, StrictEncode};
    use core::convert::TryFrom;
    use core::fmt::Debug;
    use core::ops::{Add, Bound, RangeBounds, RangeInclusive, Sub};
    use num_derive::{FromPrimitive, ToPrimitive};
    use num_traits::{Bounded, FromPrimitive, ToPrimitive};

    impl StrictEncode for StateSchema {
        type Error = Error;

        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
            Ok(strict_encode_list!(e; self.format, self.abi))
        }
    }

    impl StrictDecode for StateSchema {
        type Error = Error;

        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
            Ok(Self {
                format: StateFormat::strict_decode(&mut d)?,
                abi: script::AssignmentAbi::strict_decode(&mut d)?,
            })
        }
    }

    impl_enum_strict_encoding!(StateType);

    impl StrictEncode for StateFormat {
        type Error = Error;

        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
            Ok(match self {
                StateFormat::Declarative => StateType::Declarative.strict_encode(e)?,
                StateFormat::DiscreteFiniteField(data) => {
                    strict_encode_list!(e; StateType::DiscreteFiniteField, data)
                }
                StateFormat::CustomData(data) => {
                    strict_encode_list!(e; StateType::CustomData, data)
                }
            })
        }
    }

    impl StrictDecode for StateFormat {
        type Error = Error;

        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
            let format = StateType::strict_decode(&mut d)?;
            Ok(match format {
                StateType::Declarative => StateFormat::Declarative,
                StateType::DiscreteFiniteField => {
                    StateFormat::DiscreteFiniteField(DiscreteFiniteFieldFormat::strict_decode(d)?)
                }
                StateType::CustomData => StateFormat::CustomData(DataFormat::strict_decode(d)?),
            })
        }
    }

    #[derive(Debug, Display, FromPrimitive, ToPrimitive)]
    #[display_from(Debug)]
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

    impl StrictEncode for DiscreteFiniteFieldFormat {
        type Error = Error;

        fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Self::Error> {
            match self {
                // Today we support only a single format of confidential data,
                // but tomorrow there might be more
                DiscreteFiniteFieldFormat::Unsigned64bit => {
                    DataFormat::Unsigned(Bits::Bit64, 0, core::u64::MAX as u128).strict_encode(e)
                }
            }
        }
    }

    impl StrictDecode for DiscreteFiniteFieldFormat {
        type Error = Error;

        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
            let format = EncodingTag::strict_decode(&mut d)?;
            match format {
                EncodingTag::Unsigned => {
                    let bits = Bits::strict_decode(&mut d)?;
                    let (min, max) = match bits {
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
                        invalid_bits => Err(Error::UnsupportedDataStructure(format!(
                            "confidential amounts can be only of u64 type; \
                             {} bit unsigned integers are not yet supported",
                            invalid_bits
                        )))?,
                    };
                    if min != 0 || max != core::u64::MAX as u128 {
                        Err(Error::UnsupportedDataStructure(format!(
                            "confidential amounts can be only of u64 type; \
                             allowed values should cover full u64 value range \
                             0..{}, however {}..{} was met",
                            core::u64::MAX,
                            min,
                            max
                        )))?
                    }
                    Ok(DiscreteFiniteFieldFormat::Unsigned64bit)
                }
                invalid_tag => Err(Error::UnsupportedDataStructure(format!(
                    "confidential amounts can be only of u64 type; \
                     {} type of the data is not yet supported",
                    invalid_tag
                ))),
            }
        }
    }

    impl StrictEncode for DataFormat {
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
                    + TryFrom<u8>
                    + Default,
            {
                let min = match provided.start_bound() {
                    Bound::Excluded(bound) | Bound::Included(bound) if !allowed.contains(bound) => {
                        Err(Error::DataIntegrityError(format!(
                            "Lower bound {:?} of the allowed range for \
                                 DataFormat is outside of the possible values \
                                 of used number type",
                            bound,
                        )))?
                    }
                    Bound::Included(bound) => *bound,
                    Bound::Excluded(_) if !exclusive => Err(Error::DataIntegrityError(
                        "Excluded upper bound for the allowed range in \
                         DataFormat does not make sense for float type"
                            .to_string(),
                    ))?,
                    Bound::Excluded(bound) => *bound + T::try_from(1).unwrap_or_default(),
                    Bound::Unbounded => *allowed.start(),
                };
                let max = match provided.end_bound() {
                    Bound::Excluded(bound) | Bound::Included(bound) if !allowed.contains(bound) => {
                        Err(Error::DataIntegrityError(format!(
                            "Upper bound {:?} of the allowed range for \
                                 DataFormat is outside of the possible values \
                                 of used number type",
                            bound,
                        )))?
                    }
                    Bound::Included(bound) => *bound,
                    Bound::Excluded(_) if !exclusive => Err(Error::DataIntegrityError(
                        "Excluded upper bound for the allowed range in \
                         DataFormat does not make sense for float type"
                            .to_string(),
                    ))?,
                    Bound::Excluded(bound) => *bound - T::try_from(1).unwrap_or_default(),
                    Bound::Unbounded => *allowed.end(),
                };
                Ok((min, max))
            }

            macro_rules! write_min_max {
                ($min:ident, $max:ident, $e:ident, $len:ident) => {
                    let (min, max) = ($min.to_le_bytes().to_vec(), $max.to_le_bytes().to_vec());
                    $e.write_all(&min)?;
                    $e.write_all(&max)?;
                    $len += ::core::mem::size_of_val(&min) * 2
                };
            }

            Ok(match self {
                DataFormat::Unsigned(bits, min, max) => {
                    let mut len = (EncodingTag::Unsigned).strict_encode(&mut e)?;
                    len += bits.strict_encode(&mut e)?;
                    match bits {
                        Bits::Bit8 => {
                            let min = u8::try_from(*min)
                                .map_err(|_| Error::ValueOutOfRange(
                                    "Minimum value for Unsigned data type are outside of bit dimension".to_string(), 
                                    (core::u8::MIN as u128)..(core::u8::MAX as u128), *min as u128))?;
                            let max = u8::try_from(*max)
                                .map_err(|_| Error::ValueOutOfRange(
                                    "Maximum value for Unsigned data type are outside of bit dimension".to_string(),
                                    (core::u8::MIN as u128)..(core::u8::MAX as u128), *max as u128))?;
                            let (min, max) =
                                get_bounds(min..=max, core::u8::MIN..=core::u8::MAX, true)?;
                            write_min_max!(min, max, e, len);
                        }
                        Bits::Bit16 => {
                            let min = u16::try_from(*min)
                                    .map_err(|_| Error::ValueOutOfRange(
                                        "Minimum value for Unsigned data type are outside of bit dimension".to_string(),
                                        (core::u16::MIN as u128)..(core::u16::MAX as u128), *min as u128))?;
                            let max = u16::try_from(*max)
                                    .map_err(|_| Error::ValueOutOfRange(
                                        "Maximum value for Unsigned data type are outside of bit dimension".to_string(),
                                        (core::u16::MIN as u128)..(core::u16::MAX as u128), *max as u128))?;
                            let (min, max) =
                                get_bounds(min..=max, core::u16::MIN..=core::u16::MAX, true)?;
                            write_min_max!(min, max, e, len);
                        }
                        Bits::Bit32 => {
                            let min = u32::try_from(*min)
                                    .map_err(|_| Error::ValueOutOfRange(
                                        "Minimum value for Unsigned data type are outside of bit dimension".to_string(),
                                        (core::u32::MIN as u128)..(core::u32::MAX as u128), *min as u128))?;
                            let max = u32::try_from(*max)
                                    .map_err(|_| Error::ValueOutOfRange(
                                        "Maximum value for Unsigned data type are outside of bit dimension".to_string(),
                                        (core::u32::MIN as u128)..(core::u32::MAX as u128), *max as u128))?;
                            let (min, max) =
                                get_bounds(min..=max, core::u32::MIN..=core::u32::MAX, true)?;
                            write_min_max!(min, max, e, len);
                        }
                        Bits::Bit64 => {
                            let min = u64::try_from(*min)
                                    .map_err(|_| Error::ValueOutOfRange(
                                        "Minimum value for Unsigned data type are outside of bit dimension".to_string(),
                                        (core::u64::MIN as u128)..(core::u64::MAX as u128), *min as u128))?;
                            let max = u64::try_from(*max)
                                    .map_err(|_| Error::ValueOutOfRange(
                                        "Maximum value for Unsigned data type are outside of bit dimension".to_string(),
                                        (core::u64::MIN as u128)..(core::u64::MAX as u128), *max as u128))?;
                            let (min, max) =
                                get_bounds(min..=max, core::u64::MIN..=core::u64::MAX, true)?;
                            write_min_max!(min, max, e, len);
                        }
                    }
                    len
                }

                DataFormat::Integer(bits, min, max) => {
                    let mut len = (EncodingTag::Integer).strict_encode(&mut e)?;
                    len += bits.strict_encode(&mut e)?;
                    match bits {
                        Bits::Bit8 => {
                            let min = i8::try_from(*min)
                                .map_err(|_| Error::ValueOutOfRange(
                                    "Minimum value for Integer data type are outside of bit dimension".to_string(),
                                    (core::i8::MIN as u128)..(core::i8::MAX as u128), *min as u128))?;
                            let max = i8::try_from(*max)
                                .map_err(|_| Error::ValueOutOfRange(
                                    "Maximum value for Integer data type are outside of bit dimension".to_string(),
                                    (core::i8::MIN as u128)..(core::i8::MAX as u128), *max as u128))?;
                            let (min, max) =
                                get_bounds(min..=max, core::i8::MIN..=core::i8::MAX, true)?;
                            write_min_max!(min, max, e, len);
                        }
                        Bits::Bit16 => {
                            let min = i16::try_from(*min)
                                .map_err(|_| Error::ValueOutOfRange(
                                    "Minimum value for Integer data type are outside of bit dimension".to_string(),
                                    (core::i16::MIN as u128)..(core::i16::MAX as u128), *min as u128))?;
                            let max = i16::try_from(*max)
                                .map_err(|_| Error::ValueOutOfRange(
                                    "Maximum value for Integer data type are outside of bit dimension".to_string(),
                                    (core::i16::MIN as u128)..(core::i16::MAX as u128), *max as u128))?;
                            let (min, max) =
                                get_bounds(min..=max, core::i16::MIN..=core::i16::MAX, true)?;
                            write_min_max!(min, max, e, len);
                        }
                        Bits::Bit32 => {
                            let min = i32::try_from(*min)
                                .map_err(|_| Error::ValueOutOfRange(
                                    "Minimum value for Integer data type are outside of bit dimension".to_string(),
                                    (core::i32::MIN as u128)..(core::i32::MAX as u128), *min as u128))?;
                            let max = i32::try_from(*max)
                                .map_err(|_| Error::ValueOutOfRange(
                                    "Maximum value for Integer data type are outside of bit dimension".to_string(),
                                    (core::i32::MIN as u128)..(core::i32::MAX as u128), *max as u128))?;
                            let (min, max) =
                                get_bounds(min..=max, core::i32::MIN..=core::i32::MAX, true)?;
                            write_min_max!(min, max, e, len);
                        }
                        Bits::Bit64 => {
                            let min = i64::try_from(*min)
                                .map_err(|_| Error::ValueOutOfRange(
                                    "Minimum value for Integer data type are outside of bit dimension".to_string(),
                                    (core::i64::MIN as u128)..(core::i64::MAX as u128), *min as u128))?;
                            let max = i64::try_from(*max)
                                .map_err(|_| Error::ValueOutOfRange(
                                    "Maximum value for Integer data type are outside of bit dimension".to_string(),
                                    (core::i64::MIN as u128)..(core::i64::MAX as u128), *max as u128))?;
                            let (min, max) =
                                get_bounds(min..=max, core::i64::MIN..=core::i64::MAX, true)?;
                            write_min_max!(min, max, e, len);
                        }
                    }
                    len
                }

                DataFormat::Float(bits, min, max) => {
                    let mut len = (EncodingTag::Float).strict_encode(&mut e)?;
                    len += bits.strict_encode(&mut e)?;
                    match bits {
                        Bits::Bit32 => {
                            let min = *min as f32;
                            let max = *max as f32;
                            let (min, max) =
                                get_bounds(min..=max, core::f32::MIN..=core::f32::MAX, true)?;
                            write_min_max!(min, max, e, len);
                        }
                        Bits::Bit64 => {
                            let (min, max) =
                                get_bounds(min..=max, core::f64::MIN..=core::f64::MAX, true)?;
                            write_min_max!(min, max, e, len);
                        }
                        unsupported_bits => Err(Error::ValueOutOfRange(
                            "The provided number of bits for the floating number \
                             is not supported by the platform"
                                .to_string(),
                            32..64,
                            unsupported_bits.to_u64().unwrap() as u128,
                        ))?,
                    }
                    len
                }

                DataFormat::Enum(values) => strict_encode_list!(e; EncodingTag::Enum, values),
                DataFormat::String(size) => strict_encode_list!(e; EncodingTag::String, size),
                DataFormat::Bytes(size) => strict_encode_list!(e; EncodingTag::Bytes, size),
                DataFormat::Digest(algo) => strict_encode_list!(e; EncodingTag::Digest, algo),
                DataFormat::PublicKey(curve, ser) => {
                    strict_encode_list!(e; EncodingTag::PublicKey, curve, ser)
                }
                DataFormat::Signature(algo) => strict_encode_list!(e; EncodingTag::Signature, algo),
            })
        }
    }

    impl StrictDecode for DataFormat {
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
                        } /*
                          Bits::Bit128 => {
                              let mut min = [0u8; 16];
                              let mut max = [0u8; 16];
                              d.read_exact(&mut min)?;
                              d.read_exact(&mut max)?;
                              (u128::from_le_bytes(min), u128::from_le_bytes(max))
                          }
                           */
                    };
                    DataFormat::Unsigned(bits, min, max)
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
                        } /*
                          Bits::Bit128 => {
                              let mut min = [0u8; 16];
                              let mut max = [0u8; 16];
                              d.read_exact(&mut min)?;
                              d.read_exact(&mut max)?;
                              (i128::from_le_bytes(min), i128::from_le_bytes(max))
                          }
                           */
                    };
                    DataFormat::Integer(bits, min, max)
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
                    DataFormat::Float(bits, min, max)
                }
                EncodingTag::Enum => DataFormat::Enum(BTreeSet::<u8>::strict_decode(&mut d)?),
                EncodingTag::String => DataFormat::String(u16::strict_decode(&mut d)?),
                EncodingTag::Bytes => DataFormat::Bytes(u16::strict_decode(&mut d)?),
                EncodingTag::Digest => DataFormat::Digest(DigestAlgorithm::strict_decode(&mut d)?),
                EncodingTag::PublicKey => DataFormat::PublicKey(
                    EllipticCurve::strict_decode(&mut d)?,
                    elliptic_curve::PointSerialization::strict_decode(&mut d)?,
                ),
                EncodingTag::Signature => DataFormat::Signature(
                    elliptic_curve::SignatureAlgorithm::strict_decode(&mut d)?,
                ),
            })
        }
    }
}

mod _validation {
    use amplify::AsAny;
    use core::any::Any;

    use super::*;
    use crate::client_side_validation::Conceal;
    use crate::rgb::{
        data, validation, Assignment, DeclarativeStrategy, HashStrategy, NodeId, PedersenStrategy,
        StateTypes,
    };
    use crate::strict_encoding::{Error as EncodingError, StrictDecode, StrictEncode};

    fn range_check<T, U>(
        type_id: usize,
        is_meta: bool,
        val: T,
        min: U,
        max: U,
        status: &mut validation::Status,
    ) where
        T: Copy,
        U: From<T>,
        U: PartialOrd,
    {
        if U::from(val) < min {
            status.add_failure(if is_meta {
                validation::Failure::SchemaMetaValueTooSmall(type_id)
            } else {
                validation::Failure::SchemaStateValueTooSmall(type_id)
            });
        }
        if U::from(val) > max {
            status.add_failure(if is_meta {
                validation::Failure::SchemaMetaValueTooLarge(type_id)
            } else {
                validation::Failure::SchemaStateValueTooLarge(type_id)
            });
        }
    }

    impl DataFormat {
        pub fn validate(&self, item_id: usize, data: &data::Revealed) -> validation::Status {
            let mut status = validation::Status::new();
            match (self, data) {
                (Self::Unsigned(Bits::Bit8, min, max), data::Revealed::U8(val)) => {
                    range_check(item_id, true, *val, *min, *max, &mut status)
                }
                (Self::Unsigned(Bits::Bit16, min, max), data::Revealed::U16(val)) => {
                    range_check(item_id, true, *val, *min, *max, &mut status)
                }
                (Self::Unsigned(Bits::Bit32, min, max), data::Revealed::U32(val)) => {
                    range_check(item_id, true, *val, *min, *max, &mut status)
                }
                (Self::Unsigned(Bits::Bit64, min, max), data::Revealed::U64(val)) => {
                    range_check(item_id, true, *val, *min, *max, &mut status)
                }
                (Self::Unsigned(bits, _, _), _) => {
                    status.add_failure(validation::Failure::SchemaMismatchedBits(item_id, *bits));
                }

                (Self::Integer(Bits::Bit8, min, max), data::Revealed::I8(val)) => {
                    range_check(item_id, true, *val, *min, *max, &mut status)
                }
                (Self::Integer(Bits::Bit16, min, max), data::Revealed::I16(val)) => {
                    range_check(item_id, true, *val, *min, *max, &mut status)
                }
                (Self::Integer(Bits::Bit32, min, max), data::Revealed::I32(val)) => {
                    range_check(item_id, true, *val, *min, *max, &mut status)
                }
                (Self::Integer(Bits::Bit64, min, max), data::Revealed::I64(val)) => {
                    range_check(item_id, true, *val, *min, *max, &mut status)
                }
                (Self::Integer(bits, _, _), _) => {
                    status.add_failure(validation::Failure::SchemaMismatchedBits(item_id, *bits));
                }

                (Self::Float(Bits::Bit32, min, max), data::Revealed::F32(val)) => {
                    range_check(item_id, true, *val, *min, *max, &mut status)
                }
                (Self::Float(Bits::Bit64, min, max), data::Revealed::F64(val)) => {
                    range_check(item_id, true, *val, *min, *max, &mut status)
                }
                (Self::Float(bits, _, _), _) => {
                    status.add_failure(validation::Failure::SchemaMismatchedBits(item_id, *bits));
                }

                (Self::Enum(value_set), data::Revealed::U8(val)) => {
                    if !value_set.contains(val) {
                        status
                            .add_failure(validation::Failure::SchemaWrongEnumValue(item_id, *val));
                    }
                }
                (Self::Enum(_), _) => {
                    status.add_failure(validation::Failure::SchemaMismatchedBits(
                        item_id,
                        Bits::Bit8,
                    ));
                }

                (Self::String(len), data::Revealed::String(val)) => {
                    if val.len() > *len as usize {
                        status.add_failure(validation::Failure::SchemaWrongDataLength(
                            item_id,
                            *len,
                            val.len(),
                        ));
                    }
                }
                (Self::Bytes(len), data::Revealed::Bytes(val)) => {
                    if val.len() > *len as usize {
                        status.add_failure(validation::Failure::SchemaWrongDataLength(
                            item_id,
                            *len,
                            val.len(),
                        ));
                    }
                }

                (Self::Digest(DigestAlgorithm::Sha256), data::Revealed::Sha256(_)) => {}
                (Self::Digest(DigestAlgorithm::Sha512), data::Revealed::Sha512(_)) => {}
                (Self::Digest(DigestAlgorithm::Bitcoin160), data::Revealed::Bitcoin160(_)) => {}
                (Self::Digest(DigestAlgorithm::Bitcoin256), data::Revealed::Bitcoin256(_)) => {}

                (
                    Self::PublicKey(EllipticCurve::Secp256k1, _),
                    data::Revealed::Secp256k1Pubkey(_),
                ) => {}
                (
                    Self::PublicKey(EllipticCurve::Curve25519, _),
                    data::Revealed::Ed25519Pubkey(_),
                ) => {}
                (
                    Self::Signature(elliptic_curve::SignatureAlgorithm::Ecdsa),
                    data::Revealed::Secp256k1ECDSASignature(_),
                ) => {}
                (
                    Self::Signature(elliptic_curve::SignatureAlgorithm::Ed25519),
                    data::Revealed::Ed25519Signature(_),
                ) => {}

                _ => {
                    status.add_failure(validation::Failure::SchemaMismatchedDataType(item_id));
                }
            }
            status
        }
    }

    impl StateFormat {
        pub fn validate<STATE>(
            &self,
            node_id: &NodeId,
            assignment_id: usize,
            data: &Assignment<STATE>,
        ) -> validation::Status
        where
            STATE: StateTypes,
            STATE::Confidential: PartialEq + Eq,
            STATE::Confidential: From<<STATE::Revealed as Conceal>::Confidential>,
            EncodingError: From<<STATE::Confidential as StrictEncode>::Error>
                + From<<STATE::Confidential as StrictDecode>::Error>
                + From<<STATE::Revealed as StrictEncode>::Error>
                + From<<STATE::Revealed as StrictDecode>::Error>,
        {
            let mut status = validation::Status::new();
            match data {
                Assignment::Confidential { assigned_state, .. }
                | Assignment::ConfidentialAmount { assigned_state, .. } => {
                    let a: &dyn Any = assigned_state.as_any();
                    match self {
                        StateFormat::Declarative => {
                            if a.downcast_ref::<<DeclarativeStrategy as StateTypes>::Confidential>()
                                .is_none()
                            {
                                status.add_failure(validation::Failure::SchemaMismatchedStateType(
                                    assignment_id,
                                ));
                            }
                        }
                        StateFormat::DiscreteFiniteField(_) => {
                            if a.downcast_ref::<<PedersenStrategy as StateTypes>::Confidential>()
                                .is_none()
                            {
                                status.add_failure(validation::Failure::SchemaMismatchedStateType(
                                    assignment_id,
                                ));
                            }
                            // TODO: When other homomorphic formats will be added,
                            //       add information to the status like with
                            //       hashed data below
                        }
                        StateFormat::CustomData(_) => {
                            match a.downcast_ref::<<HashStrategy as StateTypes>::Confidential>() {
                                None => {
                                    status.add_failure(
                                        validation::Failure::SchemaMismatchedStateType(
                                            assignment_id,
                                        ),
                                    );
                                }
                                Some(_) => {
                                    status.add_info(
                                        validation::Info::UncheckableConfidentialStateData(
                                            node_id.clone(),
                                            assignment_id,
                                        ),
                                    );
                                }
                            }
                        }
                    }
                }
                Assignment::Revealed { assigned_state, .. }
                | Assignment::ConfidentialSeal { assigned_state, .. } => {
                    let a: &dyn Any = assigned_state.as_any();
                    match self {
                        StateFormat::Declarative => {
                            if a.downcast_ref::<<DeclarativeStrategy as StateTypes>::Revealed>()
                                .is_none()
                            {
                                status.add_failure(validation::Failure::SchemaMismatchedStateType(
                                    assignment_id,
                                ));
                            }
                        }
                        StateFormat::DiscreteFiniteField(_format) => {
                            if a.downcast_ref::<<PedersenStrategy as StateTypes>::Revealed>()
                                .is_none()
                            {
                                status.add_failure(validation::Failure::SchemaMismatchedStateType(
                                    assignment_id,
                                ));
                            }
                            // TODO: When other homomorphic formats will be added,
                            //       add type check like with hashed data below
                        }
                        StateFormat::CustomData(format) => {
                            match a.downcast_ref::<<HashStrategy as StateTypes>::Revealed>() {
                                None => {
                                    status.add_failure(
                                        validation::Failure::SchemaMismatchedStateType(
                                            assignment_id,
                                        ),
                                    );
                                }
                                Some(data) => {
                                    status += format.validate(assignment_id, data);
                                }
                            }
                        }
                    }
                }
            }
            status
        }
    }
}

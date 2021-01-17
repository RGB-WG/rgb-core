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

#[derive(Clone, PartialEq, Debug, Display, StrictEncode, StrictDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[display(Debug)]
pub struct StateSchema {
    pub format: StateFormat,
    pub abi: script::AssignmentAbi,
}

#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Debug,
    Display,
    ToPrimitive,
    FromPrimitive,
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "snake_case")
)]
#[non_exhaustive]
#[repr(u8)]
#[display(Debug)]
pub enum StateType {
    Declarative = 0,
    DiscreteFiniteField = 1,
    CustomData = 2,
}

#[derive(Clone, PartialEq, Debug, Display)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "snake_case")
)]
#[non_exhaustive]
#[display(Debug)]
pub enum StateFormat {
    Declarative,
    DiscreteFiniteField(DiscreteFiniteFieldFormat),
    CustomData(DataFormat),
}

#[derive(Clone, PartialEq, Debug, Display, ToPrimitive, FromPrimitive)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "lowercase")
)]
#[display(Debug)]
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
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "lowercase")
)]
#[display(Debug)]
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
    TxOutPoint,
    Tx,
    Psbt,
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
    use core::convert::TryFrom;
    use core::fmt::Debug;
    use core::ops::{Add, Bound, RangeBounds, RangeInclusive, Sub};
    use lnpbp::strict_encoding::{Error, StrictDecode, StrictEncode};
    use num_derive::{FromPrimitive, ToPrimitive};
    use num_traits::{Bounded, ToPrimitive};

    impl_enum_strict_encoding!(StateType);

    impl StrictEncode for StateFormat {
        fn strict_encode<E: io::Write>(
            &self,
            mut e: E,
        ) -> Result<usize, Error> {
            Ok(match self {
                StateFormat::Declarative => {
                    StateType::Declarative.strict_encode(e)?
                }
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
        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
            let format = StateType::strict_decode(&mut d)?;
            Ok(match format {
                StateType::Declarative => StateFormat::Declarative,
                StateType::DiscreteFiniteField => {
                    StateFormat::DiscreteFiniteField(
                        DiscreteFiniteFieldFormat::strict_decode(d)?,
                    )
                }
                StateType::CustomData => {
                    StateFormat::CustomData(DataFormat::strict_decode(d)?)
                }
            })
        }
    }

    #[derive(Debug, Display, FromPrimitive, ToPrimitive)]
    #[display(Debug)]
    #[repr(u8)]
    enum EncodingTag {
        // Primitive types
        Unsigned = 0,
        Integer = 1,
        Float = 2,
        Enum = 3,
        String = 4,
        Bytes = 5,
        // Cryptographic types
        Digest = 0x10,
        PublicKey = 0x11,
        Signature = 0x12,
        // Composed types
        TxOutPoint = 0x20,
        Tx = 0x21,
        Psbt = 0x22,
    }
    impl_enum_strict_encoding!(EncodingTag);

    impl StrictEncode for DiscreteFiniteFieldFormat {
        fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
            match self {
                // Today we support only a single format of confidential data,
                // but tomorrow there might be more
                DiscreteFiniteFieldFormat::Unsigned64bit => {
                    DataFormat::Unsigned(Bits::Bit64, 0, core::u64::MAX as u128)
                        .strict_encode(e)
                }
            }
        }
    }

    impl StrictDecode for DiscreteFiniteFieldFormat {
        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
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
                        _ => Err(Error::UnsupportedDataStructure(
                            "confidential amounts can be only of u64 type; \
                             unsigned integers with different bit coin are not \
                             yet supported",
                        ))?,
                    };
                    if min != 0 || max != core::u64::MAX as u128 {
                        Err(Error::UnsupportedDataStructure(
                            "confidential amounts can be only of u64 type; \
                             allowed values should cover full u64 value range",
                        ))?
                    }
                    Ok(DiscreteFiniteFieldFormat::Unsigned64bit)
                }
                _ => Err(Error::UnsupportedDataStructure(
                    "confidential amounts can be only of u64 type; \
                     other types of the data is not yet supported",
                )),
            }
        }
    }

    impl StrictEncode for DataFormat {
        fn strict_encode<E: io::Write>(
            &self,
            mut e: E,
        ) -> Result<usize, Error> {
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
                    Bound::Excluded(bound) | Bound::Included(bound)
                        if !allowed.contains(bound) =>
                    {
                        Err(Error::DataIntegrityError(format!(
                            "Lower bound {:?} of the allowed range for \
                             DataFormat is outside of the possible values \
                             of used number type",
                            bound,
                        )))?
                    }
                    Bound::Included(bound) => *bound,
                    Bound::Excluded(_) if !exclusive => {
                        Err(Error::DataIntegrityError(
                            "Excluded upper bound for the allowed range in \
                             DataFormat does not make sense for float type"
                                .to_string(),
                        ))?
                    }
                    Bound::Excluded(bound) => {
                        *bound + T::try_from(1).unwrap_or_default()
                    }
                    Bound::Unbounded => *allowed.start(),
                };
                let max = match provided.end_bound() {
                    Bound::Excluded(bound) | Bound::Included(bound)
                        if !allowed.contains(bound) =>
                    {
                        Err(Error::DataIntegrityError(format!(
                            "Upper bound {:?} of the allowed range for \
                             DataFormat is outside of the possible values \
                             of used number type",
                            bound,
                        )))?
                    }
                    Bound::Included(bound) => *bound,
                    Bound::Excluded(_) if !exclusive => {
                        Err(Error::DataIntegrityError(
                            "Excluded upper bound for the allowed range in \
                             DataFormat does not make sense for float type"
                                .to_string(),
                        ))?
                    }
                    Bound::Excluded(bound) => {
                        *bound - T::try_from(1).unwrap_or_default()
                    }
                    Bound::Unbounded => *allowed.end(),
                };
                Ok((min, max))
            }

            macro_rules! write_min_max {
                ($min:ident, $max:ident, $e:ident, $len:ident) => {
                    let (min, max) = (
                        $min.to_le_bytes().to_vec(),
                        $max.to_le_bytes().to_vec(),
                    );
                    $e.write_all(&min)?;
                    $e.write_all(&max)?;
                    $len += ::core::mem::size_of_val(&$min)
                          + ::core::mem::size_of_val(&$max);
                };
            }

            Ok(match self {
                DataFormat::Unsigned(bits, min, max) => {
                    let mut len =
                        (EncodingTag::Unsigned).strict_encode(&mut e)?;
                    len += bits.strict_encode(&mut e)?;
                    match bits {
                        Bits::Bit8 => {
                            let min = u8::try_from(*min)
                                .map_err(|_| Error::ValueOutOfRange(
                                    "Minimum value for Unsigned data type are outside of bit dimension",
                                    (core::u8::MIN as u128)..(core::u8::MAX as u128), *min as u128))?;
                            let max = u8::try_from(*max)
                                .map_err(|_| Error::ValueOutOfRange(
                                    "Maximum value for Unsigned data type are outside of bit dimension",
                                    (core::u8::MIN as u128)..(core::u8::MAX as u128), *max as u128))?;
                            let (min, max) = get_bounds(
                                min..=max,
                                core::u8::MIN..=core::u8::MAX,
                                true,
                            )?;
                            write_min_max!(min, max, e, len);
                        }
                        Bits::Bit16 => {
                            let min = u16::try_from(*min)
                                    .map_err(|_| Error::ValueOutOfRange(
                                        "Minimum value for Unsigned data type are outside of bit dimension",
                                        (core::u16::MIN as u128)..(core::u16::MAX as u128), *min as u128))?;
                            let max = u16::try_from(*max)
                                    .map_err(|_| Error::ValueOutOfRange(
                                        "Maximum value for Unsigned data type are outside of bit dimension",
                                        (core::u16::MIN as u128)..(core::u16::MAX as u128), *max as u128))?;
                            let (min, max) = get_bounds(
                                min..=max,
                                core::u16::MIN..=core::u16::MAX,
                                true,
                            )?;
                            write_min_max!(min, max, e, len);
                        }
                        Bits::Bit32 => {
                            let min = u32::try_from(*min)
                                    .map_err(|_| Error::ValueOutOfRange(
                                        "Minimum value for Unsigned data type are outside of bit dimension",
                                        (core::u32::MIN as u128)..(core::u32::MAX as u128), *min as u128))?;
                            let max = u32::try_from(*max)
                                    .map_err(|_| Error::ValueOutOfRange(
                                        "Maximum value for Unsigned data type are outside of bit dimension",
                                        (core::u32::MIN as u128)..(core::u32::MAX as u128), *max as u128))?;
                            let (min, max) = get_bounds(
                                min..=max,
                                core::u32::MIN..=core::u32::MAX,
                                true,
                            )?;
                            write_min_max!(min, max, e, len);
                        }
                        Bits::Bit64 => {
                            let min = u64::try_from(*min)
                                    .map_err(|_| Error::ValueOutOfRange(
                                        "Minimum value for Unsigned data type are outside of bit dimension",
                                        (core::u64::MIN as u128)..(core::u64::MAX as u128), *min as u128))?;
                            let max = u64::try_from(*max)
                                    .map_err(|_| Error::ValueOutOfRange(
                                        "Maximum value for Unsigned data type are outside of bit dimension",
                                        (core::u64::MIN as u128)..(core::u64::MAX as u128), *max as u128))?;
                            let (min, max) = get_bounds(
                                min..=max,
                                core::u64::MIN..=core::u64::MAX,
                                true,
                            )?;
                            write_min_max!(min, max, e, len);
                        }
                    }
                    len
                }

                DataFormat::Integer(bits, min, max) => {
                    let mut len =
                        (EncodingTag::Integer).strict_encode(&mut e)?;
                    len += bits.strict_encode(&mut e)?;
                    match bits {
                        Bits::Bit8 => {
                            let min = i8::try_from(*min)
                                .map_err(|_| Error::ValueOutOfRange(
                                    "Minimum value for Integer data type are outside of bit dimension",
                                    (core::i8::MIN as u128)..(core::i8::MAX as u128), *min as u128))?;
                            let max = i8::try_from(*max)
                                .map_err(|_| Error::ValueOutOfRange(
                                    "Maximum value for Integer data type are outside of bit dimension",
                                    (core::i8::MIN as u128)..(core::i8::MAX as u128), *max as u128))?;
                            let (min, max) = get_bounds(
                                min..=max,
                                core::i8::MIN..=core::i8::MAX,
                                true,
                            )?;
                            write_min_max!(min, max, e, len);
                        }
                        Bits::Bit16 => {
                            let min = i16::try_from(*min)
                                .map_err(|_| Error::ValueOutOfRange(
                                    "Minimum value for Integer data type are outside of bit dimension",
                                    (core::i16::MIN as u128)..(core::i16::MAX as u128), *min as u128))?;
                            let max = i16::try_from(*max)
                                .map_err(|_| Error::ValueOutOfRange(
                                    "Maximum value for Integer data type are outside of bit dimension",
                                    (core::i16::MIN as u128)..(core::i16::MAX as u128), *max as u128))?;
                            let (min, max) = get_bounds(
                                min..=max,
                                core::i16::MIN..=core::i16::MAX,
                                true,
                            )?;
                            write_min_max!(min, max, e, len);
                        }
                        Bits::Bit32 => {
                            let min = i32::try_from(*min)
                                .map_err(|_| Error::ValueOutOfRange(
                                    "Minimum value for Integer data type are outside of bit dimension",
                                    (core::i32::MIN as u128)..(core::i32::MAX as u128), *min as u128))?;
                            let max = i32::try_from(*max)
                                .map_err(|_| Error::ValueOutOfRange(
                                    "Maximum value for Integer data type are outside of bit dimension",
                                    (core::i32::MIN as u128)..(core::i32::MAX as u128), *max as u128))?;
                            let (min, max) = get_bounds(
                                min..=max,
                                core::i32::MIN..=core::i32::MAX,
                                true,
                            )?;
                            write_min_max!(min, max, e, len);
                        }
                        Bits::Bit64 => {
                            let min = i64::try_from(*min)
                                .map_err(|_| Error::ValueOutOfRange(
                                    "Minimum value for Integer data type are outside of bit dimension",
                                    (core::i64::MIN as u128)..(core::i64::MAX as u128), *min as u128))?;
                            let max = i64::try_from(*max)
                                .map_err(|_| Error::ValueOutOfRange(
                                    "Maximum value for Integer data type are outside of bit dimension",
                                    (core::i64::MIN as u128)..(core::i64::MAX as u128), *max as u128))?;
                            let (min, max) = get_bounds(
                                min..=max,
                                core::i64::MIN..=core::i64::MAX,
                                true,
                            )?;
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
                             is not supported by the platform",
                            32..64,
                            unsupported_bits.to_u64().unwrap() as u128,
                        ))?,
                    }
                    len
                }

                DataFormat::Enum(values) => {
                    strict_encode_list!(e; EncodingTag::Enum, values)
                }
                DataFormat::String(size) => {
                    strict_encode_list!(e; EncodingTag::String, size)
                }
                DataFormat::Bytes(size) => {
                    strict_encode_list!(e; EncodingTag::Bytes, size)
                }
                DataFormat::Digest(algo) => {
                    strict_encode_list!(e; EncodingTag::Digest, algo)
                }
                DataFormat::PublicKey(curve, ser) => {
                    strict_encode_list!(e; EncodingTag::PublicKey, curve, ser)
                }
                DataFormat::Signature(algo) => {
                    strict_encode_list!(e; EncodingTag::Signature, algo)
                }
                DataFormat::TxOutPoint => {
                    EncodingTag::TxOutPoint.strict_encode(&mut e)?
                }
                DataFormat::Tx => EncodingTag::Tx.strict_encode(&mut e)?,
                DataFormat::Psbt => EncodingTag::Psbt.strict_encode(&mut e)?,
            })
        }
    }

    impl StrictDecode for DataFormat {
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
                EncodingTag::Enum => {
                    DataFormat::Enum(BTreeSet::<u8>::strict_decode(&mut d)?)
                }
                EncodingTag::String => {
                    DataFormat::String(u16::strict_decode(&mut d)?)
                }
                EncodingTag::Bytes => {
                    DataFormat::Bytes(u16::strict_decode(&mut d)?)
                }
                EncodingTag::Digest => {
                    DataFormat::Digest(DigestAlgorithm::strict_decode(&mut d)?)
                }
                EncodingTag::PublicKey => DataFormat::PublicKey(
                    EllipticCurve::strict_decode(&mut d)?,
                    elliptic_curve::PointSerialization::strict_decode(&mut d)?,
                ),
                EncodingTag::Signature => DataFormat::Signature(
                    elliptic_curve::SignatureAlgorithm::strict_decode(&mut d)?,
                ),
                EncodingTag::TxOutPoint => DataFormat::TxOutPoint,
                EncodingTag::Tx => DataFormat::Tx,
                EncodingTag::Psbt => DataFormat::Psbt,
            })
        }
    }
}

mod _validation {
    use amplify::AsAny;
    use core::any::Any;

    use super::*;
    use crate::{
        data, validation, DeclarativeStrategy, HashStrategy, NodeId,
        OwnedState, PedersenStrategy, StateTypes,
    };
    use lnpbp::client_side_validation::Conceal;

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
        pub fn validate(
            &self,
            item_id: usize,
            data: &data::Revealed,
        ) -> validation::Status {
            let mut status = validation::Status::new();
            match (self, data) {
                (
                    Self::Unsigned(Bits::Bit8, min, max),
                    data::Revealed::U8(val),
                ) => range_check(item_id, true, *val, *min, *max, &mut status),
                (
                    Self::Unsigned(Bits::Bit16, min, max),
                    data::Revealed::U16(val),
                ) => range_check(item_id, true, *val, *min, *max, &mut status),
                (
                    Self::Unsigned(Bits::Bit32, min, max),
                    data::Revealed::U32(val),
                ) => range_check(item_id, true, *val, *min, *max, &mut status),
                (
                    Self::Unsigned(Bits::Bit64, min, max),
                    data::Revealed::U64(val),
                ) => range_check(item_id, true, *val, *min, *max, &mut status),
                (Self::Unsigned(bits, _, _), _) => {
                    status.add_failure(
                        validation::Failure::SchemaMismatchedBits {
                            field_or_state_type: item_id,
                            expected: *bits,
                        },
                    );
                }

                (
                    Self::Integer(Bits::Bit8, min, max),
                    data::Revealed::I8(val),
                ) => range_check(item_id, true, *val, *min, *max, &mut status),
                (
                    Self::Integer(Bits::Bit16, min, max),
                    data::Revealed::I16(val),
                ) => range_check(item_id, true, *val, *min, *max, &mut status),
                (
                    Self::Integer(Bits::Bit32, min, max),
                    data::Revealed::I32(val),
                ) => range_check(item_id, true, *val, *min, *max, &mut status),
                (
                    Self::Integer(Bits::Bit64, min, max),
                    data::Revealed::I64(val),
                ) => range_check(item_id, true, *val, *min, *max, &mut status),
                (Self::Integer(bits, _, _), _) => {
                    status.add_failure(
                        validation::Failure::SchemaMismatchedBits {
                            field_or_state_type: item_id,
                            expected: *bits,
                        },
                    );
                }

                (
                    Self::Float(Bits::Bit32, min, max),
                    data::Revealed::F32(val),
                ) => range_check(item_id, true, *val, *min, *max, &mut status),
                (
                    Self::Float(Bits::Bit64, min, max),
                    data::Revealed::F64(val),
                ) => range_check(item_id, true, *val, *min, *max, &mut status),
                (Self::Float(bits, _, _), _) => {
                    status.add_failure(
                        validation::Failure::SchemaMismatchedBits {
                            field_or_state_type: item_id,
                            expected: *bits,
                        },
                    );
                }

                (Self::Enum(value_set), data::Revealed::U8(val)) => {
                    if !value_set.contains(val) {
                        status.add_failure(
                            validation::Failure::SchemaWrongEnumValue {
                                field_or_state_type: item_id,
                                unexpected: *val,
                            },
                        );
                    }
                }
                (Self::Enum(_), _) => {
                    status.add_failure(
                        validation::Failure::SchemaMismatchedBits {
                            field_or_state_type: item_id,
                            expected: Bits::Bit8,
                        },
                    );
                }

                (Self::String(len), data::Revealed::String(val)) => {
                    if val.len() > *len as usize {
                        status.add_failure(
                            validation::Failure::SchemaWrongDataLength {
                                field_or_state_type: item_id,
                                max_expected: *len,
                                found: val.len(),
                            },
                        );
                    }
                }
                (Self::Bytes(len), data::Revealed::Bytes(val)) => {
                    if val.len() > *len as usize {
                        status.add_failure(
                            validation::Failure::SchemaWrongDataLength {
                                field_or_state_type: item_id,
                                max_expected: *len,
                                found: val.len(),
                            },
                        );
                    }
                }

                (
                    Self::Digest(DigestAlgorithm::Sha256),
                    data::Revealed::Sha256(_),
                ) => {}
                (
                    Self::Digest(DigestAlgorithm::Sha512),
                    data::Revealed::Sha512(_),
                ) => {}
                (
                    Self::Digest(DigestAlgorithm::Bitcoin160),
                    data::Revealed::Bitcoin160(_),
                ) => {}
                (
                    Self::Digest(DigestAlgorithm::Bitcoin256),
                    data::Revealed::Bitcoin256(_),
                ) => {}

                (
                    Self::PublicKey(EllipticCurve::Secp256k1, _),
                    data::Revealed::Secp256k1Pubkey(_),
                ) => {}
                (
                    Self::PublicKey(EllipticCurve::Curve25519, _),
                    data::Revealed::Curve25519Pubkey(_),
                ) => {}
                (
                    Self::Signature(elliptic_curve::SignatureAlgorithm::Ecdsa),
                    data::Revealed::Secp256k1ECDSASignature(_),
                ) => {}
                (
                    Self::Signature(
                        elliptic_curve::SignatureAlgorithm::Ed25519,
                    ),
                    data::Revealed::Ed25519Signature(_),
                ) => {}
                (Self::TxOutPoint, data::Revealed::TxOutPoint(_)) => {}
                (Self::Tx, data::Revealed::Tx(_)) => {}
                (Self::Psbt, data::Revealed::Psbt(_)) => {}

                _ => {
                    status.add_failure(
                        validation::Failure::SchemaMismatchedDataType(item_id),
                    );
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
            data: &OwnedState<STATE>,
        ) -> validation::Status
        where
            STATE: StateTypes,
            STATE::Confidential: PartialEq + Eq,
            STATE::Confidential:
                From<<STATE::Revealed as Conceal>::Confidential>,
        {
            let mut status = validation::Status::new();
            match data {
                OwnedState::Confidential { assigned_state, .. }
                | OwnedState::ConfidentialAmount { assigned_state, .. } => {
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
                OwnedState::Revealed { assigned_state, .. }
                | OwnedState::ConfidentialSeal { assigned_state, .. } => {
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::contract::data::{self, Revealed};
    use crate::contract::{value, NodeId};
    use crate::validation::{Failure, Validity};
    use crate::{
        DeclarativeStrategy, HashStrategy, OwnedState, PedersenStrategy,
    };

    use bitcoin::blockdata::transaction::OutPoint;
    use bitcoin::hashes::{hex::FromHex, sha256};
    use std::collections::BTreeMap;

    use lnpbp::bp::blind::OutpointReveal;
    use lnpbp::bp::TaggedHash;
    use lnpbp::client_side_validation::Conceal;
    use lnpbp::secp256k1zkp::rand::thread_rng;
    use lnpbp::strict_encoding::{strict_serialize, StrictDecode};
    use lnpbp::test_helpers::*;

    // Txids to generate seals
    static TXID_VEC: [&str; 4] = [
        "201fdd1e2b62d7b6938271295118ee181f1bac5e57d9f4528925650d36d3af8e",
        "f57ed27ee4199072c5ff3b774febc94d26d3e4a5559d133de4750a948df50e06",
        "12072893d951c633dcafb4d3074d1fc41c5e6e64b8d53e3b0705c41bc6679d54",
        "8f75db9f89c7c75f0a54322f18cd4d557ae75c24a8e5a95eae13fe26edc2d789",
    ];

    #[test]
    #[should_panic(expected = "UnsupportedDataStructure")]
    fn test_garbage_df_format1() {
        let bytes: Vec<u8> = vec![
            0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255,
            255,
        ];
        DiscreteFiniteFieldFormat::strict_decode(&bytes[..]).unwrap();
    }

    #[test]
    #[should_panic(expected = "UnsupportedDataStructure")]
    fn test_garbage_df_format2() {
        let bytes: Vec<u8> = vec![
            1, 8, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255,
            255,
        ];
        DiscreteFiniteFieldFormat::strict_decode(&bytes[..]).unwrap();
    }

    #[test]
    #[should_panic(expected = "UnsupportedDataStructure")]
    fn test_garbage_df_format3() {
        let bytes: Vec<u8> = vec![
            1, 8, 0, 0, 0, 0, 0, 0, 0, 1, 255, 255, 255, 255, 255, 255, 255,
            255,
        ];
        DiscreteFiniteFieldFormat::strict_decode(&bytes[..]).unwrap();
    }

    #[test]
    #[should_panic(expected = "UnsupportedDataStructure")]
    fn test_garbage_df_format4() {
        let bytes: Vec<u8> = vec![
            1, 8, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255,
            127,
        ];
        DiscreteFiniteFieldFormat::strict_decode(&bytes[..]).unwrap();
    }

    #[test]
    #[should_panic(expected = "DataIntegrityError")]
    fn test_garbage_data_format1() {
        let bytes: Vec<u8> = vec![2, 2, 4, 0, 0, 0, 0, 255, 255, 127, 127];
        DataFormat::strict_decode(&bytes[..]).unwrap();
    }

    #[test]
    #[should_panic(expected = "ValueOutOfRange")]
    fn test_garbage_data_format2() {
        let format = DataFormat::Float(Bits::Bit16, 0.0, core::f32::MAX as f64);
        strict_serialize(&format).unwrap();
    }

    #[test]
    fn test_random() {
        let n = 67u8;
        println!("{}", ::core::mem::size_of_val(&n));
    }

    #[test]
    fn test_encoding_state_format() {
        // Create a Map of Format type and encoded data

        let mut map: BTreeMap<&str, Vec<u8>> = BTreeMap::new();
        // Declarative and Pedersan formats
        map.insert("Declerative", vec![0]);
        map.insert(
            "DiscreteFinite format",
            vec![
                1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255,
                255, 255,
            ],
        );
        // data formats
        map.insert("u8", vec![2, 0, 1, 0, 255]);
        map.insert("u16", vec![2, 0, 2, 0, 0, 255, 255]);
        map.insert("u32", vec![2, 0, 4, 0, 0, 0, 0, 255, 255, 255, 255]);
        map.insert(
            "u64",
            vec![
                2, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255,
                255, 255,
            ],
        );
        map.insert("i8", vec![2, 1, 1, 0, 127]);
        map.insert("i16", vec![2, 1, 2, 0, 0, 255, 127]);
        map.insert("i32", vec![2, 1, 4, 0, 0, 0, 0, 255, 255, 255, 127]);
        map.insert(
            "i64",
            vec![
                2, 1, 8, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255,
                255, 127,
            ],
        );
        map.insert("f32", vec![2, 2, 4, 0, 0, 0, 0, 255, 255, 127, 127]);
        map.insert(
            "f64",
            vec![
                2, 2, 8, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255,
                239, 127,
            ],
        );

        // Enums
        map.insert("Enum(1, 2, 3)", vec![2, 3, 3, 0, 1, 2, 3]);

        // String
        map.insert("String(13", vec![2, 4, 13, 0]);

        // Bytes
        map.insert("Bytes(27)", vec![2, 5, 27, 0]);

        // Digest Algo
        map.insert("Digest(Sha256)", vec![2, 16, 17]);
        map.insert("Digest(Sha512)", vec![2, 16, 18]);
        map.insert("Digest(Bitcoin160)", vec![2, 16, 72]);
        map.insert("Digest(Bitcoin256)", vec![2, 16, 81]);

        // Txoutpoint
        map.insert("TxOutPoint", vec![2, 32]);

        // Public Keys
        map.insert("PublickKey(Secp, Compressed)", vec![2, 17, 0, 1]);
        map.insert("PublickKey(Secp, Unompressed)", vec![2, 17, 0, 0]);
        map.insert("PublickKey(Secp, SchnorrBip)", vec![2, 17, 0, 2]);
        map.insert("PublickKey(Curve25519, Compressed)", vec![2, 17, 16, 1]);
        map.insert("PublickKey(Curve25519, Unompressed)", vec![2, 17, 16, 0]);
        map.insert("PublickKey(Curve25519, SchnorrBip)", vec![2, 17, 16, 2]);

        // Signatures
        map.insert("Signature(Ecdsa)", vec![2, 18, 0]);
        map.insert("Signature(Schnorr)", vec![2, 18, 1]);
        map.insert("Signature(Ed25519)", vec![2, 18, 2]);

        // TX TxOutpoint and Psbt
        map.insert("TxOutpoint", vec![2, 32]);
        map.insert("Tx", vec![2, 33]);
        map.insert("Psbt", vec![2, 34]);

        // Test for correct encoding of each cases
        let _test: Vec<()> = map
            .iter()
            .map(|pair| {
                let data = pair.1;
                test_encode!((data, StateFormat));
            })
            .collect();

        // Test for correct encoding in StateSchema
        // Only one variant is created as StateSchema::Abi
        // maps against single AssignmentAction variant
        let schema_bytes = vec![0u8, 1, 0, 0, 255, 3];
        let schema = StateSchema::strict_decode(&schema_bytes[..]).unwrap();

        test_encode!((schema_bytes, StateSchema));
        assert_eq!(schema.format, StateFormat::Declarative);
        assert_eq!(
            schema.abi.get(&script::AssignmentAction::Validate).unwrap(),
            &script::Procedure::Embedded(
                script::StandardProcedure::NonfungibleInflation
            )
        );
    }

    #[test]
    fn test_dataformat_validate() {
        // Test general cases that pass validation=
        assert_eq!(
            DataFormat::u8().validate(3, &Revealed::U8(32u8)).validity(),
            Validity::Valid
        );
        assert_eq!(
            DataFormat::u16()
                .validate(3, &Revealed::U16(32u16))
                .validity(),
            Validity::Valid
        );
        assert_eq!(
            DataFormat::u32()
                .validate(3, &Revealed::U32(32u32))
                .validity(),
            Validity::Valid
        );
        assert_eq!(
            DataFormat::u64()
                .validate(3, &Revealed::U64(32u64))
                .validity(),
            Validity::Valid
        );
        assert_eq!(
            DataFormat::i8().validate(3, &Revealed::I8(32i8)).validity(),
            Validity::Valid
        );
        assert_eq!(
            DataFormat::i16()
                .validate(3, &Revealed::I16(32i16))
                .validity(),
            Validity::Valid
        );
        assert_eq!(
            DataFormat::i32()
                .validate(3, &Revealed::I32(32i32))
                .validity(),
            Validity::Valid
        );
        assert_eq!(
            DataFormat::i64()
                .validate(3, &Revealed::I64(32i64))
                .validity(),
            Validity::Valid
        );
        assert_eq!(
            DataFormat::f32()
                .validate(3, &Revealed::F32(32f32))
                .validity(),
            Validity::Valid
        );
        assert_eq!(
            DataFormat::f64()
                .validate(3, &Revealed::F64(32f64))
                .validity(),
            Validity::Valid
        );

        // Test failure for values smaller than allowed
        assert_eq!(
            DataFormat::i32()
                .validate(3, &Revealed::I32(-25i32))
                .validity(),
            Validity::Invalid
        );
        assert_eq!(
            DataFormat::i32()
                .validate(3, &Revealed::I32(-25i32))
                .failures[0],
            Failure::SchemaMetaValueTooSmall(3)
        );
        assert_eq!(
            DataFormat::i8()
                .validate(3, &Revealed::I8(-25i8))
                .validity(),
            Validity::Invalid
        );
        assert_eq!(
            DataFormat::i8().validate(3, &Revealed::I8(-25i8)).failures[0],
            Failure::SchemaMetaValueTooSmall(3)
        );
        assert_eq!(
            DataFormat::i16()
                .validate(3, &Revealed::I16(-25i16))
                .validity(),
            Validity::Invalid
        );
        assert_eq!(
            DataFormat::i16()
                .validate(3, &Revealed::I16(-25i16))
                .failures[0],
            Failure::SchemaMetaValueTooSmall(3)
        );
        assert_eq!(
            DataFormat::i64()
                .validate(3, &Revealed::I64(-25i64))
                .validity(),
            Validity::Invalid
        );
        assert_eq!(
            DataFormat::i64()
                .validate(3, &Revealed::I64(-25i64))
                .failures[0],
            Failure::SchemaMetaValueTooSmall(3)
        );
        assert_eq!(
            DataFormat::f32()
                .validate(3, &Revealed::F32(-25f32))
                .validity(),
            Validity::Invalid
        );
        assert_eq!(
            DataFormat::f32()
                .validate(3, &Revealed::F32(-25f32))
                .failures[0],
            Failure::SchemaMetaValueTooSmall(3)
        );
        assert_eq!(
            DataFormat::f64()
                .validate(3, &Revealed::F64(-25f64))
                .validity(),
            Validity::Invalid
        );
        assert_eq!(
            DataFormat::f64()
                .validate(3, &Revealed::F64(-25f64))
                .failures[0],
            Failure::SchemaMetaValueTooSmall(3)
        );
        assert_eq!(
            DataFormat::i32()
                .validate(3, &Revealed::I64(-25i64))
                .failures[0],
            Failure::SchemaMismatchedBits {
                field_or_state_type: 3,
                expected: Bits::Bit32
            }
        );

        // Test incompatible data
        assert_eq!(
            DataFormat::u16()
                .validate(3, &Revealed::U32(25u32))
                .failures[0],
            Failure::SchemaMismatchedBits {
                field_or_state_type: 3,
                expected: Bits::Bit16
            }
        );
        assert_eq!(
            DataFormat::f32()
                .validate(3, &Revealed::F64(25f64))
                .failures[0],
            Failure::SchemaMismatchedBits {
                field_or_state_type: 3,
                expected: Bits::Bit32
            }
        );

        // Test validity and failure cases for Enum format
        let mut set = BTreeSet::new();
        set.insert(1u8);
        set.insert(2u8);
        set.insert(3u8);

        let enum_fromat = DataFormat::Enum(set);
        assert_eq!(
            enum_fromat.validate(3, &Revealed::U8(3u8)).validity(),
            Validity::Valid
        );
        assert_eq!(
            enum_fromat.validate(3, &Revealed::U8(4u8)).failures[0],
            Failure::SchemaWrongEnumValue {
                field_or_state_type: 3,
                unexpected: 4
            }
        );
        assert_eq!(
            enum_fromat.validate(3, &Revealed::U16(4u16)).failures[0],
            Failure::SchemaMismatchedBits {
                field_or_state_type: 3,
                expected: Bits::Bit8
            }
        );

        // Test failure cases for String format
        let string_data = Revealed::String("Hello".to_string());
        let string_format = DataFormat::String(2u16);
        assert_eq!(
            string_format.validate(3, &string_data).failures[0],
            Failure::SchemaWrongDataLength {
                field_or_state_type: 3,
                max_expected: 2,
                found: 5
            }
        );

        // Test failure cases for Bytes format
        let bytes = vec![1u8, 2u8, 3u8];
        let bytes_data = Revealed::Bytes(bytes);
        let bytes_format = DataFormat::Bytes(2u16);
        assert_eq!(
            bytes_format.validate(3, &bytes_data).failures[0],
            Failure::SchemaWrongDataLength {
                field_or_state_type: 3,
                max_expected: 2,
                found: 3
            }
        );

        // Generic failure situation
        assert_eq!(
            bytes_format.validate(3, &string_data).failures[0],
            Failure::SchemaMismatchedDataType(3)
        );
    }

    #[test]
    fn test_state_format() {
        // Create typical assignments
        // Only Revealed and Confidential variants are created for simplicity
        // Which covers the two validation branch
        let mut rng = thread_rng();

        let txid_vec: Vec<bitcoin::Txid> = TXID_VEC
            .iter()
            .map(|txid| bitcoin::Txid::from_hex(txid).unwrap())
            .collect();

        // Create Declerative Assignments
        let assignment_dec_rev = OwnedState::<DeclarativeStrategy>::Revealed {
            seal_definition: crate::contract::seal::Revealed::TxOutpoint(
                OutpointReveal::from(OutPoint::new(txid_vec[0], 1)),
            ),
            assigned_state: data::Void,
        };

        let assignment_dec_conf =
            OwnedState::<DeclarativeStrategy>::Confidential {
                seal_definition: crate::contract::seal::Revealed::TxOutpoint(
                    OutpointReveal::from(OutPoint::new(txid_vec[1], 2)),
                )
                .conceal(),
                assigned_state: data::Void,
            };

        // Create Pedersan Assignments
        let assignment_ped_rev = OwnedState::<PedersenStrategy>::Revealed {
            seal_definition: crate::contract::seal::Revealed::TxOutpoint(
                OutpointReveal::from(OutPoint::new(txid_vec[0], 1)),
            ),
            assigned_state: value::Revealed::with_amount(10u64, &mut rng),
        };

        let assignment_ped_conf =
            OwnedState::<PedersenStrategy>::Confidential {
                seal_definition: crate::contract::seal::Revealed::TxOutpoint(
                    OutpointReveal::from(OutPoint::new(txid_vec[1], 1)),
                )
                .conceal(),
                assigned_state: value::Revealed::with_amount(10u64, &mut rng)
                    .conceal(),
            };

        // Create CustomData Assignmnets
        let state_data_vec: Vec<data::Revealed> = TXID_VEC
            .iter()
            .map(|data| {
                data::Revealed::Sha256(sha256::Hash::from_hex(data).unwrap())
            })
            .collect();

        let assignment_hash_rev = OwnedState::<HashStrategy>::Revealed {
            seal_definition: crate::contract::seal::Revealed::TxOutpoint(
                OutpointReveal::from(OutPoint::new(txid_vec[0], 1)),
            ),
            assigned_state: state_data_vec[0].clone(),
        };

        let assignment_hash_conf = OwnedState::<HashStrategy>::Confidential {
            seal_definition: crate::contract::seal::Revealed::TxOutpoint(
                OutpointReveal::from(OutPoint::new(txid_vec[1], 1)),
            )
            .conceal(),
            assigned_state: state_data_vec[0].clone().conceal(),
        };

        // Create NodeId amd Stateformats
        let node_id = NodeId::from_hex(
            "201fdd1e2b62d7b6938271295118ee181f1bac5e57d9f4528925650d36d3af8e",
        )
        .unwrap();
        let dec_format = StateFormat::Declarative;
        let ped_format = StateFormat::DiscreteFiniteField(
            DiscreteFiniteFieldFormat::Unsigned64bit,
        );
        let hash_format = StateFormat::CustomData(DataFormat::Digest(
            DigestAlgorithm::Sha256,
        ));

        // Assert different failure combinations
        assert_eq!(
            dec_format
                .validate(&node_id, 3usize, &assignment_ped_rev)
                .failures[0],
            Failure::SchemaMismatchedStateType(3)
        );
        assert_eq!(
            dec_format
                .validate(&node_id, 3usize, &assignment_ped_conf)
                .failures[0],
            Failure::SchemaMismatchedStateType(3)
        );
        assert_eq!(
            dec_format
                .validate(&node_id, 3usize, &assignment_hash_rev)
                .failures[0],
            Failure::SchemaMismatchedStateType(3)
        );
        assert_eq!(
            dec_format
                .validate(&node_id, 3usize, &assignment_hash_conf)
                .failures[0],
            Failure::SchemaMismatchedStateType(3)
        );

        assert_eq!(
            ped_format
                .validate(&node_id, 3usize, &assignment_dec_rev)
                .failures[0],
            Failure::SchemaMismatchedStateType(3)
        );
        assert_eq!(
            ped_format
                .validate(&node_id, 3usize, &assignment_dec_conf)
                .failures[0],
            Failure::SchemaMismatchedStateType(3)
        );
        assert_eq!(
            ped_format
                .validate(&node_id, 3usize, &assignment_hash_rev)
                .failures[0],
            Failure::SchemaMismatchedStateType(3)
        );
        assert_eq!(
            ped_format
                .validate(&node_id, 3usize, &assignment_hash_conf)
                .failures[0],
            Failure::SchemaMismatchedStateType(3)
        );

        assert_eq!(
            hash_format
                .validate(&node_id, 3usize, &assignment_dec_rev)
                .failures[0],
            Failure::SchemaMismatchedStateType(3)
        );
        assert_eq!(
            hash_format
                .validate(&node_id, 3usize, &assignment_dec_conf)
                .failures[0],
            Failure::SchemaMismatchedStateType(3)
        );
        assert_eq!(
            hash_format
                .validate(&node_id, 3usize, &assignment_ped_rev)
                .failures[0],
            Failure::SchemaMismatchedStateType(3)
        );
        assert_eq!(
            hash_format
                .validate(&node_id, 3usize, &assignment_ped_conf)
                .failures[0],
            Failure::SchemaMismatchedStateType(3)
        );
    }
}

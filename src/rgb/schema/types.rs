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

use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use std::{convert::TryFrom, io};

pub trait UnsignedInteger:
    Clone + Copy + PartialEq + Eq + PartialOrd + Ord + Into<u64> + std::fmt::Debug
{
    fn as_u64(self) -> u64 {
        self.into()
    }
}

impl UnsignedInteger for u8 {}
impl UnsignedInteger for u16 {}
impl UnsignedInteger for u32 {}
impl UnsignedInteger for u64 {}

pub trait Number: Clone + Copy + PartialEq + PartialOrd + std::fmt::Debug {}

impl Number for u8 {}
impl Number for u16 {}
impl Number for u32 {}
impl Number for u64 {}
impl Number for u128 {}
impl Number for i8 {}
impl Number for i16 {}
impl Number for i32 {}
impl Number for i64 {}
impl Number for i128 {}
impl Number for f32 {}
impl Number for f64 {}

/// NB: For now, we support only up to 128-bit integers and 64-bit floats;
/// nevertheless RGB schema standard allows up to 256-byte numeric types.
/// Support for larger types can be added later.
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Display, ToPrimitive, FromPrimitive,
)]
#[display_from(Debug)]
#[repr(u8)]
#[non_exhaustive]
pub enum Bits {
    Bit8 = 1,
    Bit16 = 2,
    Bit32 = 4,
    Bit64 = 8,
    Bit128 = 16,
}

impl Bits {
    pub fn max_valu(&self) -> u128 {
        match *self {
            Bits::Bit8 => std::u8::MAX as u128,
            Bits::Bit16 => std::u16::MAX as u128,
            Bits::Bit32 => std::u32::MAX as u128,
            Bits::Bit64 => std::u64::MAX as u128,
            Bits::Bit128 => std::u128::MAX as u128,
        }
    }

    pub fn byte_len(&self) -> usize {
        self.to_u8()
            .expect("Bit type MUST always occupy < 256 bytes") as usize
    }

    pub fn bit_len(&self) -> usize {
        self.byte_len() * 8
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Display)]
#[display_from(Debug)]
#[repr(u8)]
#[non_exhaustive]
pub enum Occurences<I: UnsignedInteger> {
    Once,
    NoneOrOnce,
    OnceOrUpTo(Option<I>),
    NoneOrUpTo(Option<I>),
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Display)]
#[display_from(Debug)]
pub struct OccurencesError {
    pub expected: Occurences<u64>,
    pub found: u64,
}

#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Display, ToPrimitive, FromPrimitive,
)]
#[display_from(Debug)]
#[repr(u8)]
#[non_exhaustive]
pub enum DigestAlgorithm {
    Ripemd160 = 0b_0000_1000_u8,
    Sha256 = 0b_0001_0001_u8,
    Sha512 = 0b_0001_0010_u8,
    Bitcoin160 = 0b_0100_1000_u8,
    Bitcoin256 = 0b_0101_0001_u8,
    Tagged256 = 0b_1100_0000_u8,
}

pub mod elliptic_curve {
    use num_derive::{FromPrimitive, ToPrimitive};

    #[derive(
        Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Display, ToPrimitive, FromPrimitive,
    )]
    #[display_from(Debug)]
    #[repr(u8)]
    #[non_exhaustive]
    pub enum EllipticCurve {
        Secp256k1 = 0x00,
        Curve25519 = 0x10,
    }

    #[derive(
        Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Display, ToPrimitive, FromPrimitive,
    )]
    #[display_from(Debug)]
    #[repr(u8)]
    #[non_exhaustive]
    pub enum SignatureAlgorithm {
        Ecdsa = 0,
        Schnorr,
    }

    #[derive(
        Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Display, ToPrimitive, FromPrimitive,
    )]
    #[display_from(Debug)]
    #[repr(u8)]
    #[non_exhaustive]
    pub enum PointSerialization {
        Uncompressed = 0,
        Compressed,
        SchnorrBip,
    }
}
pub use elliptic_curve::EllipticCurve;

impl<I: UnsignedInteger> Occurences<I> {
    pub fn translate_u64(self) -> Occurences<u64> {
        match self {
            Occurences::Once => Occurences::Once,
            Occurences::NoneOrOnce => Occurences::NoneOrOnce,
            Occurences::OnceOrUpTo(None) => Occurences::OnceOrUpTo(None),
            Occurences::OnceOrUpTo(Some(max)) => Occurences::OnceOrUpTo(Some(max.as_u64())),
            Occurences::NoneOrUpTo(None) => Occurences::NoneOrUpTo(None),
            Occurences::NoneOrUpTo(Some(max)) => Occurences::NoneOrUpTo(Some(max.as_u64())),
        }
    }

    pub fn check_count(&self, count: I) -> Result<(), OccurencesError> {
        match self {
            Occurences::Once if count.as_u64() == 1 => Ok(()),
            Occurences::NoneOrOnce if count.as_u64() <= 1 => Ok(()),
            Occurences::OnceOrUpTo(None) if count.as_u64() > 0 => Ok(()),
            Occurences::OnceOrUpTo(Some(max)) if count.as_u64() > 0 && count <= *max => Ok(()),
            Occurences::NoneOrUpTo(None) => Ok(()),
            Occurences::NoneOrUpTo(Some(max)) if count <= *max => Ok(()),
            _ => Err(OccurencesError {
                expected: self.clone().translate_u64(),
                found: count.as_u64(),
            }),
        }
    }
}

mod strict_encoding {
    use super::*;
    use crate::strict_encoding::{Error, StrictDecode, StrictEncode};

    impl_enum_strict_encoding!(DigestAlgorithm);
    impl_enum_strict_encoding!(Bits);
    impl_enum_strict_encoding!(EllipticCurve);
    impl_enum_strict_encoding!(elliptic_curve::SignatureAlgorithm);
    impl_enum_strict_encoding!(elliptic_curve::PointSerialization);

    macro_rules! impl_occurences {
        ($type:ident) => {
            impl StrictEncode for Occurences<$type> {
                type Error = Error;

                fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
                    let value: (u8, u64) = match self {
                        Self::NoneOrOnce => (0x00u8, 0),
                        Self::Once => (0x01u8, 0),
                        Self::NoneOrUpTo(max) => (0xFEu8, max.unwrap_or(std::$type::MAX).into()),
                        Self::OnceOrUpTo(max) => (0xFFu8, max.unwrap_or(std::$type::MAX).into()),
                    };
                    let mut len = value.0.strict_encode(&mut e)?;
                    len += value.1.strict_encode(&mut e)?;
                    Ok(len)
                }
            }

            impl StrictDecode for Occurences<$type> {
                type Error = Error;

                fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
                    let value = u8::strict_decode(&mut d)?;
                    let max: u64 = u64::strict_decode(&mut d)?;
                    let max: Option<$type> = match max {
                        val if val > 0 && val < ::std::$type::MAX.into() => {
                            Ok(Some($type::try_from(max).expect("Can't fail")))
                        }
                        val if val == ::std::$type::MAX as u64 => Ok(None),
                        invalid => Err(Error::ValueOutOfRange(
                            stringify!($type).to_string(),
                            0..(::std::$type::MAX as u64),
                            invalid,
                        )),
                    }?;
                    Ok(match value {
                        0x00u8 => Self::NoneOrOnce,
                        0x01u8 => Self::Once,
                        0xFEu8 => Self::NoneOrUpTo(max),
                        0xFFu8 => Self::OnceOrUpTo(max),
                        _ => panic!(
                            "New occurence types can't appear w/o this library to be aware of"
                        ),
                    })
                }
            }
        };
    }

    impl_occurences!(u8);
    impl_occurences!(u16);
    impl_occurences!(u32);
    impl_occurences!(u64);
}

#[cfg(test)]
mod test {
    use super::Occurences;

    #[test]
    fn test_once_check_count() {
        let occurence: Occurences<u32> = Occurences::Once;
        occurence.check_count(1).unwrap();
    }
    #[test]
    #[should_panic(expected = "OccurencesError { expected: Once, found: 0 }")]
    fn test_once_check_count_fail_zero() {
        let occurence: Occurences<u32> = Occurences::Once;
        occurence.check_count(0).unwrap();
    }
    #[test]
    #[should_panic(expected = "OccurencesError { expected: Once, found: 2 }")]
    fn test_once_check_count_fail_two() {
        let occurence: Occurences<u32> = Occurences::Once;
        occurence.check_count(2).unwrap();
    }

    #[test]
    fn test_none_or_once_check_count() {
        let occurence: Occurences<u32> = Occurences::NoneOrOnce;
        occurence.check_count(1).unwrap();
    }
    #[test]
    fn test_none_or_once_check_count_zero() {
        let occurence: Occurences<u32> = Occurences::NoneOrOnce;
        occurence.check_count(0).unwrap();
    }
    #[test]
    #[should_panic(expected = "OccurencesError { expected: NoneOrOnce, found: 2 }")]
    fn test_none_or_once_check_count_fail_two() {
        let occurence: Occurences<u32> = Occurences::NoneOrOnce;
        occurence.check_count(2).unwrap();
    }

    #[test]
    fn test_once_or_up_to_none() {
        let occurence: Occurences<u32> = Occurences::OnceOrUpTo(None);
        occurence.check_count(1).unwrap();
    }
    #[test]
    fn test_once_or_up_to_none_large() {
        let occurence: Occurences<u32> = Occurences::OnceOrUpTo(None);
        occurence.check_count(u32::MAX).unwrap();
    }
    #[test]
    #[should_panic(expected = "OccurencesError { expected: OnceOrUpTo(None), found: 0 }")]
    fn test_once_or_up_to_none_fail_zero() {
        let occurence: Occurences<u32> = Occurences::OnceOrUpTo(None);
        occurence.check_count(0).unwrap();
    }
    #[test]
    fn test_once_or_up_to_42() {
        let occurence: Occurences<u32> = Occurences::OnceOrUpTo(Some(42));
        occurence.check_count(42).unwrap();
    }
    #[test]
    #[should_panic(expected = "OccurencesError { expected: OnceOrUpTo(Some(42)), found: 43 }")]
    fn test_once_or_up_to_42_large() {
        let occurence: Occurences<u32> = Occurences::OnceOrUpTo(Some(42));
        occurence.check_count(43).unwrap();
    }
    #[test]
    #[should_panic(expected = "OccurencesError { expected: OnceOrUpTo(Some(42)), found: 0 }")]
    fn test_once_or_up_to_42_fail_zero() {
        let occurence: Occurences<u32> = Occurences::OnceOrUpTo(Some(42));
        occurence.check_count(0).unwrap();
    }

    #[test]
    fn test_none_or_up_to_none_zero() {
        let occurence: Occurences<u32> = Occurences::NoneOrUpTo(None);
        occurence.check_count(0).unwrap();
    }
    #[test]
    fn test_none_or_up_to_none_large() {
        let occurence: Occurences<u32> = Occurences::NoneOrUpTo(None);
        occurence.check_count(u32::MAX).unwrap();
    }
    #[test]
    fn test_none_or_up_to_42_zero() {
        let occurence: Occurences<u32> = Occurences::NoneOrUpTo(Some(42));
        occurence.check_count(0).unwrap();
    }
    #[test]
    fn test_none_or_up_to_42() {
        let occurence: Occurences<u32> = Occurences::NoneOrUpTo(Some(42));
        occurence.check_count(42).unwrap();
    }
    #[test]
    #[should_panic(expected = "OccurencesError { expected: NoneOrUpTo(Some(42)), found: 43 }")]
    fn test_none_or_up_to_42_large() {
        let occurence: Occurences<u32> = Occurences::NoneOrUpTo(Some(42));
        occurence.check_count(43).unwrap();
    }
}

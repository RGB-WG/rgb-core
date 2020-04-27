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


use std::{io, convert::TryFrom};

use num_traits::{ToPrimitive, FromPrimitive};
use num_derive::{ToPrimitive, FromPrimitive};

use crate::csv::serialize::*;

pub trait UnsignedInteger: Clone + Copy + PartialEq + Eq + PartialOrd + Ord + Into<u64> + std::fmt::Debug {
    fn as_u64(self) -> u64 {
        self.into()
    }
}

impl UnsignedInteger for u8 { }
impl UnsignedInteger for u16 { }
impl UnsignedInteger for u32 { }
impl UnsignedInteger for u64 { }

#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Display, ToPrimitive, FromPrimitive)]
#[display_from(Debug)]
pub enum StateFormat {
    NoState = 0,
    Amount = 1,
    Data = 0xFF,
}

impl_commitment_enum!(StateFormat);


#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Display, ToPrimitive, FromPrimitive)]
#[display_from(Debug)]
pub enum Bits {
    Bit8 = 0,
    Bit16,
    Bit32,
    Bit64,
    Bit128,
    Bit256,
}

impl_commitment_enum!(Bits);


#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Display, ToPrimitive, FromPrimitive)]
#[display_from(Debug)]
pub enum DigestAlgorithm {
    Sha256 = 0,
    Bitcoin256,
    Ripemd160,
    Bitcoin160,
    Tagged256,
}

impl_commitment_enum!(DigestAlgorithm);


#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Display, ToPrimitive, FromPrimitive)]
#[display_from(Debug)]
pub enum SignatureAlgorithm {
    EcdsaDer = 0,
    SchnorrBip,
}

impl_commitment_enum!(SignatureAlgorithm);


#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Display, ToPrimitive, FromPrimitive)]
#[display_from(Debug)]
pub enum ECPointSerialization {
    Uncompressed = 0,
    Compressed,
    SchnorrBip
}

impl_commitment_enum!(ECPointSerialization);


#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Display)]
#[display_from(Debug)]
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
    pub found: u64
}

impl<I: UnsignedInteger> Occurences<I> {
    pub fn translate_u64(self) -> Occurences<u64> {
        match self {
            Occurences::Once => Occurences::Once,
            Occurences::NoneOrOnce => Occurences::NoneOrOnce,
            Occurences::OnceOrUpTo(None) => Occurences::OnceOrUpTo(None),
            Occurences::OnceOrUpTo(Some(max)) => Occurences::OnceOrUpTo(Some(max.as_u64())),
            Occurences::NoneOrUpTo(None) => Occurences::NoneOrUpTo(None),
            Occurences::NoneOrUpTo(Some(max)) => Occurences::NoneOrUpTo(Some(max.as_u64())),
            _ => panic!("Unknown occurence variant"),
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
            _ => Err(OccurencesError { expected: self.clone().translate_u64(), found: count.as_u64() }),
        }
    }
}

macro_rules! impl_occurences {
    ($type:ident) => {
        impl Commitment for Occurences<$type> {
            fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
                let value: (u8, u64) = match self {
                    Self::NoneOrOnce => (0x00u8, 0),
                    Self::Once => (0x01u8, 0),
                    Self::NoneOrUpTo(max) => (0xFEu8, max.unwrap_or(std::$type::MAX).into()),
                    Self::OnceOrUpTo(max) => (0xFFu8, max.unwrap_or(std::$type::MAX).into()),
                    _ => panic!("New occurence types can't appear w/o this library to be aware of")
                };
                let mut len = value.0.commitment_serialize(&mut e)?;
                len += value.1.commitment_serialize(&mut e)?;
                Ok(len)
            }

            fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, Error> {
                let value = u8::commitment_deserialize(&mut d)?;
                let max: u64 = u64::commitment_deserialize(&mut d)?;
                let max: Option<$type> = match max {
                    val if val > 0 && val < ::std::$type::MAX.into() =>
                        Ok(Some($type::try_from(max).expect("Can't fail"))),
                    val if val == ::std::$type::MAX as u64 =>
                        Ok(None),
                    _ => Err(Error::ValueOutOfRange),
                }?;
                Ok(match value {
                    0x00u8 => Self::NoneOrOnce,
                    0x01u8 => Self::Once,
                    0xFEu8 => Self::NoneOrUpTo(max),
                    0xFFu8 => Self::OnceOrUpTo(max),
                    _ => panic!("New occurence types can't appear w/o this library to be aware of")
                })
            }
        }
    };
}

impl_occurences!(u8);
impl_occurences!(u16);
impl_occurences!(u32);
impl_occurences!(u64);

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

// RGB Core Library: a reference implementation of RGB smart contract standards.
// Written in 2019-2022 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the MIT License along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

use std::ops::RangeInclusive;

pub trait UnsignedInteger:
    Clone + Copy + PartialEq + Eq + PartialOrd + Ord + Into<u64> + std::fmt::Debug
{
    const MAX: Self;

    fn as_u64(self) -> u64 { self.into() }

    fn bits() -> Bits;
}

impl UnsignedInteger for u8 {
    const MAX: Self = core::u8::MAX;

    #[inline]
    fn bits() -> Bits { Bits::Bit8 }
}
impl UnsignedInteger for u16 {
    const MAX: Self = core::u16::MAX;

    #[inline]
    fn bits() -> Bits { Bits::Bit16 }
}
impl UnsignedInteger for u32 {
    const MAX: Self = core::u32::MAX;

    #[inline]
    fn bits() -> Bits { Bits::Bit32 }
}
impl UnsignedInteger for u64 {
    const MAX: Self = core::u64::MAX;

    #[inline]
    fn bits() -> Bits { Bits::Bit64 }
}

pub trait Number: Clone + Copy + PartialEq + PartialOrd + std::fmt::Debug {}

impl Number for u8 {}
impl Number for u16 {}
impl Number for u32 {}
impl Number for u64 {}
impl Number for u128 {}
impl Number for usize {}
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
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[derive(StrictEncode, StrictDecode)]
#[strict_encoding(by_value, repr = u8)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "lowercase")
)]
#[repr(u8)]
#[non_exhaustive]
pub enum Bits {
    Bit8 = 1,
    Bit16 = 2,
    Bit32 = 4,
    Bit64 = 8,
    Bit128 = 16,
    // Bit256 = 32,
}
// TODO #46: Add support for 256-bit types

impl Bits {
    pub fn max_value(self) -> u128 {
        match self {
            Bits::Bit8 => core::u8::MAX as u128,
            Bits::Bit16 => core::u16::MAX as u128,
            Bits::Bit32 => core::u32::MAX as u128,
            Bits::Bit64 => core::u64::MAX as u128,
            Bits::Bit128 => core::u128::MAX as u128,
        }
    }

    pub fn byte_len(self) -> usize { (self as u8) as usize }

    pub fn bit_len(self) -> usize { self.byte_len() * 8 }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[repr(u8)]
pub enum Occurrences {
    Once,
    NoneOrOnce,
    NoneOrMore,
    OnceOrMore,
    NoneOrUpTo(u16),
    OnceOrUpTo(u16),
    Exactly(u16),
    Range(RangeInclusive<u16>),
}

impl Occurrences {
    pub fn min_value(&self) -> u16 {
        match self {
            Occurrences::Once => 1,
            Occurrences::NoneOrOnce => 0,
            Occurrences::NoneOrMore => 0,
            Occurrences::OnceOrMore => 1,
            Occurrences::NoneOrUpTo(_) => 0,
            Occurrences::OnceOrUpTo(_) => 1,
            Occurrences::Exactly(val) => *val,
            Occurrences::Range(range) => *range.start(),
        }
    }

    pub fn max_value(&self) -> u16 {
        match self {
            Occurrences::Once | Occurrences::NoneOrOnce => 1,
            Occurrences::NoneOrMore | Occurrences::OnceOrMore => u16::MAX,
            Occurrences::OnceOrUpTo(max) | Occurrences::NoneOrUpTo(max) => *max,
            Occurrences::Exactly(val) => *val,
            Occurrences::Range(range) => *range.end(),
        }
    }

    pub fn check(&self, count: u16) -> Result<(), OccurrencesError> {
        let orig_count = count;
        if count > u16::MAX.into() {
            Err(OccurrencesError {
                min: self.min_value().into(),
                max: self.max_value().into(),
                found: count.into(),
            })?
        }
        match self {
            Occurrences::Once if count == 1 => Ok(()),
            Occurrences::NoneOrOnce if count <= 1 => Ok(()),
            Occurrences::OnceOrMore if count > 0 => Ok(()),
            Occurrences::OnceOrUpTo(max) if count > 0 && count <= *max => Ok(()),
            Occurrences::NoneOrMore => Ok(()),
            Occurrences::NoneOrUpTo(max) if count <= *max => Ok(()),
            Occurrences::Exactly(val) if count == *val => Ok(()),
            Occurrences::Range(range) if range.contains(&count) => Ok(()),
            _ => Err(OccurrencesError {
                min: self.min_value().into(),
                max: self.max_value().into(),
                found: orig_count.into(),
            }),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Display, StrictEncode, StrictDecode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
#[display(Debug)]
pub struct OccurrencesError {
    pub min: u16,
    pub max: u16,
    pub found: u16,
}

mod _strict_encoding {
    use std::io;

    use strict_encoding::{Error, StrictDecode, StrictEncode};

    use super::*;

    impl StrictEncode for Occurrences {
        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
            let (min, max) = match self {
                Occurrences::NoneOrOnce => (0, 1),
                Occurrences::Once => (1, 1),
                Occurrences::NoneOrMore => (0, core::u16::MAX.into()),
                Occurrences::OnceOrMore => (1, core::u16::MAX.into()),
                Occurrences::NoneOrUpTo(max) => (0, *max),
                Occurrences::OnceOrUpTo(max) => (1, *max),
                Occurrences::Exactly(val) => (*val, *val),
                Occurrences::Range(range) => (*range.start(), *range.end()),
            };
            Ok(min.strict_encode(&mut e)? + max.strict_encode(&mut e)?)
        }
    }

    impl StrictDecode for Occurrences {
        #[allow(unused_comparisons)]
        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
            let min = u16::strict_decode(&mut d)?;
            let max = u16::strict_decode(&mut d)?;
            Ok(match (min, max) {
                (0, 1) => Occurrences::NoneOrOnce,
                (1, 1) => Occurrences::Once,
                (0, max) if max == ::core::u16::MAX => Occurrences::NoneOrMore,
                (1, max) if max == ::core::u16::MAX => Occurrences::OnceOrMore,
                (0, max) if max > 0 => Occurrences::NoneOrUpTo(max),
                (1, max) if max > 0 => Occurrences::OnceOrUpTo(max),
                (min, max) if min == max => Occurrences::Exactly(min),
                (min, max) => Occurrences::Range(min..=max),
            })
        }
    }
}

#[cfg(test)]
mod test {
    use strict_encoding::StrictDecode;

    use super::{Occurrences, *};

    static ONCE: [u8; 4] = [1, 0, 1, 0];

    static NONEORONCE: [u8; 4] = [0, 0, 1, 0];

    static NONEUPTO_U8: [u8; 4] = [0, 0, 255, 0];

    static NONEUPTO_U16: [u8; 4] = [0, 0, 255, 255];

    #[test]
    fn test_once_check_count() {
        let occurence: Occurrences = Occurrences::Once;
        occurence.check(1).unwrap();
    }
    #[test]
    #[should_panic(expected = "OccurrencesError { min: 1, max: 1, found: 0 }")]
    fn test_once_check_count_fail_zero() {
        let occurence: Occurrences = Occurrences::Once;
        occurence.check(0).unwrap();
    }
    #[test]
    #[should_panic(expected = "OccurrencesError { min: 1, max: 1, found: 2 }")]
    fn test_once_check_count_fail_two() {
        let occurence: Occurrences = Occurrences::Once;
        occurence.check(2).unwrap();
    }

    #[test]
    fn test_none_or_once_check_count() {
        let occurence: Occurrences = Occurrences::NoneOrOnce;
        occurence.check(1).unwrap();
    }
    #[test]
    fn test_none_or_once_check_count_zero() {
        let occurence: Occurrences = Occurrences::NoneOrOnce;
        occurence.check(0).unwrap();
    }
    #[test]
    #[should_panic(expected = "OccurrencesError { min: 0, max: 1, found: 2 }")]
    fn test_none_or_once_check_count_fail_two() {
        let occurence: Occurrences = Occurrences::NoneOrOnce;
        occurence.check(2).unwrap();
    }

    #[test]
    fn test_once_or_up_to_none() {
        let occurence: Occurrences = Occurrences::OnceOrMore;
        occurence.check(1).unwrap();
    }
    #[test]
    fn test_once_or_up_to_none_large() {
        let occurence: Occurrences = Occurrences::OnceOrMore;
        occurence.check(core::u16::MAX).unwrap();
    }
    #[test]
    #[should_panic(expected = "OccurrencesError { min: 1, max: 65535, found: 0 }")]
    fn test_once_or_up_to_none_fail_zero() {
        let occurence: Occurrences = Occurrences::OnceOrMore;
        occurence.check(0).unwrap();
    }
    #[test]
    fn test_once_or_up_to_42() {
        let occurence: Occurrences = Occurrences::OnceOrUpTo(42);
        occurence.check(42).unwrap();
    }
    #[test]
    #[should_panic(expected = "OccurrencesError { min: 1, max: 42, found: 43 }")]
    fn test_once_or_up_to_42_large() {
        let occurence: Occurrences = Occurrences::OnceOrUpTo(42);
        occurence.check(43).unwrap();
    }
    #[test]
    #[should_panic(expected = "OccurrencesError { min: 1, max: 42, found: 0 }")]
    fn test_once_or_up_to_42_fail_zero() {
        let occurence: Occurrences = Occurrences::OnceOrUpTo(42);
        occurence.check(0).unwrap();
    }

    #[test]
    fn test_none_or_up_to_none_zero() {
        let occurence: Occurrences = Occurrences::NoneOrMore;
        occurence.check(0).unwrap();
    }
    #[test]
    fn test_none_or_up_to_none_large() {
        let occurence: Occurrences = Occurrences::NoneOrMore;
        occurence.check(core::u16::MAX).unwrap();
    }
    #[test]
    fn test_none_or_up_to_42_zero() {
        let occurence: Occurrences = Occurrences::NoneOrMore;
        occurence.check(0).unwrap();
    }
    #[test]
    fn test_none_or_up_to_42() {
        let occurence: Occurrences = Occurrences::NoneOrMore;
        occurence.check(42).unwrap();
    }
    #[test]
    #[should_panic(expected = "OccurrencesError { min: 0, max: 42, found: 43 }")]
    fn test_none_or_up_to_42_large() {
        let occurence: Occurrences = Occurrences::NoneOrUpTo(42);
        occurence.check(43).unwrap();
    }

    #[test]
    fn test_encode_occurance() {
        test_encode!((ONCE, Occurrences), (NONEORONCE, Occurrences));

        test_encode!((NONEUPTO_U16, Occurrences));
    }

    #[test]
    fn test_encode_occurance_2() {
        let mut once_upto_u8 = NONEUPTO_U8.clone();
        let mut once_upto_u16 = NONEUPTO_U16.clone();

        once_upto_u8[0] = 0x01;
        once_upto_u16[0] = 0x01;

        let dec2: Occurrences = Occurrences::strict_decode(&once_upto_u16[..]).unwrap();

        assert_eq!(dec2, Occurrences::OnceOrMore);

        let wc2: Occurrences = Occurrences::strict_decode(&once_upto_u8[..]).unwrap();

        assert_eq!(wc2, Occurrences::OnceOrUpTo(255));
    }

    #[test]
    fn test_bits() {
        let bit8 = Bits::strict_decode(&[0x01][..]).unwrap();
        let bit16 = Bits::strict_decode(&[0x02][..]).unwrap();
        let bit32 = Bits::strict_decode(&[0x04][..]).unwrap();
        let bit64 = Bits::strict_decode(&[0x08][..]).unwrap();

        assert_eq!(bit8, Bits::Bit8);
        assert_eq!(bit16, Bits::Bit16);
        assert_eq!(bit32, Bits::Bit32);
        assert_eq!(bit64, Bits::Bit64);

        assert_eq!(bit8.max_value(), core::u8::MAX as u128);
        assert_eq!(bit16.max_value(), core::u16::MAX as u128);
        assert_eq!(bit32.max_value(), core::u32::MAX as u128);
        assert_eq!(bit64.max_value(), core::u64::MAX as u128);

        assert_eq!(bit8.bit_len(), 8 as usize);
        assert_eq!(bit8.byte_len(), 1 as usize);
        assert_eq!(bit16.bit_len(), 16 as usize);
        assert_eq!(bit16.byte_len(), 2 as usize);
        assert_eq!(bit32.bit_len(), 32 as usize);
        assert_eq!(bit32.byte_len(), 4 as usize);
        assert_eq!(bit64.bit_len(), 64 as usize);
        assert_eq!(bit64.byte_len(), 8 as usize);
    }

    #[test]
    #[should_panic(expected = "EnumValueNotKnown")]
    fn test_bits_panic() { Bits::strict_decode(&[0x12][..]).unwrap(); }

    #[test]
    fn test_unsigned() {
        let u8_unsigned = core::u8::MAX;
        let u16_unsigned = core::u16::MAX;
        let u32_unsigned = core::u32::MAX;
        let u64_unsigned = core::u64::MAX;

        assert_eq!(u8_unsigned.as_u64(), core::u8::MAX as u64);
        assert_eq!(u8::bits(), Bits::Bit8);
        assert_eq!(u16_unsigned.as_u64(), core::u16::MAX as u64);
        assert_eq!(u16::bits(), Bits::Bit16);
        assert_eq!(u32_unsigned.as_u64(), core::u32::MAX as u64);
        assert_eq!(u32::bits(), Bits::Bit32);
        assert_eq!(u64_unsigned.as_u64(), core::u64::MAX as u64);
        assert_eq!(u64::bits(), Bits::Bit64);
    }
}

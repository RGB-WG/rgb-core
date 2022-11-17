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
                min: self.min_value(),
                max: self.max_value(),
                found: orig_count,
            }),
        }
    }
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
    ConfinedEncode,
    ConfinedDecode
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
#[display(Debug)]
pub struct OccurrencesError {
    pub min: u16,
    pub max: u16,
    pub found: u16,
}

mod _confined_encoding {
    use std::io;

    use confined_encoding::{ConfinedDecode, ConfinedEncode, Error};

    use super::*;

    impl ConfinedEncode for Occurrences {
        fn confined_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
            let (min, max) = match self {
                Occurrences::NoneOrOnce => (0, 1),
                Occurrences::Once => (1, 1),
                Occurrences::NoneOrMore => (0, core::u16::MAX),
                Occurrences::OnceOrMore => (1, core::u16::MAX),
                Occurrences::NoneOrUpTo(max) => (0, *max),
                Occurrences::OnceOrUpTo(max) => (1, *max),
                Occurrences::Exactly(val) => (*val, *val),
                Occurrences::Range(range) => (*range.start(), *range.end()),
            };
            Ok(min.confined_encode(&mut e)? + max.confined_encode(&mut e)?)
        }
    }

    impl ConfinedDecode for Occurrences {
        #[allow(unused_comparisons)]
        fn confined_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
            let min = u16::confined_decode(&mut d)?;
            let max = u16::confined_decode(&mut d)?;
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
    use confined_encoding::ConfinedDecode;
    use confined_encoding_test::test_vec_decoding_roundtrip;

    use super::Occurrences;

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
        let _: Occurrences = test_vec_decoding_roundtrip(ONCE).unwrap();
        let _: Occurrences = test_vec_decoding_roundtrip(NONEORONCE).unwrap();
        let _: Occurrences = test_vec_decoding_roundtrip(NONEUPTO_U16).unwrap();
    }

    #[test]
    fn test_encode_occurance_2() {
        let mut once_upto_u8 = NONEUPTO_U8.clone();
        let mut once_upto_u16 = NONEUPTO_U16.clone();

        once_upto_u8[0] = 0x01;
        once_upto_u16[0] = 0x01;

        let dec2: Occurrences = Occurrences::confined_decode(&once_upto_u16[..]).unwrap();

        assert_eq!(dec2, Occurrences::OnceOrMore);

        let wc2: Occurrences = Occurrences::confined_decode(&once_upto_u8[..]).unwrap();

        assert_eq!(wc2, Occurrences::OnceOrUpTo(255));
    }
}

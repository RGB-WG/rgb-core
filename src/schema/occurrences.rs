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

use std::io;
use std::ops::RangeInclusive;

use strict_encoding::{
    DecodeError, ReadStruct, StrictDecode, StrictEncode, StrictProduct, StrictStruct, StrictType,
    TypeName, TypedRead, TypedWrite, WriteStruct,
};

use crate::LIB_NAME_RGB;

#[derive(Clone, PartialEq, Eq, Hash, Debug, Default)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[repr(u8)]
pub enum Occurrences {
    #[default]
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

    pub fn check(&self, count: u16) -> Result<(), OccurrencesMismatch> {
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
            _ => Err(OccurrencesMismatch {
                min: self.min_value(),
                max: self.max_value(),
                found: orig_count,
            }),
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error)]
#[display(doc_comments)]
pub enum OccurrencesError {
    /// unable to construct occurrences value with both minimum and maximum
    /// number set to zero.
    Zero,

    /// unable to construct occurrences value with minimum number exceeding
    /// maximum
    MinExceedsMax,
}

impl TryFrom<RangeInclusive<u16>> for Occurrences {
    type Error = OccurrencesError;

    fn try_from(range: RangeInclusive<u16>) -> Result<Self, Self::Error> {
        Ok(match (*range.start(), *range.end()) {
            (0, 0) => return Err(OccurrencesError::Zero),
            (a, b) if a > b => return Err(OccurrencesError::MinExceedsMax),
            (0, 1) => Occurrences::NoneOrOnce,
            (1, 1) => Occurrences::Once,
            (0, u16::MAX) => Occurrences::NoneOrMore,
            (1, u16::MAX) => Occurrences::OnceOrMore,
            (0, max) => Occurrences::NoneOrUpTo(max),
            (1, max) => Occurrences::OnceOrUpTo(max),
            (a, b) if a == b => Occurrences::Exactly(a),
            (min, max) => Occurrences::Range(min..=max),
        })
    }
}

impl StrictType for Occurrences {
    const STRICT_LIB_NAME: &'static str = LIB_NAME_RGB;
    fn strict_name() -> Option<TypeName> { Some(tn!("Occurrences")) }
}
impl StrictProduct for Occurrences {}
impl StrictStruct for Occurrences {
    const ALL_FIELDS: &'static [&'static str] = &["min", "max"];
}
impl StrictEncode for Occurrences {
    fn strict_encode<W: TypedWrite>(&self, writer: W) -> io::Result<W> {
        writer.write_struct::<Self>(|w| {
            Ok(w.write_field(fname!("min"), &self.min_value())?
                .write_field(fname!("max"), &self.max_value())?
                .complete())
        })
    }
}
impl StrictDecode for Occurrences {
    fn strict_decode(reader: &mut impl TypedRead) -> Result<Self, DecodeError> {
        reader.read_struct(|r| {
            let min = r.read_field(fname!("min"))?;
            let max = r.read_field(fname!("max"))?;
            Occurrences::try_from(min..=max)
                .map_err(|err| DecodeError::DataIntegrityError(err.to_string()))
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Display)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
#[display(Debug)]
pub struct OccurrencesMismatch {
    pub min: u16,
    pub max: u16,
    pub found: u16,
}

#[cfg(test)]
mod test {
    use super::Occurrences;

    #[test]
    fn test_once_check_count() {
        let occurence: Occurrences = Occurrences::Once;
        occurence.check(1).unwrap();
    }
    #[test]
    #[should_panic(expected = "OccurrencesMismatch { min: 1, max: 1, found: 0 }")]
    fn test_once_check_count_fail_zero() {
        let occurence: Occurrences = Occurrences::Once;
        occurence.check(0).unwrap();
    }
    #[test]
    #[should_panic(expected = "OccurrencesMismatch { min: 1, max: 1, found: 2 }")]
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
    #[should_panic(expected = "OccurrencesMismatch { min: 0, max: 1, found: 2 }")]
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
    #[should_panic(expected = "OccurrencesMismatch { min: 1, max: 65535, found: 0 }")]
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
    #[should_panic(expected = "OccurrencesMismatch { min: 1, max: 42, found: 43 }")]
    fn test_once_or_up_to_42_large() {
        let occurence: Occurrences = Occurrences::OnceOrUpTo(42);
        occurence.check(43).unwrap();
    }
    #[test]
    #[should_panic(expected = "OccurrencesMismatch { min: 1, max: 42, found: 0 }")]
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
    #[should_panic(expected = "OccurrencesMismatch { min: 0, max: 42, found: 43 }")]
    fn test_none_or_up_to_42_large() {
        let occurence: Occurrences = Occurrences::NoneOrUpTo(42);
        occurence.check(43).unwrap();
    }
}

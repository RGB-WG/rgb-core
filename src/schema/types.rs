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

use num_traits::ToPrimitive;
use std::io;

pub trait UnsignedInteger:
    Clone + Copy + PartialEq + Eq + PartialOrd + Ord + Into<u64> + std::fmt::Debug
{
    const MAX: Self;

    fn as_u64(self) -> u64 {
        self.into()
    }

    fn bits() -> Bits;
}

impl UnsignedInteger for u8 {
    const MAX: Self = core::u8::MAX;

    #[inline]
    fn bits() -> Bits {
        Bits::Bit8
    }
}
impl UnsignedInteger for u16 {
    const MAX: Self = core::u16::MAX;

    #[inline]
    fn bits() -> Bits {
        Bits::Bit16
    }
}
impl UnsignedInteger for u32 {
    const MAX: Self = core::u32::MAX;

    #[inline]
    fn bits() -> Bits {
        Bits::Bit32
    }
}
impl UnsignedInteger for u64 {
    const MAX: Self = core::u64::MAX;

    #[inline]
    fn bits() -> Bits {
        Bits::Bit64
    }
}

pub trait Number:
    Clone + Copy + PartialEq + PartialOrd + std::fmt::Debug
{
}

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
    serde(crate = "serde_crate", rename_all = "lowercase")
)]
#[display(Debug)]
#[repr(u8)]
#[non_exhaustive]
pub enum Bits {
    Bit8 = 1,
    Bit16 = 2,
    Bit32 = 4,
    Bit64 = 8,
    /* TODO: Add support later once bitcoin library will start supporting
     *       consensus-encoding of the native rust `u128` type
     *Bit128 = 16,
     *Bit256 = 32, */
}

impl Bits {
    pub fn max_value(&self) -> u128 {
        match *self {
            Bits::Bit8 => core::u8::MAX as u128,
            Bits::Bit16 => core::u16::MAX as u128,
            Bits::Bit32 => core::u32::MAX as u128,
            Bits::Bit64 => core::u64::MAX as u128,
            //Bits::Bit128 => core::u128::MAX as u128,
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

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[display(Debug)]
#[repr(u8)]
#[non_exhaustive]
pub enum Occurences {
    Once,
    NoneOrOnce,
    NoneOrMore,
    OnceOrMore,
    NoneOrUpTo(u16),
    OnceOrUpTo(u16),
    Exactly(u16),
    Range(RangeInclusive<u16>),
}

impl Occurences {
    pub fn min_value(&self) -> u16 {
        match self {
            Occurences::Once => 1,
            Occurences::NoneOrOnce => 0,
            Occurences::NoneOrMore => 0,
            Occurences::OnceOrMore => 1,
            Occurences::NoneOrUpTo(_) => 0,
            Occurences::OnceOrUpTo(_) => 1,
            Occurences::Exactly(val) => *val,
            Occurences::Range(range) => *range.start(),
        }
    }

    pub fn max_value(&self) -> u16 {
        match self {
            Occurences::Once | Occurences::NoneOrOnce => 1,
            Occurences::NoneOrMore | Occurences::OnceOrMore => core::u16::MAX,
            Occurences::OnceOrUpTo(max) | Occurences::NoneOrUpTo(max) => *max,
            Occurences::Exactly(val) => *val,
            Occurences::Range(range) => *range.end(),
        }
    }

    pub fn check(&self, count: u16) -> Result<(), OccurrencesError> {
        let orig_count = count;
        if count > core::u16::MAX.into() {
            Err(OccurrencesError {
                min: self.min_value().into(),
                max: self.max_value().into(),
                found: count.into(),
            })?
        }
        match self {
            Occurences::Once if count == 1 => Ok(()),
            Occurences::NoneOrOnce if count <= 1 => Ok(()),
            Occurences::OnceOrMore if count > 0 => Ok(()),
            Occurences::OnceOrUpTo(max) if count > 0 && count <= *max => Ok(()),
            Occurences::NoneOrMore => Ok(()),
            Occurences::NoneOrUpTo(max) if count <= *max => Ok(()),
            Occurences::Exactly(val) if count == *val => Ok(()),
            Occurences::Range(range) if range.contains(&count) => Ok(()),
            _ => Err(OccurrencesError {
                min: self.min_value().into(),
                max: self.max_value().into(),
                found: orig_count.into(),
            }),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Display)]
#[display(Debug)]
pub struct OccurrencesError {
    pub min: u16,
    pub max: u16,
    pub found: u16,
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
    serde(crate = "serde_crate", rename_all = "lowercase")
)]
#[display(Debug)]
#[repr(u8)]
#[non_exhaustive]
pub enum DigestAlgorithm {
    // Single-path RIPEMD-160 is not secure and should not be used; see
    // <https://eprint.iacr.org/2004/199.pdf>
    //Ripemd160 = 0b_0000_1000_u8,
    Sha256 = 0b_0001_0001_u8,
    Sha512 = 0b_0001_0010_u8,
    Bitcoin160 = 0b_0100_1000_u8,
    Bitcoin256 = 0b_0101_0001_u8,
    /* Each tagged hash is a type on it's own, so the following umbrella
     * type was removed; a plain sha256 type must be used instead
     *Tagged256 = 0b_1100_0000_u8, */
}

pub mod elliptic_curve {
    use num_derive::{FromPrimitive, ToPrimitive};

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
        serde(crate = "serde_crate", rename_all = "lowercase")
    )]
    #[display(Debug)]
    #[repr(u8)]
    #[non_exhaustive]
    pub enum EllipticCurve {
        Secp256k1 = 0x00,
        Curve25519 = 0x10,
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
        serde(crate = "serde_crate", rename_all = "lowercase")
    )]
    #[display(Debug)]
    #[repr(u8)]
    #[non_exhaustive]
    pub enum SignatureAlgorithm {
        Ecdsa = 0,
        Schnorr,
        Ed25519,
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
        serde(crate = "serde_crate", rename_all = "lowercase")
    )]
    #[display(Debug)]
    #[repr(u8)]
    #[non_exhaustive]
    pub enum PointSerialization {
        Uncompressed = 0,
        Compressed,
        Bip340,
    }
}
use bitcoin::hashes::core::ops::RangeInclusive;
pub use elliptic_curve::EllipticCurve;

mod strict_encoding {
    use super::*;
    use lnpbp::strict_encoding::{Error, StrictDecode, StrictEncode};

    impl_enum_strict_encoding!(DigestAlgorithm);
    impl_enum_strict_encoding!(Bits);
    impl_enum_strict_encoding!(EllipticCurve);
    impl_enum_strict_encoding!(elliptic_curve::SignatureAlgorithm);
    impl_enum_strict_encoding!(elliptic_curve::PointSerialization);

    impl StrictEncode for Occurences {
        fn strict_encode<E: io::Write>(
            &self,
            mut e: E,
        ) -> Result<usize, Error> {
            let (min, max) = match self {
                Occurences::NoneOrOnce => (0, 1),
                Occurences::Once => (1, 1),
                Occurences::NoneOrMore => (0, core::u16::MAX.into()),
                Occurences::OnceOrMore => (1, core::u16::MAX.into()),
                Occurences::NoneOrUpTo(max) => (0, *max),
                Occurences::OnceOrUpTo(max) => (1, *max),
                Occurences::Exactly(val) => (*val, *val),
                Occurences::Range(range) => (*range.start(), *range.end()),
            };
            Ok(min.strict_encode(&mut e)? + max.strict_encode(&mut e)?)
        }
    }

    impl StrictDecode for Occurences {
        #[allow(unused_comparisons)]
        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
            let min = u16::strict_decode(&mut d)?;
            let max = u16::strict_decode(&mut d)?;
            Ok(match (min, max) {
                (0, 1) => Occurences::NoneOrOnce,
                (1, 1) => Occurences::Once,
                (0, max) if max == ::core::u16::MAX => Occurences::NoneOrMore,
                (1, max) if max == ::core::u16::MAX => Occurences::OnceOrMore,
                (0, max) if max > 0 => Occurences::NoneOrUpTo(max),
                (1, max) if max > 0 => Occurences::OnceOrUpTo(max),
                (min, max) if min == max => Occurences::Exactly(min),
                (min, max) => Occurences::Range(min..=max),
            })
        }
    }
}

#[cfg(test)]
mod test {
    use super::Occurences;
    use super::*;
    use lnpbp::strict_encoding::StrictDecode;
    use lnpbp::test_helpers::*;

    static ONCE: [u8; 4] = [1, 0, 1, 0];

    static NONEORONCE: [u8; 4] = [0, 0, 1, 0];

    static NONEUPTO_U8: [u8; 4] = [0, 0, 255, 0];

    static NONEUPTO_U16: [u8; 4] = [0, 0, 255, 255];

    #[test]
    fn test_once_check_count() {
        let occurence: Occurences = Occurences::Once;
        occurence.check(1).unwrap();
    }
    #[test]
    #[should_panic(expected = "OccurrencesError { min: 1, max: 1, found: 0 }")]
    fn test_once_check_count_fail_zero() {
        let occurence: Occurences = Occurences::Once;
        occurence.check(0).unwrap();
    }
    #[test]
    #[should_panic(expected = "OccurrencesError { min: 1, max: 1, found: 2 }")]
    fn test_once_check_count_fail_two() {
        let occurence: Occurences = Occurences::Once;
        occurence.check(2).unwrap();
    }

    #[test]
    fn test_none_or_once_check_count() {
        let occurence: Occurences = Occurences::NoneOrOnce;
        occurence.check(1).unwrap();
    }
    #[test]
    fn test_none_or_once_check_count_zero() {
        let occurence: Occurences = Occurences::NoneOrOnce;
        occurence.check(0).unwrap();
    }
    #[test]
    #[should_panic(expected = "OccurrencesError { min: 0, max: 1, found: 2 }")]
    fn test_none_or_once_check_count_fail_two() {
        let occurence: Occurences = Occurences::NoneOrOnce;
        occurence.check(2).unwrap();
    }

    #[test]
    fn test_once_or_up_to_none() {
        let occurence: Occurences = Occurences::OnceOrMore;
        occurence.check(1).unwrap();
    }
    #[test]
    fn test_once_or_up_to_none_large() {
        let occurence: Occurences = Occurences::OnceOrMore;
        occurence.check(core::u16::MAX).unwrap();
    }
    #[test]
    #[should_panic(
        expected = "OccurrencesError { min: 1, max: 65535, found: 0 }"
    )]
    fn test_once_or_up_to_none_fail_zero() {
        let occurence: Occurences = Occurences::OnceOrMore;
        occurence.check(0).unwrap();
    }
    #[test]
    fn test_once_or_up_to_42() {
        let occurence: Occurences = Occurences::OnceOrUpTo(42);
        occurence.check(42).unwrap();
    }
    #[test]
    #[should_panic(
        expected = "OccurrencesError { min: 1, max: 42, found: 43 }"
    )]
    fn test_once_or_up_to_42_large() {
        let occurence: Occurences = Occurences::OnceOrUpTo(42);
        occurence.check(43).unwrap();
    }
    #[test]
    #[should_panic(expected = "OccurrencesError { min: 1, max: 42, found: 0 }")]
    fn test_once_or_up_to_42_fail_zero() {
        let occurence: Occurences = Occurences::OnceOrUpTo(42);
        occurence.check(0).unwrap();
    }

    #[test]
    fn test_none_or_up_to_none_zero() {
        let occurence: Occurences = Occurences::NoneOrMore;
        occurence.check(0).unwrap();
    }
    #[test]
    fn test_none_or_up_to_none_large() {
        let occurence: Occurences = Occurences::NoneOrMore;
        occurence.check(core::u16::MAX).unwrap();
    }
    #[test]
    fn test_none_or_up_to_42_zero() {
        let occurence: Occurences = Occurences::NoneOrMore;
        occurence.check(0).unwrap();
    }
    #[test]
    fn test_none_or_up_to_42() {
        let occurence: Occurences = Occurences::NoneOrMore;
        occurence.check(42).unwrap();
    }
    #[test]
    #[should_panic(
        expected = "OccurrencesError { min: 0, max: 42, found: 43 }"
    )]
    fn test_none_or_up_to_42_large() {
        let occurence: Occurences = Occurences::NoneOrUpTo(42);
        occurence.check(43).unwrap();
    }

    #[test]
    fn test_encode_occurance() {
        test_encode!((ONCE, Occurences), (NONEORONCE, Occurences));

        test_encode!((NONEUPTO_U16, Occurences));
    }

    #[test]
    fn test_encode_occurance_2() {
        let mut once_upto_u8 = NONEUPTO_U8.clone();
        let mut once_upto_u16 = NONEUPTO_U16.clone();

        once_upto_u8[0] = 0x01;
        once_upto_u16[0] = 0x01;

        let dec2: Occurences =
            Occurences::strict_decode(&once_upto_u16[..]).unwrap();

        assert_eq!(dec2, Occurences::OnceOrMore);

        let wc2: Occurences =
            Occurences::strict_decode(&once_upto_u8[..]).unwrap();

        assert_eq!(wc2, Occurences::OnceOrUpTo(255));
    }

    #[test]
    fn test_digest_algorithm() {
        let sha256 = DigestAlgorithm::Sha256;
        let sha512 = DigestAlgorithm::Sha512;
        let bitcoin160 = DigestAlgorithm::Bitcoin160;
        let bitcoin256 = DigestAlgorithm::Bitcoin256;

        print_bytes(&sha256);
        print_bytes(&sha512);
        print_bytes(&bitcoin160);
        print_bytes(&bitcoin256);

        let sha256_byte: [u8; 1] = [0x11];
        let sha512_byte: [u8; 1] = [0x12];
        let bitcoin160_byte: [u8; 1] = [0x48];
        let bitcoin256_byte: [u8; 1] = [0x51];

        test_encode!(
            (sha256_byte, DigestAlgorithm),
            (sha512_byte, DigestAlgorithm),
            (bitcoin160_byte, DigestAlgorithm),
            (bitcoin256_byte, DigestAlgorithm)
        );

        let sha256 = DigestAlgorithm::strict_decode(&[0x11][..]).unwrap();
        let sha512 = DigestAlgorithm::strict_decode(&[0x12][..]).unwrap();
        let bitcoin160 = DigestAlgorithm::strict_decode(&[0x48][..]).unwrap();
        let bitcoin256 = DigestAlgorithm::strict_decode(&[0x51][..]).unwrap();

        assert_eq!(sha256, DigestAlgorithm::Sha256);
        assert_eq!(sha512, DigestAlgorithm::Sha512);
        assert_eq!(bitcoin160, DigestAlgorithm::Bitcoin160);
        assert_eq!(bitcoin256, DigestAlgorithm::Bitcoin256);
    }

    #[test]
    #[should_panic(expected = "EnumValueNotKnown")]
    fn test_digest_panic() {
        DigestAlgorithm::strict_decode(&[0x17][..]).unwrap();
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
    fn test_bits_panic() {
        Bits::strict_decode(&[0x12][..]).unwrap();
    }

    #[test]
    fn test_elliptic_curve() {
        let secp: [u8; 1] = [0x00];
        let c25519: [u8; 1] = [0x10];

        test_encode!(
            (secp, elliptic_curve::EllipticCurve),
            (c25519, elliptic_curve::EllipticCurve)
        );

        assert_eq!(
            elliptic_curve::EllipticCurve::strict_decode(&[0x00][..]).unwrap(),
            elliptic_curve::EllipticCurve::Secp256k1
        );

        assert_eq!(
            elliptic_curve::EllipticCurve::strict_decode(&[0x10][..]).unwrap(),
            elliptic_curve::EllipticCurve::Curve25519
        );
    }

    #[test]
    #[should_panic(expected = "EnumValueNotKnown")]
    fn test_elliptic_curve_panic() {
        elliptic_curve::EllipticCurve::strict_decode(&[0x09][..]).unwrap();
    }

    #[test]
    fn test_signature_algo() {
        let ecdsa_byte: [u8; 1] = [0x00];
        let schnorr_byte: [u8; 1] = [0x01];
        let ed25519_byte: [u8; 1] = [0x02];

        test_encode!(
            (ecdsa_byte, elliptic_curve::SignatureAlgorithm),
            (schnorr_byte, elliptic_curve::SignatureAlgorithm),
            (ed25519_byte, elliptic_curve::SignatureAlgorithm)
        );

        let ecdsa =
            elliptic_curve::SignatureAlgorithm::strict_decode(&[0x00][..])
                .unwrap();
        let schnorr =
            elliptic_curve::SignatureAlgorithm::strict_decode(&[0x01][..])
                .unwrap();
        let ed25519 =
            elliptic_curve::SignatureAlgorithm::strict_decode(&[0x02][..])
                .unwrap();

        assert_eq!(ecdsa, elliptic_curve::SignatureAlgorithm::Ecdsa);
        assert_eq!(schnorr, elliptic_curve::SignatureAlgorithm::Schnorr);
        assert_eq!(ed25519, elliptic_curve::SignatureAlgorithm::Ed25519);
    }

    #[test]
    #[should_panic(expected = "EnumValueNotKnown")]
    fn test_signature_algo_panic() {
        elliptic_curve::SignatureAlgorithm::strict_decode(&[0x03][..]).unwrap();
    }

    #[test]
    fn test_point_ser() {
        let uncompressed_byte: [u8; 1] = [0x00];
        let compressed_byte: [u8; 1] = [0x01];
        let schnorr_bip_byte: [u8; 1] = [0x02];

        test_encode!(
            (uncompressed_byte, elliptic_curve::PointSerialization),
            (compressed_byte, elliptic_curve::PointSerialization),
            (schnorr_bip_byte, elliptic_curve::PointSerialization)
        );

        assert_eq!(
            elliptic_curve::PointSerialization::strict_decode(&[0x00][..])
                .unwrap(),
            elliptic_curve::PointSerialization::Uncompressed
        );

        assert_eq!(
            elliptic_curve::PointSerialization::strict_decode(&[0x01][..])
                .unwrap(),
            elliptic_curve::PointSerialization::Compressed
        );

        assert_eq!(
            elliptic_curve::PointSerialization::strict_decode(&[0x02][..])
                .unwrap(),
            elliptic_curve::PointSerialization::Bip340
        );
    }

    #[test]
    #[should_panic(expected = "EnumValueNotKnown")]
    fn test_point_ser_panic() {
        elliptic_curve::PointSerialization::strict_decode(&[0x03][..]).unwrap();
    }

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

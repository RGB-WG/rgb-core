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

use core::any::Any;
use core::cmp::Ordering;
use core::fmt::Debug;
use std::io;

use amplify::AsAny;
use bitcoin::hashes::{hash160, Hash};
use commit_verify::{commit_encode, CommitConceal, CommitEncode};
use strict_encoding::strict_serialize;

use super::{ConfidentialState, RevealedState};

/// Struct using for storing Void (i.e. absent) state
#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq, AsAny)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct Void;

impl ConfidentialState for Void {}

impl RevealedState for Void {}

impl CommitConceal for Void {
    type ConcealedCommitment = Void;

    fn commit_conceal(&self) -> Self::ConcealedCommitment { self.clone() }
}
impl CommitEncode for Void {
    fn commit_encode<E: io::Write>(&self, _e: E) -> usize { 0 }
}

#[derive(Clone, Debug, Display, AsAny)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "lowercase")
)]
#[display(Debug)]
#[non_exhaustive]
pub enum Revealed {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    // TODO #15: Add support for u256
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    I128(i128),
    // TODO #15: Add support for i256
    F32(f32),
    F64(f64),
    Bytes(Vec<u8>),
    String(String),
}

impl RevealedState for Revealed {}

impl CommitConceal for Revealed {
    type ConcealedCommitment = Confidential;

    fn commit_conceal(&self) -> Self::ConcealedCommitment {
        Confidential::hash(
            &strict_serialize(self).expect("Encoding of predefined data types must not fail"),
        )
    }
}
impl commit_encode::Strategy for Revealed {
    type Strategy = commit_encode::strategies::UsingConceal;
}

impl PartialEq for Revealed {
    fn eq(&self, other: &Self) -> bool {
        let some = strict_serialize(self).expect("Encoding of predefined data types must not fail");
        let other =
            strict_serialize(other).expect("Encoding of predefined data types must not fail");
        some.eq(&other)
    }
}

impl Eq for Revealed {}

impl PartialOrd for Revealed {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let some = strict_serialize(self).expect("Encoding of predefined data types must not fail");
        let other =
            strict_serialize(other).expect("Encoding of predefined data types must not fail");
        some.partial_cmp(&other)
    }
}

impl Ord for Revealed {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).unwrap_or_else(|| {
            let some =
                strict_serialize(self).expect("Encoding of predefined data types must not fail");
            let other =
                strict_serialize(other).expect("Encoding of predefined data types must not fail");
            some.cmp(&other)
        })
    }
}

// # Security analysis
//
// While RIPEMD-160 collision security is not perfect and a
// [known attack exists](https://eprint.iacr.org/2004/199.pdf)
// for our purposes it still works well. First, we use SHA-256 followed by
// RIPEMD-160 (known as bitcoin hash 160 function), and even if a collision for
// a resulting RIPEMD-160 hash would be known, to fake the commitment we still
// and present verifier with some alternative data we have to find a SHA-256
// collision for RIPEMD-160 preimage with meaningful SHA-256 preimage, which
// requires us to break SHA-256 collision resistance. Second, when we transfer
// the confidential state data, they will occupy space, and 20 bytes of hash
// is much better than 32 bytes, especially for low-profile original state data
// (like numbers).
hash_newtype!(
    Confidential,
    hash160::Hash,
    20,
    doc = "Confidential representation of data"
);

impl ConfidentialState for Confidential {}

impl AsAny for Confidential {
    fn as_any(&self) -> &dyn Any { self as &dyn Any }
}

impl commit_encode::Strategy for Confidential {
    type Strategy = commit_encode::strategies::UsingStrict;
}

impl Revealed {
    pub fn u8(&self) -> Option<u8> {
        match self {
            Revealed::U8(val) => Some(*val),
            _ => None,
        }
    }
    pub fn u16(&self) -> Option<u16> {
        match self {
            Revealed::U16(val) => Some(*val),
            _ => None,
        }
    }
    pub fn u32(&self) -> Option<u32> {
        match self {
            Revealed::U32(val) => Some(*val),
            _ => None,
        }
    }
    pub fn u64(&self) -> Option<u64> {
        match self {
            Revealed::U64(val) => Some(*val),
            _ => None,
        }
    }
    pub fn i8(&self) -> Option<i8> {
        match self {
            Revealed::I8(val) => Some(*val),
            _ => None,
        }
    }
    pub fn i16(&self) -> Option<i16> {
        match self {
            Revealed::I16(val) => Some(*val),
            _ => None,
        }
    }
    pub fn i32(&self) -> Option<i32> {
        match self {
            Revealed::I32(val) => Some(*val),
            _ => None,
        }
    }
    pub fn i64(&self) -> Option<i64> {
        match self {
            Revealed::I64(val) => Some(*val),
            _ => None,
        }
    }
    pub fn f32(&self) -> Option<f32> {
        match self {
            Revealed::F32(val) => Some(*val),
            _ => None,
        }
    }
    pub fn f64(&self) -> Option<f64> {
        match self {
            Revealed::F64(val) => Some(*val),
            _ => None,
        }
    }
    pub fn bytes(&self) -> Option<Vec<u8>> {
        match self {
            Revealed::Bytes(val) => Some(val.clone()),
            _ => None,
        }
    }
    pub fn string(&self) -> Option<String> {
        match self {
            Revealed::String(val) => Some(val.clone()),
            _ => None,
        }
    }
}

pub(super) mod _strict_encoding {
    use std::io;

    use strict_encoding::{strategies, Error, Strategy, StrictDecode, StrictEncode};

    use super::*;

    impl Strategy for Confidential {
        type Strategy = strategies::HashFixedBytes;
    }

    #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, FromPrimitive, ToPrimitive, Debug)]
    #[repr(u8)]
    pub enum EncodingTag {
        U8 = 0b_0000_0000_u8,
        U16 = 0b_0000_0001_u8,
        U32 = 0b_0000_0010_u8,
        U64 = 0b_0000_0011_u8,
        U128 = 0b_0000_0100_u8,
        I8 = 0b_0000_1000_u8,
        I16 = 0b_0000_1001_u8,
        I32 = 0b_0000_1010_u8,
        I64 = 0b_0000_1011_u8,
        I128 = 0b_0000_1100_u8,
        F32 = 0b_0001_0010_u8,
        F64 = 0b_0001_0011_u8,

        Bytes = 0b_0010_0000_u8,
        String = 0b_0010_0001_u8,
    }
    impl_enum_strict_encoding!(EncodingTag);

    impl StrictEncode for Void {
        fn strict_encode<E: io::Write>(&self, _: E) -> Result<usize, Error> { Ok(0) }
    }

    impl StrictDecode for Void {
        fn strict_decode<D: io::Read>(_: D) -> Result<Self, Error> { Ok(Void) }
    }

    impl StrictEncode for Revealed {
        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
            Ok(match self {
                Revealed::U8(val) => {
                    strict_encode_list!(e; EncodingTag::U8, val)
                }
                Revealed::U16(val) => {
                    strict_encode_list!(e; EncodingTag::U16, val)
                }
                Revealed::U32(val) => {
                    strict_encode_list!(e; EncodingTag::U32, val)
                }
                Revealed::U64(val) => {
                    strict_encode_list!(e; EncodingTag::U64, val)
                }
                Revealed::U128(val) => {
                    strict_encode_list!(e; EncodingTag::U128, val)
                }
                Revealed::I8(val) => {
                    strict_encode_list!(e; EncodingTag::I8, val)
                }
                Revealed::I16(val) => {
                    strict_encode_list!(e; EncodingTag::I16, val)
                }
                Revealed::I32(val) => {
                    strict_encode_list!(e; EncodingTag::I32, val)
                }
                Revealed::I64(val) => {
                    strict_encode_list!(e; EncodingTag::I64, val)
                }
                Revealed::I128(val) => {
                    strict_encode_list!(e; EncodingTag::I128, val)
                }
                Revealed::F32(val) => {
                    strict_encode_list!(e; EncodingTag::F32, val)
                }
                Revealed::F64(val) => {
                    strict_encode_list!(e; EncodingTag::F64, val)
                }
                Revealed::Bytes(val) => {
                    strict_encode_list!(e; EncodingTag::Bytes, val)
                }
                Revealed::String(val) => {
                    strict_encode_list!(e; EncodingTag::String, val)
                }
            })
        }
    }

    impl StrictDecode for Revealed {
        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
            let format = EncodingTag::strict_decode(&mut d)?;
            Ok(match format {
                EncodingTag::U8 => Revealed::U8(u8::strict_decode(&mut d)?),
                EncodingTag::U16 => Revealed::U16(u16::strict_decode(&mut d)?),
                EncodingTag::U32 => Revealed::U32(u32::strict_decode(&mut d)?),
                EncodingTag::U64 => Revealed::U64(u64::strict_decode(&mut d)?),
                EncodingTag::U128 => Revealed::U128(u128::strict_decode(&mut d)?),
                EncodingTag::I8 => Revealed::I8(i8::strict_decode(&mut d)?),
                EncodingTag::I16 => Revealed::I16(i16::strict_decode(&mut d)?),
                EncodingTag::I32 => Revealed::I32(i32::strict_decode(&mut d)?),
                EncodingTag::I64 => Revealed::I64(i64::strict_decode(&mut d)?),
                EncodingTag::I128 => Revealed::I128(i128::strict_decode(&mut d)?),
                EncodingTag::F32 => Revealed::F32(f32::strict_decode(&mut d)?),
                EncodingTag::F64 => Revealed::F64(f64::strict_decode(&mut d)?),
                EncodingTag::Bytes => Revealed::Bytes(Vec::strict_decode(&mut d)?),
                EncodingTag::String => Revealed::String(String::strict_decode(&mut d)?),
            })
        }
    }

    #[cfg(test)]
    mod test {
        use super::EncodingTag;

        #[test]
        fn test_enum_encodingtag_exhaustive() {
            test_encoding_enum_u8_exhaustive!(EncodingTag;
                EncodingTag::U8 => 0b_0000_0000_u8,
                EncodingTag::U16 => 0b_0000_0001_u8,
                EncodingTag::U32 => 0b_0000_0010_u8,
                EncodingTag::U64 => 0b_0000_0011_u8,
                EncodingTag::U128 => 0b_0000_0100_u8,
                EncodingTag::I8 => 0b_0000_1000_u8,
                EncodingTag::I16 => 0b_0000_1001_u8,
                EncodingTag::I32 => 0b_0000_1010_u8,
                EncodingTag::I64 => 0b_0000_1011_u8,
                EncodingTag::I128 => 0b_0000_1100_u8,
                EncodingTag::F32 => 0b_0001_0010_u8,
                EncodingTag::F64 => 0b_0001_0011_u8,

                EncodingTag::Bytes => 0b_0010_0000_u8,
                EncodingTag::String => 0b_0010_0001_u8,
            )
            .unwrap();
        }
    }
}

#[cfg(test)]
mod test {
    use strict_encoding::StrictDecode;

    use super::super::test::test_confidential;
    use super::*;

    // Hard coded test vectors
    static U_8: [u8; 2] = [0x0, 0x8];
    static U_16: [u8; 3] = [0x1, 0x10, 0x0];
    static U_32: [u8; 5] = [0x2, 0x20, 0x0, 0x0, 0x0];
    static U_64: [u8; 9] = [0x3, 0x40, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0];
    static I_8: [u8; 2] = [0x8, 0x8];
    static I_16: [u8; 3] = [0x9, 0x10, 0x0];
    static I_32: [u8; 5] = [0xa, 0x20, 0x0, 0x0, 0x0];
    static I_64: [u8; 9] = [0xb, 0x40, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0];
    static F_32: [u8; 5] = [0x12, 0x14, 0xae, 0x2, 0x42];
    static F_64: [u8; 9] = [0x13, 0x7b, 0x14, 0xae, 0x47, 0xe1, 0x2a, 0x50, 0x40];
    static BYTES: [u8; 36] = [
        0x20, 0x21, 0x0, 0x7c, 0x66, 0xc0, 0x28, 0x3e, 0xe9, 0xbe, 0x98, 0xe, 0x29, 0xce, 0x32,
        0x5a, 0xf, 0x46, 0x79, 0xef, 0x87, 0x28, 0x8e, 0xd7, 0x3c, 0xe4, 0x7f, 0xc4, 0xf5, 0xc7,
        0x9d, 0x19, 0xeb, 0xfa, 0x57, 0xda,
    ];
    static STRING: [u8; 20] = [
        0x21, 0x11, 0x0, 0x45, 0x54, 0x48, 0x20, 0x49, 0x53, 0x20, 0x41, 0x20, 0x53, 0x45, 0x43,
        0x55, 0x52, 0x49, 0x54, 0x59,
    ];

    static U8_CONCEALED: [u8; 20] = [
        0x99, 0x3c, 0xfd, 0x1, 0x69, 0xe, 0xa0, 0xa8, 0xb2, 0x83, 0x1e, 0xf0, 0x25, 0x36, 0xce,
        0xed, 0x3e, 0x9b, 0xbf, 0x80,
    ];
    static U16_CONCEALED: [u8; 20] = [
        0x73, 0x36, 0xe0, 0x2b, 0x7, 0x8f, 0x8c, 0xb1, 0xb9, 0x5b, 0x27, 0x3c, 0x92, 0xc1, 0x80,
        0x95, 0xa, 0xa3, 0x26, 0xf7,
    ];
    static U32_CONCEALED: [u8; 20] = [
        0xf7, 0xcf, 0xbd, 0x3b, 0xac, 0xa1, 0x4e, 0xf, 0xc7, 0xea, 0xd0, 0xc7, 0xd5, 0xb0, 0x8c,
        0xba, 0xbd, 0x41, 0xc4, 0x3f,
    ];
    static U64_CONCEALED: [u8; 20] = [
        0x2, 0x5f, 0x33, 0x8f, 0x5a, 0x45, 0x89, 0xd4, 0xe, 0x56, 0x47, 0xe8, 0xfc, 0xb3, 0x6b,
        0x7f, 0xc4, 0x29, 0x92, 0x71,
    ];
    static I8_CONCEALED: [u8; 20] = [
        0xf5, 0x39, 0x1f, 0xf2, 0x83, 0x2b, 0xc6, 0xb1, 0x78, 0x59, 0x54, 0x14, 0x28, 0xbf, 0xc1,
        0x49, 0xf6, 0xcf, 0xd7, 0x78,
    ];
    static I16_CONCEALED: [u8; 20] = [
        0x61, 0x0, 0xc2, 0x37, 0x7, 0x97, 0x33, 0xf, 0xcf, 0xbb, 0x40, 0xcb, 0xad, 0xf7, 0x81,
        0x7e, 0x10, 0xd, 0x55, 0xa5,
    ];
    static I32_CONCEALED: [u8; 20] = [
        0xaa, 0xbe, 0x9b, 0x73, 0xf8, 0xfa, 0x84, 0x9d, 0x28, 0x79, 0x8b, 0x5c, 0x13, 0x91, 0xe9,
        0xbf, 0xc8, 0xa4, 0x2a, 0xc3,
    ];
    static I64_CONCEALED: [u8; 20] = [
        0xd, 0x56, 0xef, 0xcb, 0x53, 0xba, 0xd5, 0x52, 0xb, 0xc6, 0xea, 0x4f, 0xe1, 0xa8, 0x56,
        0x42, 0x3d, 0x66, 0x34, 0xc5,
    ];
    static F32_CONCEALED: [u8; 20] = [
        0xa2, 0xb0, 0x80, 0x82, 0xa9, 0x52, 0xa5, 0x41, 0xb8, 0xbd, 0x2, 0xd4, 0x29, 0xf0, 0x90,
        0xca, 0x8b, 0xa4, 0x5d, 0xfc,
    ];
    static F64_CONCEALED: [u8; 20] = [
        0x5f, 0xe8, 0xdd, 0xd4, 0xca, 0x55, 0x41, 0x14, 0x50, 0x24, 0xcf, 0x85, 0x8c, 0xb4, 0x11,
        0x5d, 0x9f, 0x8a, 0xaf, 0x87,
    ];
    static BYTES_CONCEALED: [u8; 20] = [
        0xf, 0x33, 0xe5, 0xdf, 0x8, 0x7c, 0x5c, 0xef, 0x5f, 0xae, 0xbe, 0x76, 0x76, 0xd9, 0xe7,
        0xa6, 0xb8, 0x2b, 0x4a, 0x99,
    ];
    static STRING_CONCEALED: [u8; 20] = [
        0xf8, 0x3b, 0x1b, 0xcd, 0xd8, 0x82, 0x55, 0xe1, 0xf9, 0x37, 0x52, 0xeb, 0x20, 0x90, 0xfe,
        0xa9, 0x14, 0x4f, 0x8a, 0xe1,
    ];

    // Normal encode/decode testing
    #[test]
    fn test_encoding() {
        test_encode!(
            (U_8, Revealed),
            (U_16, Revealed),
            (U_32, Revealed),
            (U_64, Revealed),
            (I_8, Revealed),
            (I_16, Revealed),
            (I_32, Revealed),
            (I_64, Revealed),
            (F_32, Revealed),
            (F_64, Revealed),
            (BYTES, Revealed),
            (STRING, Revealed),
        );
    }

    // Garbage data encode/decode testing
    #[test]
    fn test_garbage() {
        let err = "EncodingTag";
        test_garbage_exhaustive!(150..255;
            (U_8, Revealed, err),
            (U_16, Revealed, err),
            (U_32, Revealed, err),
            (U_64, Revealed, err),
            (I_8, Revealed, err),
            (I_16, Revealed, err),
            (I_32, Revealed, err),
            (I_64, Revealed, err),
            (F_32, Revealed, err),
            (F_64, Revealed, err),
            (BYTES, Revealed, err),
            (STRING, Revealed, err),
        );
    }

    #[test]
    fn test_conf1() {
        macro_rules! test_confidential {
            ($(($revealed:ident, $conf:ident, $T:ty)),*) => (
                {
                    $(
                        test_confidential::<$T>(&$revealed[..], &$conf[..], &$conf[..]);
                    )*
                }
            );
        }

        test_confidential!(
            (U_8, U8_CONCEALED, Revealed),
            (U_16, U16_CONCEALED, Revealed),
            (U_32, U32_CONCEALED, Revealed),
            (U_64, U64_CONCEALED, Revealed),
            (I_8, I8_CONCEALED, Revealed),
            (I_16, I16_CONCEALED, Revealed),
            (I_32, I32_CONCEALED, Revealed),
            (I_64, I64_CONCEALED, Revealed),
            (F_32, F32_CONCEALED, Revealed),
            (F_64, F64_CONCEALED, Revealed),
            (F_64, F64_CONCEALED, Revealed),
            (BYTES, BYTES_CONCEALED, Revealed),
            (STRING, STRING_CONCEALED, Revealed),
        );
    }
}

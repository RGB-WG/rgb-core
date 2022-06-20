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

use core::any::Any;
use core::cmp::Ordering;
use core::fmt::Debug;
use std::hash::Hasher;
use std::io;

use amplify::num::apfloat::ieee;
use amplify::num::{i1024, i256, i512, u1024, u256, u512};
use amplify::AsAny;
use bitcoin::hashes::{sha256, sha256t};
use commit_verify::{commit_encode, CommitConceal, CommitEncode, TaggedHash};
use half::bf16;
use stens::{AsciiString, PrimitiveType, TypeRef};
use strict_encoding::strict_serialize;

use super::{ConfidentialState, RevealedState};

/// Struct using for storing Void (i.e. absent) state
#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, AsAny)]
#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct Void();

impl ConfidentialState for Void {}

impl RevealedState for Void {}

impl CommitConceal for Void {
    type ConcealedCommitment = Void;

    fn commit_conceal(&self) -> Self::ConcealedCommitment { self.clone() }
}
impl CommitEncode for Void {
    fn commit_encode<E: io::Write>(&self, _e: E) -> usize { 0 }
}

#[derive(Clone, Debug, AsAny, Display)]
#[derive(StrictEncode, StrictDecode)]
#[strict_encoding(repr = u8)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
#[display(Debug)]
pub enum Revealed {
    #[strict_encoding(value = 0x00)]
    U8(u8),
    #[strict_encoding(value = 0x01)]
    U16(u16),
    #[strict_encoding(value = 0x02)]
    U32(u32),
    #[strict_encoding(value = 0x03)]
    U64(u64),
    #[strict_encoding(value = 0x04)]
    U128(u128),
    #[strict_encoding(value = 0x05)]
    #[display("U256({0})")]
    U256(u256),
    #[strict_encoding(value = 0x06)]
    #[display("U512({0})")]
    U512(u512),
    #[strict_encoding(value = 0x07)]
    #[display("U1024({0})")]
    U1024(u1024),

    #[strict_encoding(value = 0x10)]
    I8(i8),
    #[strict_encoding(value = 0x11)]
    I16(i16),
    #[strict_encoding(value = 0x12)]
    I32(i32),
    #[strict_encoding(value = 0x13)]
    I64(i64),
    #[strict_encoding(value = 0x14)]
    I128(i128),
    #[strict_encoding(value = 0x15)]
    #[display("I256({0})")]
    I256(i256),
    #[strict_encoding(value = 0x16)]
    #[display("I512({0})")]
    I512(i512),
    #[strict_encoding(value = 0x17)]
    #[display("I1024({0})")]
    I1024(i1024),

    // TODO #100: Implement tapered float format
    #[strict_encoding(value = 0x30)]
    #[display("F16B({0})")]
    F16B(bf16),
    #[strict_encoding(value = 0x31)]
    #[cfg_attr(feature = "serde", serde(with = "serde_with::rust::display_fromstr"))]
    #[display("F16({0})")]
    F16(ieee::Half),
    #[strict_encoding(value = 0x32)]
    F32(f32),
    #[strict_encoding(value = 0x33)]
    F64(f64),
    #[strict_encoding(value = 0x34)]
    #[cfg_attr(feature = "serde", serde(with = "serde_with::rust::display_fromstr"))]
    #[display("F80({0})")]
    F80(ieee::X87DoubleExtended),
    #[strict_encoding(value = 0x35)]
    #[cfg_attr(feature = "serde", serde(with = "serde_with::rust::display_fromstr"))]
    #[display("F128({0})")]
    F128(ieee::Quad),
    #[strict_encoding(value = 0x36)]
    #[cfg_attr(feature = "serde", serde(with = "serde_with::rust::display_fromstr"))]
    #[display("F256({0})")]
    F256(ieee::Oct),

    #[strict_encoding(value = 0xE0)]
    #[display("<bytes>")]
    Bytes(Vec<u8>),
    #[strict_encoding(value = 0xEE)]
    #[display(inner)]
    AsciiString(AsciiString),
    #[strict_encoding(value = 0xEF)]
    #[display(inner)]
    UnicodeString(String),
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

impl std::hash::Hash for Revealed {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(&self.commit_conceal().commit_serialize())
    }
}

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

// "rgb:data:confidential"
static MIDSTATE_CONFIDENTIAL_DATA: [u8; 32] = [
    151, 235, 12, 105, 100, 154, 61, 159, 108, 179, 41, 229, 218, 159, 57, 12, 233, 248, 167, 213,
    228, 9, 202, 215, 27, 84, 249, 215, 93, 189, 75, 146,
];

/// Tag used for [`Confidential`] hash value of the data
pub struct ConfidentialTag;

impl sha256t::Tag for ConfidentialTag {
    #[inline]
    fn engine() -> sha256::HashEngine {
        let midstate = sha256::Midstate::from_inner(MIDSTATE_CONFIDENTIAL_DATA);
        sha256::HashEngine::from_midstate(midstate, 64)
    }
}

/// Blind version of transaction outpoint-based single-use-seal
#[derive(Wrapper, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, From)]
#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
#[wrapper(Debug, Display)]
pub struct Confidential(sha256t::Hash<ConfidentialTag>);

impl commit_encode::Strategy for Confidential {
    type Strategy = commit_encode::strategies::UsingStrict;
}

impl ConfidentialState for Confidential {}

impl AsAny for Confidential {
    fn as_any(&self) -> &dyn Any { self as &dyn Any }
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
    pub fn u128(&self) -> Option<u128> {
        match self {
            Revealed::U128(val) => Some(*val),
            _ => None,
        }
    }
    pub fn u256(&self) -> Option<u256> {
        match self {
            Revealed::U256(val) => Some(*val),
            _ => None,
        }
    }
    pub fn u512(&self) -> Option<u512> {
        match self {
            Revealed::U512(val) => Some(*val),
            _ => None,
        }
    }
    pub fn u1024(&self) -> Option<u1024> {
        match self {
            Revealed::U1024(val) => Some(*val),
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
    pub fn i128(&self) -> Option<i128> {
        match self {
            Revealed::I128(val) => Some(*val),
            _ => None,
        }
    }
    pub fn i256(&self) -> Option<i256> {
        match self {
            Revealed::I256(val) => Some(*val),
            _ => None,
        }
    }
    pub fn i512(&self) -> Option<i512> {
        match self {
            Revealed::I512(val) => Some(*val),
            _ => None,
        }
    }
    pub fn i1024(&self) -> Option<i1024> {
        match self {
            Revealed::I1024(val) => Some(*val),
            _ => None,
        }
    }

    pub fn f16b(&self) -> Option<bf16> {
        match self {
            Revealed::F16B(val) => Some(*val),
            _ => None,
        }
    }
    pub fn f16(&self) -> Option<ieee::Half> {
        match self {
            Revealed::F16(val) => Some(*val),
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
    pub fn f80(&self) -> Option<ieee::X87DoubleExtended> {
        match self {
            Revealed::F80(val) => Some(*val),
            _ => None,
        }
    }
    pub fn f128(&self) -> Option<ieee::Quad> {
        match self {
            Revealed::F128(val) => Some(*val),
            _ => None,
        }
    }
    pub fn f256(&self) -> Option<ieee::Oct> {
        match self {
            Revealed::F256(val) => Some(*val),
            _ => None,
        }
    }
    // TODO #100: Implement tapered float format

    pub fn bytes(&self) -> Option<Vec<u8>> {
        match self {
            Revealed::Bytes(val) => Some(val.clone()),
            _ => None,
        }
    }
    pub fn ascii_string(&self) -> Option<AsciiString> {
        match self {
            Revealed::AsciiString(val) => Some(val.clone()),
            _ => None,
        }
    }
    pub fn unicode_string(&self) -> Option<String> {
        match self {
            Revealed::UnicodeString(val) => Some(val.clone()),
            _ => None,
        }
    }

    pub fn schema_type(&self) -> TypeRef {
        match self {
            Revealed::U8(_) => TypeRef::u8(),
            Revealed::U16(_) => TypeRef::u16(),
            Revealed::U32(_) => TypeRef::u32(),
            Revealed::U64(_) => TypeRef::u64(),
            Revealed::U128(_) => TypeRef::u128(),
            Revealed::U256(_) => TypeRef::Primitive(PrimitiveType::U256.into()),
            Revealed::U512(_) => TypeRef::Primitive(PrimitiveType::U512.into()),
            Revealed::U1024(_) => TypeRef::Primitive(PrimitiveType::U1024.into()),
            Revealed::I8(_) => TypeRef::i8(),
            Revealed::I16(_) => TypeRef::i16(),
            Revealed::I32(_) => TypeRef::i32(),
            Revealed::I64(_) => TypeRef::i64(),
            Revealed::I128(_) => TypeRef::i128(),
            Revealed::I256(_) => TypeRef::Primitive(PrimitiveType::I256.into()),
            Revealed::I512(_) => TypeRef::Primitive(PrimitiveType::I512.into()),
            Revealed::I1024(_) => TypeRef::Primitive(PrimitiveType::I1024.into()),
            Revealed::F16B(_) => TypeRef::Primitive(PrimitiveType::F16b.into()),
            Revealed::F16(_) => TypeRef::Primitive(PrimitiveType::F16.into()),
            Revealed::F32(_) => TypeRef::f32(),
            Revealed::F64(_) => TypeRef::f64(),
            Revealed::F80(_) => TypeRef::Primitive(PrimitiveType::F80.into()),
            Revealed::F128(_) => TypeRef::Primitive(PrimitiveType::F128.into()),
            Revealed::F256(_) => TypeRef::Primitive(PrimitiveType::F256.into()),
            Revealed::Bytes(_) => TypeRef::bytes(),
            Revealed::AsciiString(_) => TypeRef::ascii_string(),
            Revealed::UnicodeString(_) => TypeRef::unicode_string(),
        }
    }
}

#[cfg(test)]
mod test {
    use amplify::Wrapper;
    use commit_verify::tagged_hash;
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

    static U8_CONCEALED: [u8; 32] = [
        161, 96, 17, 80, 21, 40, 216, 159, 16, 118, 181, 5, 129, 1, 104, 13, 140, 180, 187, 73,
        167, 191, 192, 20, 193, 188, 208, 129, 106, 33, 92, 39,
    ];
    static U16_CONCEALED: [u8; 32] = [
        80, 54, 157, 249, 250, 32, 49, 160, 128, 1, 178, 23, 207, 113, 37, 140, 67, 7, 13, 62, 216,
        70, 81, 20, 180, 35, 104, 112, 98, 181, 18, 102,
    ];
    static U32_CONCEALED: [u8; 32] = [
        121, 102, 29, 211, 144, 20, 177, 201, 217, 150, 2, 207, 78, 113, 204, 38, 38, 105, 164, 68,
        227, 224, 14, 236, 77, 60, 101, 225, 174, 12, 230, 161,
    ];
    static U64_CONCEALED: [u8; 32] = [
        80, 99, 180, 211, 149, 79, 160, 168, 50, 150, 54, 190, 65, 240, 179, 156, 212, 5, 211, 72,
        82, 27, 87, 184, 156, 76, 44, 148, 102, 137, 212, 28,
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

    #[test]
    fn test_confidential_midstate() {
        let midstate = tagged_hash::Midstate::with(b"rgb:data:confidential");
        assert_eq!(
            midstate.into_inner().into_inner(),
            MIDSTATE_CONFIDENTIAL_DATA
        );
    }

    // Normal encode/decode testing
    #[test]
    #[ignore]
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
            (STRING, Revealed)
        );
    }

    // Garbage data encode/decode testing
    #[test]
    #[ignore]
    fn test_garbage() {
        let err = "Revealed";
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
            (STRING, Revealed, err)
        );
    }

    #[test]
    #[ignore]
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
            (STRING, STRING_CONCEALED, Revealed)
        );
    }
}

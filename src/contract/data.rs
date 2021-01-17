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

use amplify::AsAny;
use core::any::Any;
use core::cmp::Ordering;
use core::fmt::Debug;

use bitcoin::hashes::{hash160, sha256, sha256d, sha512, Hash};
use bitcoin::util::psbt::PartiallySignedTransaction;
use bitcoin::OutPoint;
use bitcoin::{secp256k1, Transaction};

use lnpbp::client_side_validation::{
    commit_strategy, CommitEncodeWithStrategy, Conceal,
};
use lnpbp::strict_encoding::strict_serialize;

use super::{ConfidentialState, RevealedState};

/// Struct using for storing Void (i.e. absent) state
#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq, AsAny)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub struct Void;

impl ConfidentialState for Void {}

impl RevealedState for Void {}

impl Conceal for Void {
    type Confidential = Void;

    fn conceal(&self) -> Self::Confidential {
        self.clone()
    }
}
impl CommitEncodeWithStrategy for Void {
    type Strategy = commit_strategy::UsingConceal;
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
    // TODO: Add support later once bitcoin library will start supporting
    //       consensus-encoding of the native rust `u128` type
    // U128(u128),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    // TODO: Add support later once bitcoin library will start supporting
    //       consensus-encoding of the native rust `i128` type
    // I128(i128),
    F32(f32),
    F64(f64),
    Bytes(Vec<u8>),
    String(String),

    /// Single-path RIPEMD-160 is not secure and should not be used; see
    /// <https://eprint.iacr.org/2004/199.pdf>
    Sha256(sha256::Hash),
    Sha512(sha512::Hash),
    Bitcoin160(hash160::Hash),
    Bitcoin256(sha256d::Hash),

    Secp256k1Pubkey(secp256k1::PublicKey),
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::bech32::to_bech32_str",
            deserialize_with = "crate::bech32::from_bech32_str"
        )
    )]
    Curve25519Pubkey(ed25519_dalek::PublicKey),

    Secp256k1ECDSASignature(secp256k1::Signature),
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::bech32::to_bech32_str",
            deserialize_with = "crate::bech32::from_bech32_str"
        )
    )]
    Ed25519Signature(ed25519_dalek::Signature),
    // TODO: Add support for Schnorr's signatures once they will be
    //       implemented in rust-secp256k1
    TxOutPoint(OutPoint),
    Tx(Transaction),
    Psbt(PartiallySignedTransaction),
}

impl RevealedState for Revealed {}

impl Conceal for Revealed {
    type Confidential = Confidential;

    fn conceal(&self) -> Self::Confidential {
        Confidential::hash(
            &strict_serialize(self)
                .expect("Encoding of predefined data types must not fail"),
        )
    }
}
impl CommitEncodeWithStrategy for Revealed {
    type Strategy = commit_strategy::UsingConceal;
}

impl PartialEq for Revealed {
    fn eq(&self, other: &Self) -> bool {
        let some = strict_serialize(self)
            .expect("Encoding of predefined data types must not fail");
        let other = strict_serialize(other)
            .expect("Encoding of predefined data types must not fail");
        some.eq(&other)
    }
}

impl Eq for Revealed {}

impl PartialOrd for Revealed {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let some = strict_serialize(self)
            .expect("Encoding of predefined data types must not fail");
        let other = strict_serialize(other)
            .expect("Encoding of predefined data types must not fail");
        some.partial_cmp(&other)
    }
}

impl Ord for Revealed {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).unwrap_or_else(|| {
            let some = strict_serialize(self)
                .expect("Encoding of predefined data types must not fail");
            let other = strict_serialize(other)
                .expect("Encoding of predefined data types must not fail");
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
    fn as_any(&self) -> &dyn Any {
        self as &dyn Any
    }
}

impl CommitEncodeWithStrategy for Confidential {
    type Strategy = commit_strategy::UsingStrict;
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

pub mod strict_encoding {
    use super::*;

    use lnpbp::strict_encoding::{
        strategies, Error, Strategy, StrictDecode, StrictEncode,
    };
    use std::io;

    impl Strategy for Confidential {
        type Strategy = strategies::HashFixedBytes;
    }

    #[derive(
        Copy,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        FromPrimitive,
        ToPrimitive,
        Debug,
    )]
    #[repr(u8)]
    pub enum EncodingTag {
        U8 = 0b_0000_0000_u8,
        U16 = 0b_0000_0001_u8,
        U32 = 0b_0000_0010_u8,
        U64 = 0b_0000_0011_u8,
        // U128 = 0b_0000_0100_u8,
        I8 = 0b_0000_1000_u8,
        I16 = 0b_0000_1001_u8,
        I32 = 0b_0000_1010_u8,
        I64 = 0b_0000_1011_u8,
        // I128 = 0b_0000_1100_u8,
        F32 = 0b_0001_0010_u8,
        F64 = 0b_0001_0011_u8,

        Bytes = 0b_0010_0000_u8,
        String = 0b_0010_0001_u8,

        Sha256 = 0b_0100_0000_u8,
        Sha512 = 0b_0100_0001_u8,
        Bitcoin160 = 0b_0100_1000_u8,
        Bitcoin256 = 0b_0100_1001_u8,

        Secp256k1Pubkey = 0b_1000_0001_u8,
        Secp256k1Signature = 0b_1000_0010_u8,

        Curve25519Pubkey = 0b_1000_1001_u8,
        Ed25519Signature = 0b_1000_1010_u8,

        TxOutPoint = 0b_0101_0001_u8,
        Tx = 0b_0101_0010_u8,
        Psbt = 0b_0101_0011_u8,
    }
    impl_enum_strict_encoding!(EncodingTag);

    impl StrictEncode for Void {
        fn strict_encode<E: io::Write>(&self, _: E) -> Result<usize, Error> {
            Ok(0)
        }
    }

    impl StrictDecode for Void {
        fn strict_decode<D: io::Read>(_: D) -> Result<Self, Error> {
            Ok(Void)
        }
    }

    impl StrictEncode for Revealed {
        fn strict_encode<E: io::Write>(
            &self,
            mut e: E,
        ) -> Result<usize, Error> {
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
                // Value::U128(val) => strict_encode_list!(e; EncodingTag::U128,
                // val),
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
                // Value::I128(val) => strict_encode_list!(e; EncodingTag::I128,
                // val),
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
                Revealed::Sha256(val) => {
                    strict_encode_list!(e; EncodingTag::Sha256, val)
                }
                Revealed::Sha512(val) => {
                    strict_encode_list!(e; EncodingTag::Sha512, val)
                }
                Revealed::Bitcoin160(val) => {
                    strict_encode_list!(e; EncodingTag::Bitcoin160, val)
                }
                Revealed::Bitcoin256(val) => {
                    strict_encode_list!(e; EncodingTag::Bitcoin256, val)
                }
                Revealed::Secp256k1Pubkey(val) => {
                    strict_encode_list!(e; EncodingTag::Secp256k1Pubkey, val)
                }
                Revealed::Secp256k1ECDSASignature(val) => {
                    strict_encode_list!(e; EncodingTag::Secp256k1Signature, val)
                }
                Revealed::Curve25519Pubkey(val) => {
                    strict_encode_list!(e; EncodingTag::Curve25519Pubkey, val)
                }
                Revealed::Ed25519Signature(val) => {
                    strict_encode_list!(e; EncodingTag::Ed25519Signature, val)
                }
                Revealed::TxOutPoint(val) => {
                    strict_encode_list!(e; EncodingTag::TxOutPoint, val)
                }
                Revealed::Tx(val) => {
                    strict_encode_list!(e; EncodingTag::Tx, val)
                }
                Revealed::Psbt(val) => {
                    strict_encode_list!(e; EncodingTag::Psbt, val)
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
                // EncodingTag::U128 => Value::U128(u128::strict_decode(&mut
                // d)?),
                EncodingTag::I8 => Revealed::I8(i8::strict_decode(&mut d)?),
                EncodingTag::I16 => Revealed::I16(i16::strict_decode(&mut d)?),
                EncodingTag::I32 => Revealed::I32(i32::strict_decode(&mut d)?),
                EncodingTag::I64 => Revealed::I64(i64::strict_decode(&mut d)?),
                // EncodingTag::I128 => Value::I128(i128::strict_decode(&mut
                // d)?),
                EncodingTag::F32 => Revealed::F32(f32::strict_decode(&mut d)?),
                EncodingTag::F64 => Revealed::F64(f64::strict_decode(&mut d)?),
                EncodingTag::Bytes => {
                    Revealed::Bytes(Vec::strict_decode(&mut d)?)
                }
                EncodingTag::String => {
                    Revealed::String(String::strict_decode(&mut d)?)
                }
                EncodingTag::Bitcoin160 => {
                    Revealed::Bitcoin160(hash160::Hash::strict_decode(&mut d)?)
                }
                EncodingTag::Bitcoin256 => {
                    Revealed::Bitcoin256(sha256d::Hash::strict_decode(&mut d)?)
                }
                EncodingTag::Sha256 => {
                    Revealed::Sha256(sha256::Hash::strict_decode(&mut d)?)
                }
                EncodingTag::Sha512 => {
                    Revealed::Sha512(sha512::Hash::strict_decode(&mut d)?)
                }
                EncodingTag::Secp256k1Pubkey => Revealed::Secp256k1Pubkey(
                    secp256k1::PublicKey::strict_decode(&mut d)?,
                ),
                EncodingTag::Secp256k1Signature => {
                    Revealed::Secp256k1ECDSASignature(
                        secp256k1::Signature::strict_decode(&mut d)?,
                    )
                }
                EncodingTag::Curve25519Pubkey => Revealed::Curve25519Pubkey(
                    ed25519_dalek::PublicKey::strict_decode(&mut d)?,
                ),
                EncodingTag::Ed25519Signature => Revealed::Ed25519Signature(
                    ed25519_dalek::Signature::strict_decode(&mut d)?,
                ),
                EncodingTag::TxOutPoint => {
                    Revealed::TxOutPoint(OutPoint::strict_decode(&mut d)?)
                }
                EncodingTag::Tx => {
                    Revealed::Tx(Transaction::strict_decode(&mut d)?)
                }
                EncodingTag::Psbt => Revealed::Psbt(
                    PartiallySignedTransaction::strict_decode(&mut d)?,
                ),
            })
        }
    }

    #[cfg(test)]
    mod test {
        use super::EncodingTag;

        #[test]
        fn test_enum_encodingtag_exhaustive() {
            test_enum_u8_exhaustive!(EncodingTag;
                EncodingTag::U8 => 0b_0000_0000_u8,
                EncodingTag::U16 => 0b_0000_0001_u8,
                EncodingTag::U32 => 0b_0000_0010_u8,
                EncodingTag::U64 => 0b_0000_0011_u8,
                EncodingTag::I8 => 0b_0000_1000_u8,
                EncodingTag::I16 => 0b_0000_1001_u8,
                EncodingTag::I32 => 0b_0000_1010_u8,
                EncodingTag::I64 => 0b_0000_1011_u8,
                EncodingTag::F32 => 0b_0001_0010_u8,
                EncodingTag::F64 => 0b_0001_0011_u8,

                EncodingTag::Bytes => 0b_0010_0000_u8,
                EncodingTag::String => 0b_0010_0001_u8,

                EncodingTag::Sha256 => 0b_0100_0000_u8,
                EncodingTag::Sha512 => 0b_0100_0001_u8,
                EncodingTag::Bitcoin160 => 0b_0100_1000_u8,
                EncodingTag::Bitcoin256 => 0b_0100_1001_u8,

                EncodingTag::Secp256k1Pubkey => 0b_1000_0001_u8,
                EncodingTag::Secp256k1Signature => 0b_1000_0010_u8,

                EncodingTag::Curve25519Pubkey => 0b_1000_1001_u8,
                EncodingTag::Ed25519Signature => 0b_1000_1010_u8,

                EncodingTag::TxOutPoint => 0b_0101_0001_u8,
                EncodingTag::Tx => 0b_0101_0010_u8,
                EncodingTag::Psbt => 0b_0101_0011_u8
            );
        }
    }
}

#[cfg(test)]
mod test {
    use super::super::test::test_confidential;
    use super::*;

    use lnpbp::strict_encoding::StrictDecode;
    use lnpbp::test_helpers::*;

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
    static F_64: [u8; 9] =
        [0x13, 0x7b, 0x14, 0xae, 0x47, 0xe1, 0x2a, 0x50, 0x40];
    static BYTES: [u8; 36] = [
        0x20, 0x21, 0x0, 0x7c, 0x66, 0xc0, 0x28, 0x3e, 0xe9, 0xbe, 0x98, 0xe,
        0x29, 0xce, 0x32, 0x5a, 0xf, 0x46, 0x79, 0xef, 0x87, 0x28, 0x8e, 0xd7,
        0x3c, 0xe4, 0x7f, 0xc4, 0xf5, 0xc7, 0x9d, 0x19, 0xeb, 0xfa, 0x57, 0xda,
    ];
    static STRING: [u8; 20] = [
        0x21, 0x11, 0x0, 0x45, 0x54, 0x48, 0x20, 0x49, 0x53, 0x20, 0x41, 0x20,
        0x53, 0x45, 0x43, 0x55, 0x52, 0x49, 0x54, 0x59,
    ];
    static BITCOIN160: [u8; 21] = [
        0x48, 0xf, 0x33, 0xe5, 0xdf, 0x8, 0x7c, 0x5c, 0xef, 0x5f, 0xae, 0xbe,
        0x76, 0x76, 0xd9, 0xe7, 0xa6, 0xb8, 0x2b, 0x4a, 0x99,
    ];
    static BITCOIN256: [u8; 33] = [
        0x49, 0x39, 0x3a, 0x97, 0x1e, 0x46, 0x1d, 0x1c, 0x52, 0xd4, 0xb7, 0xb9,
        0xb6, 0x5c, 0x65, 0x1a, 0x21, 0x69, 0xf6, 0x82, 0x75, 0x9b, 0x5e, 0xc5,
        0xa2, 0x0, 0xde, 0x78, 0x7e, 0x40, 0x79, 0x55, 0x7b,
    ];
    static SHA256: [u8; 33] = [
        0x40, 0x99, 0x95, 0x91, 0x96, 0xd2, 0x51, 0x41, 0x94, 0x68, 0x59, 0xbb,
        0x21, 0x3e, 0xcc, 0x7f, 0x5f, 0xca, 0x55, 0xb8, 0x82, 0x46, 0x7e, 0xb1,
        0xd3, 0x9b, 0xf5, 0x88, 0xdf, 0xa8, 0x33, 0x2f, 0xa0,
    ];
    static SHA512: [u8; 65] = [
        0x41, 0x67, 0xf7, 0x21, 0x22, 0x5e, 0xfb, 0xd2, 0x5, 0xfc, 0xe, 0x96,
        0x70, 0x0, 0x43, 0xc, 0x4, 0xa0, 0xe, 0xef, 0x86, 0xa2, 0x9e, 0xdd,
        0x40, 0xfa, 0xf4, 0x4e, 0x1b, 0xe2, 0x27, 0x75, 0xea, 0xcf, 0x8e, 0x74,
        0xfe, 0x87, 0x2f, 0xc0, 0x3d, 0xd4, 0x51, 0x2f, 0x45, 0x15, 0xc6, 0xac,
        0xa9, 0x7b, 0xb8, 0xf2, 0xf1, 0xf3, 0x84, 0x90, 0xd9, 0x78, 0x6b, 0x4,
        0x3e, 0x36, 0xed, 0xff, 0x35,
    ];
    static PK_BYTES_02: [u8; 34] = [
        0x81, 0x2, 0x9b, 0x63, 0x47, 0x39, 0x85, 0x5, 0xf5, 0xec, 0x93, 0x82,
        0x6d, 0xc6, 0x1c, 0x19, 0xf4, 0x7c, 0x66, 0xc0, 0x28, 0x3e, 0xe9, 0xbe,
        0x98, 0xe, 0x29, 0xce, 0x32, 0x5a, 0xf, 0x46, 0x79, 0xef,
    ];
    static SIG_BYTES: [u8; 65] = [
        0x82, 0xdf, 0x2b, 0x7, 0x1, 0x5f, 0x2e, 0x1, 0x67, 0x74, 0x18, 0x7e,
        0xad, 0x4a, 0x4f, 0x71, 0x9a, 0x14, 0xe3, 0xe1, 0xad, 0xa1, 0x78, 0xd6,
        0x6c, 0xce, 0xcf, 0xa4, 0x5b, 0x63, 0x30, 0x70, 0xc2, 0x43, 0xa2, 0xd7,
        0x6e, 0xe0, 0x5d, 0x63, 0x49, 0xfe, 0x98, 0x69, 0x6c, 0x1c, 0x4d, 0x9a,
        0x67, 0x11, 0x24, 0xde, 0x40, 0xc5, 0x31, 0x71, 0xa4, 0xb2, 0x82, 0xb7,
        0x69, 0xb7, 0xc6, 0x96, 0xcd,
    ];
    static TXOUTPOINT_BYTES: [u8; 37] = [
        0x51, 0x53, 0xc6, 0x31, 0x13, 0xed, 0x18, 0x68, 0xfc, 0xa, 0xdf, 0x8e,
        0xcd, 0xfd, 0x1f, 0x4d, 0xd6, 0xe5, 0xe3, 0x85, 0x83, 0xa4, 0x9d, 0xb,
        0x14, 0xe7, 0xf8, 0x87, 0xa4, 0xd1, 0x61, 0x78, 0x21, 0x4, 0x0, 0x0,
        0x0,
    ];
    static TX_BYTES: [u8; 194] = [
        0x52, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x59, 0x58, 0x95, 0xea,
        0x20, 0x17, 0x9d, 0xe8, 0x70, 0x52, 0xb4, 0x04, 0x6d, 0xfe, 0x6f, 0xd5,
        0x15, 0x86, 0x05, 0x05, 0xd6, 0x51, 0x1a, 0x90, 0x04, 0xcf, 0x12, 0xa1,
        0xf9, 0x3c, 0xac, 0x7c, 0x01, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
        0xff, 0x01, 0xde, 0xb8, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x17, 0xa9,
        0x14, 0x0f, 0x34, 0x44, 0xe2, 0x71, 0x62, 0x0c, 0x73, 0x68, 0x08, 0xaa,
        0x7b, 0x33, 0xe3, 0x70, 0xbd, 0x87, 0xcb, 0x5a, 0x07, 0x87, 0x02, 0x48,
        0x30, 0x45, 0x02, 0x21, 0x00, 0xfb, 0x60, 0xda, 0xd8, 0xdf, 0x4a, 0xf2,
        0x84, 0x1a, 0xdc, 0x03, 0x46, 0x63, 0x8c, 0x16, 0xd0, 0xb8, 0x03, 0x5f,
        0x5e, 0x3f, 0x37, 0x53, 0xb8, 0x8d, 0xb1, 0x22, 0xe7, 0x0c, 0x79, 0xf9,
        0x37, 0x02, 0x20, 0x75, 0x6e, 0x66, 0x33, 0xb1, 0x7f, 0xd2, 0x71, 0x0e,
        0x62, 0x63, 0x47, 0xd2, 0x8d, 0x60, 0xb0, 0xa2, 0xd6, 0xcb, 0xb4, 0x1d,
        0xe5, 0x17, 0x40, 0x64, 0x4b, 0x9f, 0xb3, 0xba, 0x77, 0x51, 0x04, 0x01,
        0x21, 0x02, 0x8f, 0xa9, 0x37, 0xca, 0x8c, 0xba, 0x21, 0x97, 0xa3, 0x7c,
        0x00, 0x71, 0x76, 0xed, 0x89, 0x41, 0x05, 0x5d, 0x3b, 0xcb, 0x86, 0x27,
        0xd0, 0x85, 0xe9, 0x45, 0x53, 0xe6, 0x2f, 0x05, 0x7d, 0xcc, 0x00, 0x00,
        0x00, 0x00,
    ];
    static PSBT_BYTES: [u8; 556] = [
        0x53, 0x70, 0x73, 0x62, 0x74, 0xff, 0x01, 0x00, 0x75, 0x02, 0x00, 0x00,
        0x00, 0x01, 0x26, 0x81, 0x71, 0x37, 0x1e, 0xdf, 0xf2, 0x85, 0xe9, 0x37,
        0xad, 0xee, 0xa4, 0xb3, 0x7b, 0x78, 0x00, 0x0c, 0x05, 0x66, 0xcb, 0xb3,
        0xad, 0x64, 0x64, 0x17, 0x13, 0xca, 0x42, 0x17, 0x1b, 0xf6, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0x02, 0xd3, 0xdf, 0xf5, 0x05,
        0x00, 0x00, 0x00, 0x00, 0x19, 0x76, 0xa9, 0x14, 0xd0, 0xc5, 0x99, 0x03,
        0xc5, 0xba, 0xc2, 0x86, 0x87, 0x60, 0xe9, 0x0f, 0xd5, 0x21, 0xa4, 0x66,
        0x5a, 0xa7, 0x65, 0x20, 0x88, 0xac, 0x00, 0xe1, 0xf5, 0x05, 0x00, 0x00,
        0x00, 0x00, 0x17, 0xa9, 0x14, 0x35, 0x45, 0xe6, 0xe3, 0x3b, 0x83, 0x2c,
        0x47, 0x05, 0x0f, 0x24, 0xd3, 0xee, 0xb9, 0x3c, 0x9c, 0x03, 0x94, 0x8b,
        0xc7, 0x87, 0xb3, 0x2e, 0x13, 0x00, 0x00, 0x01, 0x00, 0xfd, 0xa5, 0x01,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x89, 0xa3, 0xc7, 0x1e, 0xab,
        0x4d, 0x20, 0xe0, 0x37, 0x1b, 0xbb, 0xa4, 0xcc, 0x69, 0x8f, 0xa2, 0x95,
        0xc9, 0x46, 0x3a, 0xfa, 0x2e, 0x39, 0x7f, 0x85, 0x33, 0xcc, 0xb6, 0x2f,
        0x95, 0x67, 0xe5, 0x01, 0x00, 0x00, 0x00, 0x17, 0x16, 0x00, 0x14, 0xbe,
        0x18, 0xd1, 0x52, 0xa9, 0xb0, 0x12, 0x03, 0x9d, 0xaf, 0x3d, 0xa7, 0xde,
        0x4f, 0x53, 0x34, 0x9e, 0xec, 0xb9, 0x85, 0xff, 0xff, 0xff, 0xff, 0x86,
        0xf8, 0xaa, 0x43, 0xa7, 0x1d, 0xff, 0x14, 0x48, 0x89, 0x3a, 0x53, 0x0a,
        0x72, 0x37, 0xef, 0x6b, 0x46, 0x08, 0xbb, 0xb2, 0xdd, 0x2d, 0x01, 0x71,
        0xe6, 0x3a, 0xec, 0x6a, 0x48, 0x90, 0xb4, 0x01, 0x00, 0x00, 0x00, 0x17,
        0x16, 0x00, 0x14, 0xfe, 0x3e, 0x9e, 0xf1, 0xa7, 0x45, 0xe9, 0x74, 0xd9,
        0x02, 0xc4, 0x35, 0x59, 0x43, 0xab, 0xcb, 0x34, 0xbd, 0x53, 0x53, 0xff,
        0xff, 0xff, 0xff, 0x02, 0x00, 0xc2, 0xeb, 0x0b, 0x00, 0x00, 0x00, 0x00,
        0x19, 0x76, 0xa9, 0x14, 0x85, 0xcf, 0xf1, 0x09, 0x7f, 0xd9, 0xe0, 0x08,
        0xbb, 0x34, 0xaf, 0x70, 0x9c, 0x62, 0x19, 0x7b, 0x38, 0x97, 0x8a, 0x48,
        0x88, 0xac, 0x72, 0xfe, 0xf8, 0x4e, 0x2c, 0x00, 0x00, 0x00, 0x17, 0xa9,
        0x14, 0x33, 0x97, 0x25, 0xba, 0x21, 0xef, 0xd6, 0x2a, 0xc7, 0x53, 0xa9,
        0xbc, 0xd0, 0x67, 0xd6, 0xc7, 0xa6, 0xa3, 0x9d, 0x05, 0x87, 0x02, 0x47,
        0x30, 0x44, 0x02, 0x20, 0x27, 0x12, 0xbe, 0x22, 0xe0, 0x27, 0x0f, 0x39,
        0x4f, 0x56, 0x83, 0x11, 0xdc, 0x7c, 0xa9, 0xa6, 0x89, 0x70, 0xb8, 0x02,
        0x5f, 0xdd, 0x3b, 0x24, 0x02, 0x29, 0xf0, 0x7f, 0x8a, 0x5f, 0x3a, 0x24,
        0x02, 0x20, 0x01, 0x8b, 0x38, 0xd7, 0xdc, 0xd3, 0x14, 0xe7, 0x34, 0xc9,
        0x27, 0x6b, 0xd6, 0xfb, 0x40, 0xf6, 0x73, 0x32, 0x5b, 0xc4, 0xba, 0xa1,
        0x44, 0xc8, 0x00, 0xd2, 0xf2, 0xf0, 0x2d, 0xb2, 0x76, 0x5c, 0x01, 0x21,
        0x03, 0xd2, 0xe1, 0x56, 0x74, 0x94, 0x1b, 0xad, 0x4a, 0x99, 0x63, 0x72,
        0xcb, 0x87, 0xe1, 0x85, 0x6d, 0x36, 0x52, 0x60, 0x6d, 0x98, 0x56, 0x2f,
        0xe3, 0x9c, 0x5e, 0x9e, 0x7e, 0x41, 0x3f, 0x21, 0x05, 0x02, 0x48, 0x30,
        0x45, 0x02, 0x21, 0x00, 0xd1, 0x2b, 0x85, 0x2d, 0x85, 0xdc, 0xd9, 0x61,
        0xd2, 0xf5, 0xf4, 0xab, 0x66, 0x06, 0x54, 0xdf, 0x6e, 0xed, 0xcc, 0x79,
        0x4c, 0x0c, 0x33, 0xce, 0x5c, 0xc3, 0x09, 0xff, 0xb5, 0xfc, 0xe5, 0x8d,
        0x02, 0x20, 0x67, 0x33, 0x8a, 0x8e, 0x0e, 0x17, 0x25, 0xc1, 0x97, 0xfb,
        0x1a, 0x88, 0xaf, 0x59, 0xf5, 0x1e, 0x44, 0xe4, 0x25, 0x5b, 0x20, 0x16,
        0x7c, 0x86, 0x84, 0x03, 0x1c, 0x05, 0xd1, 0xf2, 0x59, 0x2a, 0x01, 0x21,
        0x02, 0x23, 0xb7, 0x2b, 0xee, 0xf0, 0x96, 0x5d, 0x10, 0xbe, 0x07, 0x78,
        0xef, 0xec, 0xd6, 0x1f, 0xca, 0xc6, 0xf7, 0x9a, 0x4e, 0xa1, 0x69, 0x39,
        0x33, 0x80, 0x73, 0x44, 0x64, 0xf8, 0x4f, 0x2a, 0xb3, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];

    static U8_CONCEALED: [u8; 20] = [
        0x99, 0x3c, 0xfd, 0x1, 0x69, 0xe, 0xa0, 0xa8, 0xb2, 0x83, 0x1e, 0xf0,
        0x25, 0x36, 0xce, 0xed, 0x3e, 0x9b, 0xbf, 0x80,
    ];
    static U16_CONCEALED: [u8; 20] = [
        0x73, 0x36, 0xe0, 0x2b, 0x7, 0x8f, 0x8c, 0xb1, 0xb9, 0x5b, 0x27, 0x3c,
        0x92, 0xc1, 0x80, 0x95, 0xa, 0xa3, 0x26, 0xf7,
    ];
    static U32_CONCEALED: [u8; 20] = [
        0xf7, 0xcf, 0xbd, 0x3b, 0xac, 0xa1, 0x4e, 0xf, 0xc7, 0xea, 0xd0, 0xc7,
        0xd5, 0xb0, 0x8c, 0xba, 0xbd, 0x41, 0xc4, 0x3f,
    ];
    static U64_CONCEALED: [u8; 20] = [
        0x2, 0x5f, 0x33, 0x8f, 0x5a, 0x45, 0x89, 0xd4, 0xe, 0x56, 0x47, 0xe8,
        0xfc, 0xb3, 0x6b, 0x7f, 0xc4, 0x29, 0x92, 0x71,
    ];
    static I8_CONCEALED: [u8; 20] = [
        0xf5, 0x39, 0x1f, 0xf2, 0x83, 0x2b, 0xc6, 0xb1, 0x78, 0x59, 0x54, 0x14,
        0x28, 0xbf, 0xc1, 0x49, 0xf6, 0xcf, 0xd7, 0x78,
    ];
    static I16_CONCEALED: [u8; 20] = [
        0x61, 0x0, 0xc2, 0x37, 0x7, 0x97, 0x33, 0xf, 0xcf, 0xbb, 0x40, 0xcb,
        0xad, 0xf7, 0x81, 0x7e, 0x10, 0xd, 0x55, 0xa5,
    ];
    static I32_CONCEALED: [u8; 20] = [
        0xaa, 0xbe, 0x9b, 0x73, 0xf8, 0xfa, 0x84, 0x9d, 0x28, 0x79, 0x8b, 0x5c,
        0x13, 0x91, 0xe9, 0xbf, 0xc8, 0xa4, 0x2a, 0xc3,
    ];
    static I64_CONCEALED: [u8; 20] = [
        0xd, 0x56, 0xef, 0xcb, 0x53, 0xba, 0xd5, 0x52, 0xb, 0xc6, 0xea, 0x4f,
        0xe1, 0xa8, 0x56, 0x42, 0x3d, 0x66, 0x34, 0xc5,
    ];
    static F32_CONCEALED: [u8; 20] = [
        0xa2, 0xb0, 0x80, 0x82, 0xa9, 0x52, 0xa5, 0x41, 0xb8, 0xbd, 0x2, 0xd4,
        0x29, 0xf0, 0x90, 0xca, 0x8b, 0xa4, 0x5d, 0xfc,
    ];
    static F64_CONCEALED: [u8; 20] = [
        0x5f, 0xe8, 0xdd, 0xd4, 0xca, 0x55, 0x41, 0x14, 0x50, 0x24, 0xcf, 0x85,
        0x8c, 0xb4, 0x11, 0x5d, 0x9f, 0x8a, 0xaf, 0x87,
    ];
    static BYTES_CONCEALED: [u8; 20] = [
        0xf, 0x33, 0xe5, 0xdf, 0x8, 0x7c, 0x5c, 0xef, 0x5f, 0xae, 0xbe, 0x76,
        0x76, 0xd9, 0xe7, 0xa6, 0xb8, 0x2b, 0x4a, 0x99,
    ];
    static STRING_CONCEALED: [u8; 20] = [
        0xf8, 0x3b, 0x1b, 0xcd, 0xd8, 0x82, 0x55, 0xe1, 0xf9, 0x37, 0x52, 0xeb,
        0x20, 0x90, 0xfe, 0xa9, 0x14, 0x4f, 0x8a, 0xe1,
    ];
    static BITCOIN160_CONCEALED: [u8; 20] = [
        0x27, 0x57, 0x9d, 0x2f, 0x5f, 0x71, 0x99, 0x6b, 0x18, 0x92, 0xc6, 0xc1,
        0x7, 0xaa, 0x93, 0xf2, 0x3d, 0x3d, 0xdd, 0xac,
    ];
    static BITCOIN256_CONCEALED: [u8; 20] = [
        0xe2, 0xa3, 0x94, 0x7e, 0x77, 0xfd, 0x76, 0x1f, 0xf6, 0xb6, 0x64, 0xa,
        0xab, 0xc6, 0x59, 0xdd, 0x24, 0x4d, 0x15, 0x98,
    ];
    static SHA256_CONCEALED: [u8; 20] = [
        0x57, 0x7f, 0xdd, 0xbc, 0x8c, 0xaa, 0x57, 0x8f, 0x57, 0xde, 0x9, 0x74,
        0xe1, 0x31, 0x61, 0xeb, 0xd0, 0x1f, 0x4e, 0x80,
    ];
    static SHA512_CONCEALED: [u8; 20] = [
        0xf7, 0x97, 0x94, 0xad, 0x58, 0xc7, 0x6, 0x4a, 0xfa, 0x3a, 0x6b, 0xb4,
        0x3f, 0x29, 0xf7, 0x67, 0x3a, 0xca, 0x12, 0x17,
    ];
    static PK_BYTES_02_CONCEALED: [u8; 20] = [
        0x76, 0xf0, 0x2c, 0x49, 0x2f, 0x3f, 0xf2, 0xee, 0x2b, 0x0, 0x4a, 0x92,
        0xf8, 0xd9, 0x8f, 0x26, 0x11, 0xd8, 0x96, 0xf3,
    ];
    static SIG_BYTES_CONCEALED: [u8; 20] = [
        0xe2, 0x17, 0xd8, 0xea, 0xc5, 0x15, 0x42, 0xf2, 0xcd, 0x5e, 0xe7, 0x70,
        0xda, 0x99, 0x8, 0x92, 0x84, 0x7a, 0x29, 0xf6,
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
            (BITCOIN160, Revealed),
            (BITCOIN256, Revealed),
            (SHA256, Revealed),
            (SHA512, Revealed),
            (PK_BYTES_02, Revealed),
            (SIG_BYTES, Revealed),
            (TXOUTPOINT_BYTES, Revealed),
            (TX_BYTES, Revealed),
            (PSBT_BYTES, Revealed)
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
            (BITCOIN160, Revealed, err),
            (BITCOIN256, Revealed, err),
            (SHA256, Revealed, err),
            (SHA512, Revealed, err),
            (PK_BYTES_02, Revealed, err),
            (SIG_BYTES, Revealed, err),
            (TXOUTPOINT_BYTES, Revealed, err),
            (TX_BYTES, Revealed, err),
            (PSBT_BYTES, Revealed, err)
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
            (BITCOIN160, BITCOIN160_CONCEALED, Revealed),
            (BITCOIN256, BITCOIN256_CONCEALED, Revealed),
            (SHA256, SHA256_CONCEALED, Revealed),
            (SHA512, SHA512_CONCEALED, Revealed),
            (PK_BYTES_02, PK_BYTES_02_CONCEALED, Revealed),
            (SIG_BYTES, SIG_BYTES_CONCEALED, Revealed)
        );
    }
}

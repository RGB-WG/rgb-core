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

use bitcoin::hashes::{hash160, sha256, sha256d, sha512, Hash};
use bitcoin::secp256k1;

use super::{ConfidentialState, RevealedState};
use crate::client_side_validation::{commit_strategy, CommitEncodeWithStrategy, Conceal};
use crate::strict_encoding::strict_encode;

/// Struct using for storing Void (i.e. absent) state
#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq, AsAny)]
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
#[display_from(Debug)]
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
    Ed25519Pubkey(ed25519_dalek::PublicKey),

    Secp256k1ECDSASignature(secp256k1::Signature),
    Ed25519Signature(ed25519_dalek::Signature),
    // TODO: Add support for Schnorr's signatures once they will be implemented
    //       in rust-secp256k1
}

impl RevealedState for Revealed {}

impl Conceal for Revealed {
    type Confidential = Confidential;

    fn conceal(&self) -> Self::Confidential {
        Confidential::hash(
            &strict_encode(self).expect("Encoding of predefined data types must not fail"),
        )
    }
}
impl CommitEncodeWithStrategy for Revealed {
    type Strategy = commit_strategy::UsingConceal;
}

impl PartialEq for Revealed {
    fn eq(&self, other: &Self) -> bool {
        let some = strict_encode(self).expect("Encoding of predefined data types must not fail");
        let other = strict_encode(other).expect("Encoding of predefined data types must not fail");
        some.eq(&other)
    }
}

impl Eq for Revealed {}

impl PartialOrd for Revealed {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let some = strict_encode(self).expect("Encoding of predefined data types must not fail");
        let other = strict_encode(other).expect("Encoding of predefined data types must not fail");
        some.partial_cmp(&other)
    }
}

impl Ord for Revealed {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).unwrap_or_else(|| {
            let some =
                strict_encode(self).expect("Encoding of predefined data types must not fail");
            let other =
                strict_encode(other).expect("Encoding of predefined data types must not fail");
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

// TODO: Automate this with #derive macros
pub(super) mod strict_encoding {
    use super::*;
    use crate::strict_encoding::{strategies, Error, Strategy, StrictDecode, StrictEncode};
    use num_derive::{FromPrimitive, ToPrimitive};
    use num_traits::{FromPrimitive, ToPrimitive};
    use std::io;

    impl Strategy for Confidential {
        type Strategy = strategies::HashFixedBytes;
    }

    #[derive(FromPrimitive, ToPrimitive)]
    #[repr(u8)]
    pub(in super::super) enum EncodingTag {
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

        Ed25519Pubkey = 0b_1000_1001_u8,
        Ed25519Signature = 0b_1000_1010_u8,
    }
    impl_enum_strict_encoding!(EncodingTag);

    impl StrictEncode for Void {
        type Error = Error;
        fn strict_encode<E: io::Write>(&self, _: E) -> Result<usize, Self::Error> {
            Ok(0)
        }
    }

    impl StrictDecode for Void {
        type Error = Error;
        fn strict_decode<D: io::Read>(_: D) -> Result<Self, Self::Error> {
            Ok(Void)
        }
    }

    impl StrictEncode for Revealed {
        type Error = Error;

        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
            Ok(match self {
                Revealed::U8(val) => strict_encode_list!(e; EncodingTag::U8, val),
                Revealed::U16(val) => strict_encode_list!(e; EncodingTag::U16, val),
                Revealed::U32(val) => strict_encode_list!(e; EncodingTag::U32, val),
                Revealed::U64(val) => strict_encode_list!(e; EncodingTag::U64, val),
                // Value::U128(val) => strict_encode_list!(e; EncodingTag::U128, val),
                Revealed::I8(val) => strict_encode_list!(e; EncodingTag::I8, val),
                Revealed::I16(val) => strict_encode_list!(e; EncodingTag::I16, val),
                Revealed::I32(val) => strict_encode_list!(e; EncodingTag::I32, val),
                Revealed::I64(val) => strict_encode_list!(e; EncodingTag::I64, val),
                // Value::I128(val) => strict_encode_list!(e; EncodingTag::I128, val),
                Revealed::F32(val) => strict_encode_list!(e; EncodingTag::F32, val),
                Revealed::F64(val) => strict_encode_list!(e; EncodingTag::F64, val),
                Revealed::Bytes(val) => strict_encode_list!(e; EncodingTag::Bytes, val),
                Revealed::String(val) => strict_encode_list!(e; EncodingTag::String, val),
                Revealed::Sha256(val) => strict_encode_list!(e; EncodingTag::Sha256, val),
                Revealed::Sha512(val) => strict_encode_list!(e; EncodingTag::Sha512, val),
                Revealed::Bitcoin160(val) => strict_encode_list!(e; EncodingTag::Bitcoin160, val),
                Revealed::Bitcoin256(val) => strict_encode_list!(e; EncodingTag::Bitcoin256, val),
                Revealed::Secp256k1Pubkey(val) => {
                    strict_encode_list!(e; EncodingTag::Secp256k1Pubkey, val)
                }
                Revealed::Secp256k1ECDSASignature(val) => {
                    strict_encode_list!(e; EncodingTag::Secp256k1Signature, val)
                }
                Revealed::Ed25519Pubkey(_) => unimplemented!(),
                Revealed::Ed25519Signature(_) => unimplemented!(),
            })
        }
    }

    impl StrictDecode for Revealed {
        type Error = Error;

        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
            let format = EncodingTag::strict_decode(&mut d)?;
            Ok(match format {
                EncodingTag::U8 => Revealed::U8(u8::strict_decode(&mut d)?),
                EncodingTag::U16 => Revealed::U16(u16::strict_decode(&mut d)?),
                EncodingTag::U32 => Revealed::U32(u32::strict_decode(&mut d)?),
                EncodingTag::U64 => Revealed::U64(u64::strict_decode(&mut d)?),
                // EncodingTag::U128 => Value::U128(u128::strict_decode(&mut d)?),
                EncodingTag::I8 => Revealed::I8(i8::strict_decode(&mut d)?),
                EncodingTag::I16 => Revealed::I16(i16::strict_decode(&mut d)?),
                EncodingTag::I32 => Revealed::I32(i32::strict_decode(&mut d)?),
                EncodingTag::I64 => Revealed::I64(i64::strict_decode(&mut d)?),
                // EncodingTag::I128 => Value::I128(i128::strict_decode(&mut d)?),
                EncodingTag::F32 => Revealed::F32(f32::strict_decode(&mut d)?),
                EncodingTag::F64 => Revealed::F64(f64::strict_decode(&mut d)?),
                EncodingTag::Bytes => Revealed::Bytes(Vec::strict_decode(&mut d)?),
                EncodingTag::String => Revealed::String(String::strict_decode(&mut d)?),
                EncodingTag::Bitcoin160 => {
                    Revealed::Bitcoin160(hash160::Hash::strict_decode(&mut d)?)
                }
                EncodingTag::Bitcoin256 => {
                    Revealed::Bitcoin256(sha256d::Hash::strict_decode(&mut d)?)
                }
                EncodingTag::Sha256 => Revealed::Sha256(sha256::Hash::strict_decode(&mut d)?),
                EncodingTag::Sha512 => Revealed::Sha512(sha512::Hash::strict_decode(&mut d)?),
                EncodingTag::Secp256k1Pubkey => {
                    Revealed::Secp256k1Pubkey(secp256k1::PublicKey::strict_decode(&mut d)?)
                }
                EncodingTag::Secp256k1Signature => {
                    Revealed::Secp256k1ECDSASignature(secp256k1::Signature::strict_decode(&mut d)?)
                }
                EncodingTag::Ed25519Pubkey => unimplemented!(),
                EncodingTag::Ed25519Signature => unimplemented!(),
            })
        }
    }
}

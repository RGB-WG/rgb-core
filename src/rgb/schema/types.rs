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

use num_integer::Integer;
use num_traits::{ToPrimitive, FromPrimitive};
use num_derive::{ToPrimitive, FromPrimitive};

use crate::csv::serialize::*;

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
pub enum Occurences<MAX: Integer> where MAX: std::fmt::Debug {
    Once,
    NoneOrOnce,
    OnceOrUpTo(Option<MAX>),
    NoneOrUpTo(Option<MAX>),
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

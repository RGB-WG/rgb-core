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


use num_integer::Integer;
use num_traits::{ToPrimitive, FromPrimitive};
use num_derive::{ToPrimitive, FromPrimitive};


#[non_exhaustive]
#[derive(ToPrimitive, FromPrimitive)]
pub enum StateFormat {
    NoState = 0,
    Amount,
    Data
}


#[non_exhaustive]
#[derive(ToPrimitive, FromPrimitive)]
pub enum Bits {
    Bit8 = 0,
    Bit16,
    Bit32,
    Bit64,
    Bit128,
    Bit256,
}


#[non_exhaustive]
#[derive(ToPrimitive, FromPrimitive)]
pub enum DigestAlgorithm {
    Sha256 = 0,
    Bitcoin256,
    Ripemd160,
    Bitcoin160,
    Tagged256,
}


#[non_exhaustive]
#[derive(ToPrimitive, FromPrimitive)]
pub enum SignatureAlgorithm {
    EcdsaDer = 0,
    SchnorrBip,
}


#[non_exhaustive]
#[derive(ToPrimitive, FromPrimitive)]
pub enum ECPointSerialization {
    Uncompressed = 0,
    Compressed,
    SchnorrBip
}


#[non_exhaustive]
pub enum Occurences<MAX: Integer> {
    Once,
    NoneOrOnce,
    OnceOrUpTo(Option<MAX>),
    NoneOrUpTo(Option<MAX>),
}

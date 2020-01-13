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


pub enum StateFormat {
    NoState,
    Amount,
    Data
}

pub enum Bits {
    Bit8,
    Bit16,
    Bit32,
    Bit64,
    Bit128,
    Bit256,
}

pub enum DigestAlgorithm {
    Sha256,
    Bitcoin256,
    Ripmd160,
    Bitcoin160,
    Tagged256,
}

pub enum SignatureAlgorithm {
    EcdsaDer,
    SchnorrBip,
}

pub enum ECPointSerialization {
    Uncompressed,
    Compressed,
    SchnorrBip
}

pub enum Occurences<MAX: Integer> {
    Once,
    NoneOrOnce,
    OnceOrUpTo(Option<MAX>),
    NoneOrUpTo(Option<MAX>),
}

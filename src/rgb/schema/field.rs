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


use super::types::*;


pub enum FieldFormat {
    Unsigned { bits: Bits, min: Option<u64>, max: Option<u64> },
    Integer { bits: Bits, min: Option<i64>, max: Option<i64> },
    Float { bits: Bits, min: Option<f64>, max: Option<f64> },
    Enum { values: Vec<u8> },
    String(u16),
    Bytes(u16),
    Digest(u16, DigestAlgorithm),
    ECPoint(ECPointSerialization),
    Signature(SignatureAlgorithm),
}

pub struct Field(pub FieldFormat, pub Occurences<u8>);

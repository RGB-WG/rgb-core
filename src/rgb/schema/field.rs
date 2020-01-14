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


use std::io;

use super::types::*;
use crate::csv::serialize::*;


#[derive(Clone, Debug, Display)]
#[display_from(Debug)]
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

impl Commitment for FieldFormat {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(match self {
            Self::Unsigned { bits, min, max } => commitment_serialize_list!(e; 0x00u8, bits, min, max),
            Self::Integer { bits, min, max } => commitment_serialize_list!(e; 0x01u8, bits, min, max),
            Self::Float { bits, min, max } => unimplemented!(), // TODO: commitment_serialize_list!(e; 0x02u8, bits, min, max),
            Self::Enum { values } => commitment_serialize_list!(e; 0x10u8, values),
            Self::String(size) => commitment_serialize_list!(e; 0x20u8, size),
            Self::Bytes(size) => commitment_serialize_list!(e; 0x21u8, size),
            Self::Digest(bits, algo) => commitment_serialize_list!(e; 0x80u8, bits, algo),
            Self::ECPoint(algo) => commitment_serialize_list!(e; 0x81u8, algo),
            Self::Signature(algo) => commitment_serialize_list!(e; 0x82u8, algo),
            _ => panic!("New field formats can't appear w/o this library to be aware of")
        })
    }

    fn commitment_deserialize<D: io::Read>(d: D) -> Result<Self, Error> {
        unimplemented!()
    }
}


#[derive(Clone, Debug, Display)]
#[display_from(Debug)]
pub struct Field(pub FieldFormat, pub Occurences<u8>);

impl Commitment for Field {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        self.0.commitment_serialize(&mut e)?;
        self.1.commitment_serialize(&mut e)
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, Error> {
        Ok(Self(
            FieldFormat::commitment_deserialize(&mut d)?,
            Occurences::<u8>::commitment_deserialize(&mut d)?
        ))
    }
}

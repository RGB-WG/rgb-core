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

use std::{io, str};

use num_traits::{ToPrimitive, FromPrimitive};
use num_derive::{ToPrimitive, FromPrimitive};

use crate::csv::{Commitment, Error};

#[non_exhaustive]
#[derive(ToPrimitive, FromPrimitive)]
pub enum Extensions {
    ScriptsDenied = 0,
    ScriptsExtend,
    ScriptsReplace,
}

impl_commitment_enum!(Extensions);


#[non_exhaustive]
pub enum Procedure {
    Standard(&'static str),
    Simplicity(Vec<u8>)
}

impl Commitment for Procedure {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(match self {
            Self::Standard(name) => commitment_serialize_list!(e; 0u8, name.as_bytes().to_vec()),
            Self::Simplicity(code) => commitment_serialize_list!(e; 1u8, code),
            _ => panic!("New scripting engines can't appear w/o this library to be aware of")
        })
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let value = u8::commitment_deserialize(&mut d)?;
        let bytes = <Vec<u8>>::commitment_deserialize(&mut d)?;
        Ok(match value {
            0u8 => Self::Standard(match str::from_utf8(&bytes)? {
                "fungible" => "fungible",
                _ => Err(Error::ValueOutOfRange)?,
            }),
            1u8 => Self::Simplicity(bytes.to_vec()),
            _ => panic!("New scripting engines can't appear w/o this library to be aware of")
        })
    }
}


pub struct Scripting {
    pub validation: Procedure,
    pub extensions: Extensions,
}

impl Commitment for Scripting {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        self.validation.commitment_serialize(&mut e)?;
        self.extensions.commitment_serialize(&mut e)
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, Error> {
        Ok(Self{
            validation: <Procedure>::commitment_deserialize(&mut d)?,
            extensions: <Extensions>::commitment_deserialize(&mut d)?,
        })
    }
}

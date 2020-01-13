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

use crate::csv::{serialize, Commitment, Error};
use bitcoin::consensus::deserialize;

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

impl serialize::Commitment for Procedure {
    fn commitment_serialize<E: io::Write>(&self, &mut e: E) -> Result<usize, Error> {
        let value = match self {
            Self::Standard(name) => (0u8, name.to_vec()),
            Self::Simplicity(code) => (1u8, code),
            _ => panic!("New scripting engines can't appear w/o this library to be aware of")
        };
        let mut len = value.0.commitment_serialize(&mut e)?;
        len += value.1.commitment_serialize(&mut e)?;
        Ok(len)
    }

    fn commitment_deserialize<D: io::Read>(&mut d: D) -> Result<Self, Error> {
        let value = u8::consensus_deserialize(d)?(&mut d)?;
        let bytes = deserialize::<Vec<u8>>(&mut d)?;
        Ok(match value {
            0u8 => Self::Standard(str::from_utf8(&bytes)?),
            1u8 => Self::Simplicity(bytes),
            _ => panic!("New scripting engines can't appear w/o this library to be aware of")
        })
    }
}


pub struct Scripting {
    pub validation: Procedure,
    pub extensions: Extensions,
}

impl serialize::Commitment for Scripting {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        self.validation.commitment_serialize(&mut e)?;
        self.extensions.commitment_serialize(&mut e)
    }

    fn commitment_deserialize<D: io::Read>(&mut d: D) -> Result<Self, Error> {
        Ok(Self{
            validation: <Procedure>::commitment_deserialize(&mut d)?,
            extensions: <Extensions>::commitment_deserialize(&mut d)?,
        })
    }
}

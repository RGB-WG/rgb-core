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

use num_traits::{ToPrimitive, FromPrimitive};
use num_derive::{ToPrimitive, FromPrimitive};

use super::ValidationError;
use crate::csv::{Commitment, Error};
use crate::rgb;

#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Display, ToPrimitive, FromPrimitive)]
#[display_from(Debug)]
pub enum Extensions {
    ScriptsDenied = 0,
    ScriptsExtend,
    ScriptsReplace,
}

impl_commitment_enum!(Extensions);


#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Display, ToPrimitive, FromPrimitive)]
#[display_from(Debug)]
pub enum StandardProcedure {
    Rgb1Genesis,
    Rgb1Issue,
    Rgb1Transfer,
    Rgb1Prune,
    Rgb2Genesis,
    Rgb2Issue,
    Rgb2Transfer,
    Rgb2Prune,
}

impl_commitment_enum!(StandardProcedure);

impl StandardProcedure {
    pub fn validate(&self, _transition_script: Option<&rgb::Script>) -> Result<(), ValidationError> {
        // TODO: validate the script
        Ok(())
    }
}


#[non_exhaustive]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Display)]
#[display_from(Debug)]
pub enum Procedure {
    Standard(StandardProcedure),
    Simplicity(Vec<u8>)
}

impl Commitment for Procedure {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(match self {
            Self::Standard(proc_id) => commitment_serialize_list!(e; 0u8, proc_id),
            Self::Simplicity(code) => commitment_serialize_list!(e; 1u8, code),
            _ => panic!("New scripting engines can't appear w/o this library to be aware of")
        })
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, Error> {
        Ok(match u8::commitment_deserialize(&mut d)? {
            0u8 => Self::Standard(StandardProcedure::commitment_deserialize(&mut d)?),
            1u8 => Self::Simplicity(Vec::<u8>::commitment_deserialize(&mut d)?),
            _ => panic!("New scripting engines can't appear w/o this library to be aware of")
        })
    }
}


#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Display)]
#[display_from(Debug)]
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

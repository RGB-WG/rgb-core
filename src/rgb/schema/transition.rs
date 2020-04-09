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
use std::collections::HashMap;

use super::{
    types::*,
    field::*,
    script::Scripting,
};

use crate::csv::{serialize::Commitment, Error};


#[derive(Clone, Debug, Display)]
#[display_from(Debug)]
pub struct Transition {
    pub closes: Option<HashMap<usize, Occurences<u32>>>,
    pub fields: HashMap<usize, Field>,
    pub binds: HashMap<usize, Occurences<u32>>,
    pub scripting: Scripting,
}

impl Commitment for Transition {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        self.closes.commitment_serialize(&mut e)?;
        self.fields.commitment_serialize(&mut e)?;
        self.binds.commitment_serialize(&mut e)?;
        self.scripting.commitment_serialize(&mut e)
    }

    fn commitment_deserialize<D: io::Read>(d: D) -> Result<Self, Error> {
        unimplemented!()
        /*
        let closes = commitment_deserialize::<Option<HashMap<usize, Occurences<u32>>>>(&mut d)?;
        let fields: Vec<Field> = commitment_deserialize(&mut d)?;
        let binds = commitment_deserialize::<HashMap<usize, Occurences<u32>>>(&mut d)?;
        let scripting: Scripting = commitment_deserialize(&mut d)?;
        Ok(Self { closes, fields, binds, scripting })
        */
    }
}

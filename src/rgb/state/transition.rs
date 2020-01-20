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


use core::marker::PhantomData;
use std::{
    io, collections::HashMap
};

use super::{
    state,
    meta,
    script::Script,
};
use crate::{
    Wrapper,
    csv::serialize,
};


pub struct _MetaPhantom;
pub struct _StatePhantom;
pub type Meta = Wrapper<HashMap<meta::FieldId, meta::Value>, PhantomData<_MetaPhantom>>;
pub type State = Wrapper<HashMap<state::SealId, state::Value>, PhantomData<_StatePhantom>>;

pub struct Transition {
    pub meta: Meta,
    pub state: State,
    pub script: Option<Script>,
}

impl serialize::commitment::Commitment for Meta {
    fn commitment_serialize<E: io::Write>(&self, e: E) -> Result<usize, serialize::Error> {
        unimplemented!()
    }

    fn commitment_deserialize<D: io::Read>(d: D) -> Result<Self, serialize::Error> {
        unimplemented!()
    }
}

impl serialize::commitment::Commitment for State {
    fn commitment_serialize<E: io::Write>(&self, e: E) -> Result<usize, serialize::Error> {
        unimplemented!()
    }

    fn commitment_deserialize<D: io::Read>(d: D) -> Result<Self, serialize::Error> {
        unimplemented!()
    }
}

impl serialize::commitment::Commitment for Script {
    fn commitment_serialize<E: io::Write>(&self, e: E) -> Result<usize, serialize::Error> {
        // Nothing happens here yet
        Ok(0)
    }

    fn commitment_deserialize<D: io::Read>(d: D) -> Result<Self, serialize::Error> {
        // Nothing happens here yet
        Ok(Script::default())
    }
}

impl serialize::commitment::Commitment for Transition {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, serialize::Error> {
        Ok(
            self.meta.commitment_serialize(&mut e)? +
                self.state.commitment_serialize(&mut e)? +
                self.script.commitment_serialize(&mut e)?
        )
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, serialize::Error> {
        Ok(Self {
            meta: Meta::commitment_deserialize(&mut d)?,
            state: State::commitment_deserialize(&mut d)?,
            script: Option::<Script>::commitment_deserialize(&mut d)?
        })
    }
}

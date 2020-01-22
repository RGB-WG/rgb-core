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

use bitcoin::hashes::Hash;

use super::{
    state,
    fields,
    script::Script,
};
#[allow(unused_imports)]
#[macro_use]
use crate::bp::tagged256;
use crate::{
    Wrapper,
    csv::{serialize, commitment_serialize},
    common::merkle::*
};


wrapper!(Meta, _MetaPhantom, Vec<fields::MetaField>, doc="");
wrapper!(State, _StatePhantom, Vec<state::PartialState>, doc="");


impl serialize::commitment::Commitment for Meta {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, serialize::Error> {
        let mut data: Vec<MerkleNode> = vec![];
        self.as_ref().iter().try_for_each(|field| -> Result<(), serialize::Error> {
            data.push(MerkleNode::hash(&commitment_serialize(field)?));
            Ok(())
        })?;
        merklize(&data[..]).commitment_serialize(&mut e)
    }

    fn commitment_deserialize<D: io::Read>(d: D) -> Result<Self, serialize::Error> {
        panic!("It is impossible to deserialize from Merkle tree root commitment")
    }
}

impl serialize::commitment::Commitment for State {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, serialize::Error> {
        let mut data: Vec<MerkleNode> = vec![];
        self.as_ref().iter().try_for_each(|state| -> Result<(), serialize::Error> {
            data.push(MerkleNode::hash(&state.state_commitment()?));
            Ok(())
        })?;
        merklize(&data[..]).commitment_serialize(&mut e)
    }

    fn commitment_deserialize<D: io::Read>(d: D) -> Result<Self, serialize::Error> {
        panic!("It is impossible to deserialize from Merkle tree root commitment")
    }
}

impl serialize::commitment::Commitment for Script {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, serialize::Error> {
        // Nothing happens here yet
        let none: Vec<u8> = vec![];
        none.commitment_serialize(&mut e)
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, serialize::Error> {
        // Nothing happens here yet
        match Vec::<u8>::commitment_deserialize(&mut d)?.len() {
            0 => Ok(Self::default()),
            _ => Err(serialize::Error::ParseFailed("We can not deserialize non-empty scripts"))
        }
    }
}


pub struct Transition {
    pub meta: Meta,
    pub state: State,
    pub script: Option<Script>,
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

impl serialize::commitment::CommitmentIdentifiable for Transition {
    hashed_tag!("rgb:", "transition:1");
}

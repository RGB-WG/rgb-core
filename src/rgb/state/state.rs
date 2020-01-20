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


use std::{io, ops::Deref};

use bitcoin::util::uint::*;

use crate::csv::serialize;


#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Display)]
#[display_from(Debug)]
pub struct SealId(pub u16);

impl serialize::commitment::Commitment for SealId {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, serialize::Error> {
        self.0.commitment_serialize(&mut e)
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, serialize::Error> {
        Ok(SealId(u16::commitment_deserialize(&mut d)?))
    }
}


#[non_exhaustive]
#[derive(Clone, PartialEq, PartialOrd, Debug, Display)]
#[display_from(Debug)]
pub enum Value {
    Amount(Uint256),
    Bytes(Box<[u8]>),
    // TODO: Add other supported bound state types according to the schema
}

const TAG_AMOUNT: u8 = 0x00u8;
const TAG_BYTES: u8 = 0x60u8;

impl serialize::commitment::Commitment for Value {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, serialize::Error> {
        use Value::*;
        Ok(match self {
            Amount(v) => TAG_AMOUNT.commitment_serialize(&mut e)? + v.commitment_serialize(&mut e)?,
            Bytes(bytes) => {
                TAG_BYTES.commitment_serialize(&mut e)? + bytes.deref().commitment_serialize(&mut e)?
            },
            _ => panic!("Unsupported metafield type; can't do a commitment serialization of the data"),
        })
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, serialize::Error> {
        use Value::*;
        Ok(match u8::commitment_deserialize(&mut d)? {
            TAG_AMOUNT => Amount(Uint256::commitment_deserialize(&mut d)?),
            TAG_BYTES => Bytes(Box::from(<&[u8]>::commitment_deserialize(&mut d)?)),
            _ => panic!("Unsupported metafield type; can't do a commitment deserialization of the data"),
        })
    }
}


pub struct BoundState {
    pub id: SealId,
    pub val: Value,
}

impl serialize::commitment::Commitment for BoundState {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, serialize::Error> {
        Ok(self.id.commitment_serialize(&mut e)? + self.val.commitment_serialize(&mut e)?)
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, serialize::Error> {
        Ok(Self {
            id: SealId::commitment_deserialize(&mut d)?,
            val: Value::commitment_deserialize(&mut d)?
        })
    }
}

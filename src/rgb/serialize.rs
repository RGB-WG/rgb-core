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


use core::panic;
use std::{io, ops::Deref};

use bitcoin::{
    hash_types::Txid,
    hashes::Hash,
    util::uint::{Uint128, Uint256}
};

use crate::{bp, csv, rgb};


/// ## Metadata commitment serializaiton

/// ### Field type
impl csv::serialize::Commitment for rgb::metadata::Type {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, csv::serialize::Error> {
        self.0.commitment_serialize(&mut e)
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, csv::serialize::Error> {
        Ok(rgb::metadata::Type(u16::commitment_deserialize(&mut d)?))
    }
}

/// ### Field value

const TAG_U8: u8 = 0x01u8;
const TAG_U16: u8 = 0x02u8;
const TAG_U32: u8 = 0x04u8;
const TAG_U64: u8 = 0x08u8;
const TAG_U128: u8 = 0x0Fu8;
const TAG_U256: u8 = 0x1Fu8;
const TAG_I8: u8 = 0x21u8;
const TAG_I16: u8 = 0x22u8;
const TAG_I32: u8 = 0x24u8;
const TAG_I64: u8 = 0x28u8;
const TAG_F32: u8 = 0x44u8;
const TAG_F64: u8 = 0x48u8;
const TAG_BYTES: u8 = 0x60u8;
const TAG_STR: u8 = 0x61u8;

impl csv::serialize::Commitment for rgb::metadata::Value {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, csv::serialize::Error> {
        use rgb::metadata::Value::*;
        Ok(match self {
            U8(v) => TAG_U8.commitment_serialize(&mut e)? + v.commitment_serialize(&mut e)?,
            U16(v) => TAG_U16.commitment_serialize(&mut e)? + v.commitment_serialize(&mut e)?,
            U32(v) => TAG_U32.commitment_serialize(&mut e)? + v.commitment_serialize(&mut e)?,
            U64(v) => TAG_U64.commitment_serialize(&mut e)? + v.commitment_serialize(&mut e)?,
            U128(v) => TAG_U128.commitment_serialize(&mut e)? + v.commitment_serialize(&mut e)?,
            U256(v) => TAG_U256.commitment_serialize(&mut e)? + v.commitment_serialize(&mut e)?,
            I8(v) => TAG_I8.commitment_serialize(&mut e)? + v.commitment_serialize(&mut e)?,
            I16(v) => TAG_I16.commitment_serialize(&mut e)? + v.commitment_serialize(&mut e)?,
            I32(v) => TAG_I32.commitment_serialize(&mut e)? + v.commitment_serialize(&mut e)?,
            I64(v) => TAG_I64.commitment_serialize(&mut e)? + v.commitment_serialize(&mut e)?,
            F32(v) => TAG_F32.commitment_serialize(&mut e)? + v.commitment_serialize(&mut e)?,
            F64(v) => TAG_F64.commitment_serialize(&mut e)? + v.commitment_serialize(&mut e)?,
            Bytes(bytes) => {
                TAG_BYTES.commitment_serialize(&mut e)? + bytes.deref().commitment_serialize(&mut e)?
            },
            Str(string) => {
                TAG_STR.commitment_serialize(&mut e)? + string.as_str().commitment_serialize(&mut e)?
            },
            _ => Err(csv::serialize::Error::ValueOutOfRange)?,
        })
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, csv::serialize::Error> {
        use rgb::metadata::Value::*;
        Ok(match u8::commitment_deserialize(&mut d)? {
            TAG_U8 => U8(u8::commitment_deserialize(&mut d)?),
            TAG_U16 => U16(u16::commitment_deserialize(&mut d)?),
            TAG_U32 => U32(u32::commitment_deserialize(&mut d)?),
            TAG_U64 => U64(u64::commitment_deserialize(&mut d)?),
            TAG_U128 => U128(Uint128::commitment_deserialize(&mut d)?),
            TAG_U256 => U256(Uint256::commitment_deserialize(&mut d)?),
            TAG_I8 => I8(i8::commitment_deserialize(&mut d)?),
            TAG_I16 => I16(i16::commitment_deserialize(&mut d)?),
            TAG_I32 => I32(i32::commitment_deserialize(&mut d)?),
            TAG_I64 => I64(i64::commitment_deserialize(&mut d)?),
            TAG_F32 => F32(f32::commitment_deserialize(&mut d)?),
            TAG_F64 => F64(f64::commitment_deserialize(&mut d)?),
            TAG_BYTES => Bytes(Box::from(<&[u8]>::commitment_deserialize(&mut d)?)),
            TAG_STR => Str(String::from(<&str>::commitment_deserialize(&mut d)?)),
            _ => Err(csv::serialize::Error::ValueOutOfRange)?,
        })
    }
}

/// ### Field structure

impl csv::serialize::Commitment for rgb::metadata::Field {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, csv::serialize::Error> {
        Ok(self.id.commitment_serialize(&mut e)? + self.val.commitment_serialize(&mut e)?)
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, csv::serialize::Error> {
        Ok(Self {
            id: rgb::metadata::Type::commitment_deserialize(&mut d)?,
            val: rgb::metadata::Value::commitment_deserialize(&mut d)?
        })
    }
}

/// ### Set of metadata fields

// TODO: Refactor this into commitment generation code and separate network serialization routine
impl csv::serialize::Commitment for rgb::Metadata {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, csv::serialize::Error> {
        let mut data: Vec<bp::MerkleNode> = vec![];
        self.as_ref().iter().try_for_each(|field| -> Result<(), csv::serialize::Error> {
            data.push(bp::MerkleNode::hash(&csv::serialize::commitment_serialize(field)?));
            Ok(())
        })?;
        bp::merklize("RGB:meta:1", &data[..], 0).commitment_serialize(&mut e)
    }

    fn commitment_deserialize<D: io::Read>(d: D) -> Result<Self, csv::serialize::Error> {
        panic!("It is impossible to deserialize from Merkle tree root commitment")
    }
}


/// ## Seal commitment serialization

/// ### Seal type

impl csv::serialize::Commitment for rgb::seal::Type {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, csv::serialize::Error> {
        self.0.commitment_serialize(&mut e)
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, csv::serialize::Error> {
        Ok(Self(u16::commitment_deserialize(&mut d)?))
    }
}

/// ### Seal pointer

impl csv::serialize::Commitment for rgb::Seal {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, csv::serialize::Error> {
        Ok(self.txid.commitment_serialize(&mut e)? +
            self.vout.commitment_serialize(&mut e)?)
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, csv::serialize::Error> {
        Ok(Self::from(
            Txid::commitment_deserialize(&mut d)?,
            u16::commitment_deserialize(&mut d)?
        ))
    }
}


/// ## Data commitment serialization

const TAG_AMOUNT: u8 = 0x00u8;
const TAG_BINARY: u8 = 0x60u8;

impl csv::serialize::Commitment for rgb::data::Data {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, csv::serialize::Error> {
        use rgb::data::Data::*;
        Ok(match self {
            Balance(v) => TAG_AMOUNT.commitment_serialize(&mut e)? + v.commitment_serialize(&mut e)?,
            Binary(bytes) => {
                TAG_BINARY.commitment_serialize(&mut e)? + bytes.deref().commitment_serialize(&mut e)?
            },
            _ => Err(csv::serialize::Error::ValueOutOfRange)?,
        })
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, csv::serialize::Error> {
        use rgb::data::Data::*;
        Ok(match u8::commitment_deserialize(&mut d)? {
            TAG_AMOUNT => Balance(rgb::data::Amount::commitment_deserialize(&mut d)?),
            TAG_BINARY => Binary(Box::from(<&[u8]>::commitment_deserialize(&mut d)?)),
            _ => Err(csv::serialize::Error::ValueOutOfRange)?,
        })
    }
}


/// ## State commitment serialization

impl csv::serialize::Commitment for rgb::state::Bound {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, csv::serialize::Error> {
        Ok(
            self.id.commitment_serialize(&mut e)? +
            self.seal.commitment_serialize(&mut e)? +
            self.val.commitment_serialize(&mut e)?
        )
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, csv::serialize::Error> {
        Ok(Self {
            id: rgb::seal::Type::commitment_deserialize(&mut d)?,
            seal: rgb::seal::Seal::commitment_deserialize(&mut d)?,
            val: rgb::data::Data::commitment_deserialize(&mut d)?
        })
    }
}

// TODO: Refactor this into commitment generation code and separate network serialization routine
impl csv::serialize::Commitment for rgb::State {
    fn commitment_serialize<E: io::Write>(&self, e: E) -> Result<usize, csv::serialize::Error> {
        unimplemented!()
    }

    fn commitment_deserialize<D: io::Read>(d: D) -> Result<Self, csv::serialize::Error> {
        panic!("It is impossible to deserialize from Merkle tree root commitment")
    }
}


/// ## Script commitment serialization

impl csv::serialize::Commitment for rgb::Script {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, csv::serialize::Error> {
        // Nothing happens here yet
        let none: Vec<u8> = vec![];
        none.commitment_serialize(&mut e)
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, csv::serialize::Error> {
        // Nothing happens here yet
        match Vec::<u8>::commitment_deserialize(&mut d)?.len() {
            0 => Ok(Self::default()),
            _ => Err(csv::serialize::Error::ParseFailed("We can not deserialize non-empty scripts"))
        }
    }
}


/// ## State transition commitment serialization

impl csv::serialize::Commitment for rgb::Transition {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, csv::serialize::Error> {
        use crate::rgb::commit::Identifiable;
        Ok(
            self.meta.commitment_serialize(&mut e)? +
            self.state.commitment()?.commitment_serialize(&mut e)? +
            self.script.commitment_serialize(&mut e)?
        )
    }

    fn commitment_deserialize<D: io::Read>(d: D) -> Result<Self, csv::serialize::Error> {
        panic!("It is impossible to deserialize from transition commitment data")
        // TODO: Move this code into serialize::network
        /*Ok(Self {
            meta: Meta::commitment_deserialize(&mut d)?,
            state: State::commitment_deserialize(&mut d)?,
            script: Option::<Script>::commitment_deserialize(&mut d)?
        })*/
    }
}

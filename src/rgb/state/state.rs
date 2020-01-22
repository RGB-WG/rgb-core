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


use std::{io, ops::Deref, convert::TryFrom};

use bitcoin::{hash_types::Txid, OutPoint};

use crate::csv::{serialize, FromConsensus};


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


construct_uint!(Amount, 4);
impl FromConsensus for Amount { }


#[non_exhaustive]
#[derive(Clone, PartialEq, PartialOrd, Debug, Display)]
#[display_from(Debug)]
pub enum Value {
    Balance(Amount),
    Bytes(Box<[u8]>),
    // TODO: Add other supported bound state types according to the schema
}

const TAG_AMOUNT: u8 = 0x00u8;
const TAG_BYTES: u8 = 0x60u8;

impl serialize::commitment::Commitment for Value {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, serialize::Error> {
        use Value::*;
        Ok(match self {
            Balance(v) => TAG_AMOUNT.commitment_serialize(&mut e)? + v.commitment_serialize(&mut e)?,
            Bytes(bytes) => {
                TAG_BYTES.commitment_serialize(&mut e)? + bytes.deref().commitment_serialize(&mut e)?
            },
            _ => panic!("Unsupported metafield type; can't do a commitment serialization of the data"),
        })
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, serialize::Error> {
        use Value::*;
        Ok(match u8::commitment_deserialize(&mut d)? {
            TAG_AMOUNT => Balance(Amount::commitment_deserialize(&mut d)?),
            TAG_BYTES => Bytes(Box::from(<&[u8]>::commitment_deserialize(&mut d)?)),
            _ => panic!("Unsupported metafield type; can't do a commitment deserialization of the data"),
        })
    }
}


#[non_exhaustive]
#[derive(Clone, PartialEq, PartialOrd, Debug, Display)]
#[display_from(Debug)]
pub enum SealError {
    VoutOverflow
}

#[derive(Clone, PartialEq, PartialOrd, Debug, Display)]
#[display_from(Debug)]
pub struct Seal {
    pub txid: Txid,
    pub vout: u16,

    block_height: Option<u32>,
    block_offset: Option<u16>,
}

impl TryFrom<bitcoin::OutPoint> for Seal {
    type Error = SealError;
    fn try_from(outpoint: OutPoint) -> Result<Self, Self::Error> {
        let vout = outpoint.vout;
        if vout > std::u16::MAX as u32 {
            return Err(SealError::VoutOverflow)
        }
        Ok(Self {
            txid: outpoint.txid, vout: outpoint.vout as u16,
            block_height: None, block_offset: None
        })
    }
}

impl serialize::commitment::Commitment for Seal {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, serialize::Error> {
        Ok(self.txid.commitment_serialize(&mut e)? +
            self.vout.commitment_serialize(&mut e)?)
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, serialize::Error> {
        Ok(Self {
            txid: Txid::commitment_deserialize(&mut d)?,
            vout: u16::commitment_deserialize(&mut d)?,
            block_height: None,
            block_offset: None,
        })
    }
}



#[derive(Clone, PartialEq, PartialOrd, Debug, Display)]
#[display_from(Debug)]
pub struct BoundState {
    pub id: SealId,
    pub seal: Seal,
    pub val: Value,
}

impl serialize::commitment::Commitment for BoundState {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, serialize::Error> {
        Ok(
            self.id.commitment_serialize(&mut e)? +
            self.seal.commitment_serialize(&mut e)? +
            self.val.commitment_serialize(&mut e)?
        )
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, serialize::Error> {
        Ok(Self {
            id: SealId::commitment_deserialize(&mut d)?,
            seal: Seal::commitment_deserialize(&mut d)?,
            val: Value::commitment_deserialize(&mut d)?
        })
    }
}

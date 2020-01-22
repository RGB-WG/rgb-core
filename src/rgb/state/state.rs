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

use bitcoin::{
    hash_types::Txid,
    hashes::{sha256, sha256t},
};

use crate::cmt::committable::*;
use crate::csv::serialize::{
    self,
    FromConsensus,
    commitment_serialize
};


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
    fn try_from(outpoint: bitcoin::OutPoint) -> Result<Self, Self::Error> {
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


/// Midstate for RGB state commitment. Corresponds to "RGB:state:1" tag with
/// `23fadcc399c645274f9c884ff997f88168d6fe5739593114bb3e3851d3ed3406` hex value
const MIDSTATE_STATECOMMITMENT: [u8; 32] = [
    35, 250, 220, 195, 153, 198, 69, 39, 79, 156, 136, 79, 249, 151, 248, 129, 104, 214, 254, 87,
    57, 89, 49, 20, 187, 62, 56, 81, 211, 237, 52, 6
];

tagged_hash!(StateCommitment, StateCommitmentTag, StateCommitment, MIDSTATE_STATECOMMITMENT);

#[derive(Clone, PartialEq, PartialOrd, Debug, Display)]
#[display_from(Debug)]
pub enum PartialState {
    Commitment(StateCommitment),
    State(BoundState)
}

impl PartialState {
    pub fn state_commitment(&self) -> Result<StateCommitment, serialize::Error> {
        match self {
            Self::Commitment(cmt) => Ok(*cmt),
            Self::State(state) => state.state_commitment(),
        }
    }
}

#[derive(Clone, PartialEq, PartialOrd, Debug, Display)]
#[display_from(Debug)]
pub struct BoundState {
    pub id: SealId,
    pub seal: Seal,
    pub val: Value,
}

impl BoundState {
    pub fn state_commitment(&self) -> Result<StateCommitment, serialize::Error> {
        Ok(commitment_serialize(self)?.commit())
    }
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

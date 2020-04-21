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
use crate::csv::Error;
use crate::csv::Error::WrongDataSize;


const HASHTAG_MERKLESTATE: &'static str = "RGB:state:1";
const HASHTAG_MERKLEMETA: &'static str = "RGB:metadata:1";


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

network_serialize_from_commitment!(rgb::metadata::Type);

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
            TAG_BYTES => Bytes(Box::<[u8]>::commitment_deserialize(&mut d)?),
            TAG_STR => Str(String::commitment_deserialize(&mut d)?),
            _ => Err(csv::serialize::Error::ValueOutOfRange)?,
        })
    }
}

network_serialize_from_commitment!(rgb::metadata::Value);

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

network_serialize_from_commitment!(rgb::metadata::Field);

/// ### Set of metadata fields

impl csv::serialize::Commitment for rgb::Metadata {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, csv::serialize::Error> {
        use crate::rgb::commit::Identifiable;
        let data = self.as_ref().iter().try_fold(
            Vec::<bp::MerkleNode>::with_capacity(self.len()),
            |mut data, field| -> Result<Vec<bp::MerkleNode>, csv::serialize::Error> {
                data.push(bp::MerkleNode::from_inner(field.commitment()?.into_inner()));
                Ok(data)
            }
        )?;
        bp::merklize(HASHTAG_MERKLEMETA, &data[..], 0).commitment_serialize(&mut e)
    }

    fn commitment_deserialize<D: io::Read>(d: D) -> Result<Self, csv::serialize::Error> {
        panic!("It is impossible to deserialize from Merkle tree root commitment")
    }
}

impl csv::serialize::Network for rgb::Metadata {
    fn network_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, csv::serialize::Error> {
        self.as_ref().network_serialize(&mut e)
    }

    fn network_deserialize<D: io::Read>(mut d: D) -> Result<Self, csv::serialize::Error> {
        Vec::<rgb::metadata::Field>::network_deserialize(&mut d).map(Self::from_inner)
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

network_serialize_from_commitment!(rgb::seal::Type);

/// ### Seal pointer

const TAG_SEAL_VOUT: u8 = 0x00u8;
const TAG_SEAL_HASH: u8 = 0x80u8;

impl csv::serialize::Commitment for rgb::Seal {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, csv::serialize::Error> {
        match self {
            rgb::Seal::WitnessTxout(vout) => Ok(
                TAG_SEAL_VOUT.commitment_serialize(&mut e)? +
                vout.commitment_serialize(&mut e)?
            ),
            rgb::Seal::BlindedTxout(hash) => Ok(
                TAG_SEAL_HASH.commitment_serialize(&mut e)? +
                hash.commitment_serialize(&mut e)?
            ),
            rgb::Seal::RevealedTxout(reveal_data, _) => Ok(
                TAG_SEAL_HASH.commitment_serialize(&mut e)? +
                reveal_data.outpoint_hash().commitment_serialize(&mut e)?
            ),
        }
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, csv::serialize::Error> {
        Ok(match u8::commitment_deserialize(&mut d)? {
            TAG_SEAL_VOUT => rgb::Seal::witness(u16::commitment_deserialize(&mut d)?),
            TAG_SEAL_HASH => rgb::Seal::blinded(bp::blind::OutpointHash::commitment_deserialize(&mut d)?),
            _ => Err(csv::serialize::Error::ValueOutOfRange)?
        })
    }
}

const TAG_SEAL_WITNESS: u8 = 0x00u8;
const TAG_SEAL_BLINDED: u8 = 0x01u8;
const TAG_SEAL_REVEALED: u8 = 0x02u8;

impl csv::serialize::Network for rgb::Seal {
    fn network_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, csv::serialize::Error> {
        match self {
            rgb::Seal::WitnessTxout(vout) => Ok(
                TAG_SEAL_WITNESS.network_serialize(&mut e)? +
                vout.network_serialize(&mut e)?
            ),
            rgb::Seal::BlindedTxout(hash) => Ok(
                TAG_SEAL_BLINDED.network_serialize(&mut e)? +
                hash.network_serialize(&mut e)?
            ),
            rgb::Seal::RevealedTxout(reveal_data, short_id) => Ok(
                TAG_SEAL_REVEALED.network_serialize(&mut e)? +
                reveal_data.network_serialize(&mut e)? +
                short_id.network_serialize(&mut e)?
            ),
        }
    }

    fn network_deserialize<D: io::Read>(mut d: D) -> Result<Self, csv::serialize::Error> {
        Ok(match u8::network_deserialize(&mut d)? {
            TAG_SEAL_WITNESS => rgb::Seal::witness(
                u16::network_deserialize(&mut d)?
            ),
            TAG_SEAL_BLINDED => rgb::Seal::blinded(
                bp::blind::OutpointHash::network_deserialize(&mut d)?
            ),
            TAG_SEAL_REVEALED => rgb::Seal::outpoint_reveal(
                bp::blind::OutpointReveal::network_deserialize(&mut d)?,
                Option::<bp::ShortId>::network_deserialize(&mut d)?
            ),
            _ => Err(csv::serialize::Error::ValueOutOfRange)?,
        })
    }
}

/// ### Seal revealed outpoint

impl csv::serialize::Network for bp::blind::OutpointReveal {
    fn network_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, csv::serialize::Error> {
        Ok(
            self.blinding.network_serialize(&mut e)? +
            self.txid.network_serialize(&mut e)? +
            self.vout.network_serialize(&mut e)?
        )
    }

    fn network_deserialize<D: io::Read>(mut d: D) -> Result<Self, csv::serialize::Error> {
        Ok(Self {
            blinding: u64::network_deserialize(&mut d)?,
            txid: Txid::network_deserialize(&mut d)?,
            vout: u16::network_deserialize(&mut d)?
        })
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
            TAG_AMOUNT => Balance(rgb::data::amount::Commitment::commitment_deserialize(&mut d)?),
            TAG_BINARY => Binary(Box::from(<&[u8]>::commitment_deserialize(&mut d)?)),
            _ => Err(csv::serialize::Error::ValueOutOfRange)?,
        })
    }
}

network_serialize_from_commitment!(rgb::data::Data);

impl csv::serialize::Commitment for rgb::data::amount::Commitment {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        self.commitment.commitment_serialize(&mut e)?;
        self.bulletproof.commitment_serialize(&mut e)
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, Error> {
        use rgb::data::amount;
        use secp256k1zkp::pedersen;
        Ok(amount::Commitment {
            commitment: pedersen::Commitment::commitment_deserialize(&mut d)?,
            bulletproof: pedersen::RangeProof::commitment_deserialize(&mut d)?
        })
    }
}

network_serialize_from_commitment!(rgb::data::amount::Commitment);


impl csv::serialize::Commitment for secp256k1zkp::pedersen::Commitment {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        self.0.as_ref().commitment_serialize(&mut e)
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, Error> {
        use secp256k1zkp::constants::PEDERSEN_COMMITMENT_SIZE;
        let data = Box::<[u8]>::commitment_deserialize(&mut d)?;
        match data.len() {
            PEDERSEN_COMMITMENT_SIZE => {
                let mut ret = [0; PEDERSEN_COMMITMENT_SIZE];
                ret[..].copy_from_slice(&data);
                Ok(Self(ret))
            },
            _ => Err(WrongDataSize { expected: PEDERSEN_COMMITMENT_SIZE, found: data.len() })
        }
    }
}

network_serialize_from_commitment!(secp256k1zkp::pedersen::Commitment);


impl csv::serialize::Commitment for secp256k1zkp::pedersen::RangeProof {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        self.proof[..self.plen].as_ref().commitment_serialize(&mut e)
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, Error> {
        use secp256k1zkp::constants::MAX_PROOF_SIZE;
        let data = Box::<[u8]>::commitment_deserialize(&mut d)?;
        match data.len() {
            len if len < MAX_PROOF_SIZE => {
                let mut ret = [0; MAX_PROOF_SIZE];
                ret[..len].copy_from_slice(&data);
                Ok(Self{ proof: ret, plen: len })
            },
            _ => Err(WrongDataSize { expected: MAX_PROOF_SIZE, found: data.len() })
        }
    }
}

network_serialize_from_commitment!(secp256k1zkp::pedersen::RangeProof);



/// ## State commitment serialization

impl csv::serialize::Commitment for rgb::state::Partial {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, csv::serialize::Error> {
        match self {
            Self::Commitment(cmt) => cmt.commitment_serialize(&mut e),
            Self::State(state) => state.commitment_serialize(&mut e),
        }
    }

    fn commitment_deserialize<D: io::Read>(d: D) -> Result<Self, csv::serialize::Error> {
        panic!("It is impossible to deserialize from partial state commitment")
    }
}

const TAG_COMMITMENT: u8 = 0x00u8;
const TAG_STATE: u8 = 0x01u8;

impl csv::serialize::Network for rgb::state::Partial {
    fn network_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, csv::serialize::Error> {
        Ok(match self {
            Self::Commitment (cmt) => TAG_COMMITMENT.network_serialize(&mut e)? + cmt.network_serialize(&mut e)?,
            Self::State(state) => TAG_STATE.network_serialize(&mut e)? + state.network_serialize(&mut e)?,
        })
    }

    fn network_deserialize<D: io::Read>(mut d: D) -> Result<Self, csv::serialize::Error> {
        Ok(match u8::network_deserialize(&mut d)? {
            TAG_COMMITMENT => Self::Commitment(rgb::commit::StateCommitment::network_deserialize(&mut d)?),
            TAG_STATE => Self::State(rgb::state::Bound::network_deserialize(&mut d)?),
            _ => Err(csv::serialize::Error::ValueOutOfRange)?,
        })
    }
}


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

network_serialize_from_commitment!(rgb::state::Bound);


impl csv::serialize::Commitment for rgb::State {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, csv::serialize::Error> {
        use crate::rgb::commit::Identifiable;
        let data = self.as_ref().iter().try_fold(
            Vec::<bp::MerkleNode>::with_capacity(self.len()),
            |mut data, state| -> Result<Vec<bp::MerkleNode>, csv::serialize::Error> {
                data.push(bp::MerkleNode::from_inner(state.commitment()?.into_inner()));
                Ok(data)
            }
        )?;
        bp::merklize(HASHTAG_MERKLESTATE, &data[..], 0).commitment_serialize(&mut e)
    }

    fn commitment_deserialize<D: io::Read>(d: D) -> Result<Self, csv::serialize::Error> {
        panic!("It is impossible to deserialize from Merkle tree root commitment")
    }
}

impl csv::serialize::Network for rgb::State {
    fn network_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, csv::serialize::Error> {
        self.clone().into_inner().network_serialize(&mut e)
    }

    fn network_deserialize<D: io::Read>(mut d: D) -> Result<Self, csv::serialize::Error> {
        Vec::<rgb::state::Partial>::network_deserialize(&mut d).map(Self::from_inner)
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

network_serialize_from_commitment!(rgb::Script);


/// ## State transition commitment serialization

impl csv::serialize::Commitment for rgb::Transition {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, csv::serialize::Error> {
        use crate::rgb::commit::Identifiable;
        Ok(
            self.id.commitment_serialize(&mut e)? +
            self.meta.commitment()?.commitment_serialize(&mut e)? +
            self.state.commitment()?.commitment_serialize(&mut e)? +
            self.script.commitment()?.commitment_serialize(&mut e)?
        )
    }

    fn commitment_deserialize<D: io::Read>(d: D) -> Result<Self, csv::serialize::Error> {
        panic!("It is impossible to deserialize from transition commitment data")
    }
}

impl csv::serialize::Network for rgb::Transition {
    fn network_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, csv::serialize::Error> {
        Ok(
            self.id.network_serialize(&mut e)? +
            self.meta.network_serialize(&mut e)? +
            self.state.network_serialize(&mut e)? +
            self.script.network_serialize(&mut e)?
        )
    }

    fn network_deserialize<D: io::Read>(mut d: D) -> Result<Self, csv::serialize::Error> {
        Ok(Self {
            id: csv::serialize::Network::network_deserialize(&mut d)?,
            meta: rgb::Metadata::network_deserialize(&mut d)?,
            state: rgb::State::network_deserialize(&mut d)?,
            script: Option::<rgb::Script>::network_deserialize(&mut d)?
        })
    }
}

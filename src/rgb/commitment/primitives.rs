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


use std::{io, str, ops::Deref};

use num_traits::{ToPrimitive, FromPrimitive};
use bitcoin::{
    secp256k1,
    hash_types::Txid,
    util::uint::{Uint128, Uint256},
    consensus::encode as consensus
};

use super::{Commitment, Error};
use crate::bp::{ShortId, MerkleNode, blind::OutpointHash};


pub trait FromEnumPrimitive: FromPrimitive + ToPrimitive { }
pub trait FromConsensus: consensus::Encodable + consensus::Decodable { }

impl FromConsensus for u8 { }
impl FromConsensus for u16 { }
impl FromConsensus for u32 { }
impl FromConsensus for u64 { }
impl FromConsensus for Uint128 { }
impl FromConsensus for Uint256 { }
impl FromConsensus for i8 { }
impl FromConsensus for i16 { }
impl FromConsensus for i32 { }
impl FromConsensus for i64 { }
impl FromConsensus for Txid { }
impl FromConsensus for MerkleNode { }
impl FromConsensus for OutpointHash { }

impl<T> Commitment for T where T: FromConsensus {
    #[inline]
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(self.consensus_encode(&mut e)?)
    }

    #[inline]
    fn commitment_deserialize<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(Self::consensus_decode(d)?)
    }
}


impl Commitment for usize {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        if *self > std::u16::MAX as usize {
            return Err(consensus::Error::OversizedVectorAllocation {
                requested: *self, max: std::u16::MAX as usize
            }.into())
        }

        let size = *self as u16;
        size.commitment_serialize(&mut e)
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, Error> {
        u16::commitment_deserialize(&mut d).map(|val| val as usize)
    }
}


impl Commitment for f32 {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        e.write_all(&self.to_le_bytes()).map_err(consensus::Error::Io)?;
        Ok(4)
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf: [u8; 4] = [0; 4];
        d.read_exact(&mut buf).map_err(consensus::Error::Io)?;
        Ok(Self::from_le_bytes(buf))
    }
}


impl Commitment for f64 {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        e.write_all(&self.to_le_bytes()).map_err(consensus::Error::Io)?;
        Ok(8)
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf: [u8; 8] = [0; 8];
        d.read_exact(&mut buf).map_err(consensus::Error::Io)?;
        Ok(Self::from_le_bytes(buf))
    }
}


impl Commitment for &[u8] {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        let mut len = self.len();
        len += len.commitment_serialize(&mut e)?;
        e.write_all(self).map_err(consensus::Error::Io)?;
        Ok(len)
    }

    fn commitment_deserialize<D: io::Read>(d: D) -> Result<Self, Error> {
        panic!("Can't deserialize &[u8] type; use Box<[u8]> instead")
    }
}

impl Commitment for Box<[u8]> {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        self.deref().commitment_serialize(&mut e)
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let len = usize::commitment_deserialize(&mut d)?;
        let mut ret = Vec::with_capacity(len);
        ret.resize(len, 0);
        d.read_exact(&mut ret).map_err(consensus::Error::Io)?;
        Ok(ret.into_boxed_slice())
    }
}


impl Commitment for &str {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        self.as_bytes().commitment_serialize(&mut e)
    }

    fn commitment_deserialize<D: io::Read>(d: D) -> Result<Self, Error> {
        panic!("Can't deserialize &str type; use String instead")
    }
}

impl Commitment for String {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        self.as_bytes().commitment_serialize(&mut e)
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, Error> {
        String::from_utf8(Vec::<u8>::commitment_deserialize(&mut d)?).map_err(Error::from)
    }
}

impl Commitment for secp256k1::PublicKey {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(e.write(&self.serialize())?)
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf = [0u8; secp256k1::constants::PUBLIC_KEY_SIZE];
        d.read_exact(&mut buf);
        Ok(Self::from_slice(&buf).map_err(|_| Error::DataIntegrityError)?)
    }
}

impl Commitment for secp256k1::Signature {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(e.write(&self.serialize_compact())?)
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf = [0u8; secp256k1::constants::PUBLIC_KEY_SIZE];
        d.read_exact(&mut buf);
        Ok(Self::from_compact(&buf).map_err(|_| Error::DataIntegrityError)?)
    }
}

impl Commitment for bitcoin::Network {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(self.magic().commitment_serialize(&mut e)?)
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, Error> {
        Ok(Self::from_magic(u32::commitment_deserialize(&mut d)?).ok_or(Error::ValueOutOfRange)?)
    }
}

impl Commitment for ShortId {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        self.into_u64().commitment_serialize(&mut e)
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, Error> {
        Ok(Self::from(u64::commitment_deserialize(&mut d)?))
    }
}


// Tests
#[cfg(test)]
mod tests {
    use super::*;
    use crate::csv::commitment_serialize;

    /// Checking that byte serialization and deserialization works correctly for the most common
    /// marginal and middle-probability cases
    #[test]
    fn test_u8_serialize() {
        let zero: u8 = 0;
        let one: u8 = 1;
        let thirteen: u8 = 13;
        let confusing: u8 = 0xEF;
        let nearly_full: u8 = 0xFE;
        let full: u8 = 0xFF;

        let byte_0 = bytes![0u8];
        let byte_1 = bytes![1u8];
        let byte_13 = bytes![13u8];
        let byte_ef = bytes![0xEFu8];
        let byte_fe = bytes![0xFEu8];
        let byte_ff = bytes![0xFFu8];

        assert_eq!(commitment_serialize(&zero).unwrap(), byte_0);
        assert_eq!(commitment_serialize(&one).unwrap(), byte_1);
        assert_eq!(commitment_serialize(&thirteen).unwrap(), byte_13);
        assert_eq!(commitment_serialize(&confusing).unwrap(), byte_ef);
        assert_eq!(commitment_serialize(&nearly_full).unwrap(), byte_fe);
        assert_eq!(commitment_serialize(&full).unwrap(), byte_ff);

        assert_eq!(u8::commitment_deserialize(byte_0).unwrap(), zero);
        assert_eq!(u8::commitment_deserialize(byte_1).unwrap(), one);
        assert_eq!(u8::commitment_deserialize(byte_13).unwrap(), thirteen);
        assert_eq!(u8::commitment_deserialize(byte_ef).unwrap(), confusing);
        assert_eq!(u8::commitment_deserialize(byte_fe).unwrap(), nearly_full);
        assert_eq!(u8::commitment_deserialize(byte_ff).unwrap(), full);
    }
}

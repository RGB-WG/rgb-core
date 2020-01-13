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
use bitcoin::{
    consensus::encode as consensus,
};


#[derive(Debug)]
pub enum Error {
    BitcoinConsensus(consensus::Error)
}

impl From<consensus::Error> for Error {
    #[inline]
    fn from(err: consensus::Error) -> Self {
        Error::BitcoinConsensus(err)
    }
}

pub trait Commitment: Sized {
    fn commitment_serialize<E: io::Write>(&self, e: E) -> Result<usize, Error>;
    fn commitment_deserialize<D: io::Read>(d: D) -> Result<Self, Error>;
}

pub trait FromConsensus: consensus::Encodable + consensus::Decodable { }
impl FromConsensus for u8 {}
impl FromConsensus for u16 {}
impl FromConsensus for u32 {}
impl FromConsensus for u64 {}
impl FromConsensus for i8 {}
impl FromConsensus for i16 {}
impl FromConsensus for i32 {}
impl FromConsensus for i64 {}

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


impl<T> Commitment for Vec<T> where T: Commitment {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        if self.len() > std::u16::MAX as usize {
            return Err(consensus::Error::OversizedVectorAllocation {
                requested: self.len(), max: std::u16::MAX as usize
            }.into())
        }

        let mut serialized: usize = 0;
        let len = self.len() as u16;
        serialized += len.commitment_serialize(&mut e)?;
        for item in self {
            serialized += item.commitment_serialize(&mut e)?;
        }

        Ok(serialized)
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let len = u16::commitment_deserialize(&mut d)?;
        let mut data = Vec::<T>::with_capacity(len as usize);
        for _ in 0..len {
            data.push(T::commitment_deserialize(&mut d)?);
        }
        Ok(data)
    }
}

pub trait Network: Sized {
    fn network_serialize<E: io::Write>(&self, e: E) -> Result<usize, Error>;
    fn network_deserialize<D: io::Read>(d: D) -> Result<Self, Error>;
}

pub trait Storage: Sized {
    fn storage_serialize<E: io::Write>(&self, e: E) -> Result<usize, Error>;
    fn storage_deserialize<D: io::Read>(d: D) -> Result<Self, Error>;
}


impl<T> Network for T where T: Commitment {
    #[inline]
    fn network_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        self.commitment_serialize(&mut e)
    }

    #[inline]
    fn network_deserialize<D: io::Read>(d: D) -> Result<Self, Error> {
        Self::commitment_deserialize(d)
    }
}

impl<T> Storage for T where T: Commitment + Network {
    #[inline]
    fn storage_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        self.network_serialize(&mut e)
    }

    #[inline]
    fn storage_deserialize<D: io::Read>(d: D) -> Result<Self, Error> {
        Self::network_deserialize(d)
    }
}

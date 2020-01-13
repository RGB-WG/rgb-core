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


use std::{
    io,
    str::Utf8Error,
    collections::{HashMap, BTreeMap},
    convert::{From},
};

use num_traits::{ToPrimitive, FromPrimitive};
use bitcoin::{
    consensus::encode as consensus,
};


#[derive(Debug)]
pub enum Error {
    BitcoinConsensus(consensus::Error),
    EnumValueUnknown(u8),
    EnumValueOverflow,
    Utf8Error(Utf8Error),
    ValueOutOfRange,
    ParseFailed(&'static str)
}

impl From<Utf8Error> for Error {
    fn from(err: Utf8Error) -> Self {
        Self::Utf8Error(err)
    }
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

macro_rules! commitment_serialize_list {
    ( $encoder:ident; $($item:expr),+ ) => {
        {
            let mut len = 0usize;
            $(
                len += $item.commitment_serialize(&mut $encoder)?;
            )+
            len
        }
    }
}

pub trait FromEnumPrimitive: FromPrimitive + ToPrimitive { }
pub trait FromConsensus: consensus::Encodable + consensus::Decodable { }

impl FromConsensus for u8 { }
impl FromConsensus for u16 { }
impl FromConsensus for u32 { }
impl FromConsensus for u64 { }
impl FromConsensus for i8 { }
impl FromConsensus for i16 { }
impl FromConsensus for i32 { }
impl FromConsensus for i64 { }

macro_rules! impl_commitment_enum {
    ($type:ident) => {
        impl Commitment for $type {
            #[inline]
            fn commitment_serialize<E: ::std::io::Write>(&self, e: E) -> Result<usize, $crate::csv::serialize::Error> {
                match self.to_u8() {
                    Some(result) => result.commitment_serialize(e),
                    None => Err($crate::csv::serialize::Error::EnumValueOverflow),
                }
            }

            #[inline]
            fn commitment_deserialize<D: ::std::io::Read>(d: D) -> Result<Self,$crate::csv::serialize::Error> {
                let value = u8::commitment_deserialize(d)?;
                match Self::from_u8(value) {
                    Some(result) => Ok(result),
                    None => Err($crate::csv::serialize::Error::EnumValueUnknown(value)),
                }
            }
        }
    };
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

pub fn commitment_serialize<T: Commitment>(data: &T) -> Result<Vec<u8>, Error> {
    let mut encoder = io::Cursor::new(vec![]);
    data.commitment_serialize(&mut encoder)?;
    Ok(encoder.into_inner())
}

pub fn commitment_deserialize<T: Commitment>(data: &[u8]) -> Result<T, Error> {
    let mut decoder = io::Cursor::new(data);
    let rv = T::commitment_deserialize(&mut decoder)?;
    let consumed = decoder.position() as usize;

    // Fail if data are not consumed entirely.
    if consumed == data.len() {
        Ok(rv)
    } else {
        Err(Error::ParseFailed("data not consumed entirely when explicitly deserializing"))
    }
}



impl<T> Commitment for Option<T> where T: Commitment {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(match self {
            None => commitment_serialize_list!(e; 0u8),
            Some(val) => commitment_serialize_list!(e; 1u8, val),
        })
    }

    fn commitment_deserialize<D: io::Read>(d: D) -> Result<Self, Error> {
        unimplemented!()
    }
}

impl<T> Commitment for Vec<T> where T: Commitment {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        let len = self.len() as usize;
        let mut serialized = len.commitment_serialize(&mut e)?;
        for item in self {
            serialized += item.commitment_serialize(&mut e)?;
        }

        Ok(serialized)
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let len = usize::commitment_deserialize(&mut d)?;
        let mut data = Vec::<T>::with_capacity(len as usize);
        for _ in 0..len {
            data.push(T::commitment_deserialize(&mut d)?);
        }
        Ok(data)
    }
}

impl<T> Commitment for HashMap<usize, T> where T: Commitment {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        let len = self.len() as usize;
        let serialized = len.commitment_serialize(&mut e)?;

        let ordered: BTreeMap<_,_> = self.iter().collect();
        ordered.values().try_fold(serialized, |acc, item| {
            item.commitment_serialize(&mut e).map(|len| acc + len)
        })
    }

    fn commitment_deserialize<D: io::Read>(d: D) -> Result<Self, Error> {
        unimplemented!()
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

#[inline]
pub fn network_serialize<T: Commitment + Network>(data: &T) -> Result<Vec<u8>, Error> {
    commitment_serialize(data)
}

#[inline]
pub fn network_deserialize<T: Commitment + Network>(data: &[u8]) -> Result<T, Error> {
    T::commitment_deserialize(data)
}

#[inline]
pub fn storage_serialize<T: Commitment + Storage + Network>(data: &T) -> Result<Vec<u8>, Error> {
    network_serialize(data)
}

#[inline]
pub fn storage_deserialize<T: Commitment + Storage + Network>(data: &[u8]) -> Result<T, Error> {
    T::network_deserialize(data)
}

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

use super::Error;

pub trait Network: Sized {
    fn network_serialize<E: io::Write>(&self, e: E) -> Result<usize, Error>;
    fn network_deserialize<D: io::Read>(d: D) -> Result<Self, Error>;
}

/* We have to use custom implementations due to rust language limitations on default trait
   implementations */
// TODO: Re-implement it as a proc macro
#[macro_export]
macro_rules! network_serialize_from_commitment {
    ($type:ty) => {
        impl $crate::csv::serialize::network::Network for $type {
            #[inline]
            fn network_serialize<E: ::std::io::Write>(&self, mut e: E) -> Result<usize, $crate::csv::serialize::Error> {
                use $crate::csv::serialize::commitment::Commitment;
                self.commitment_serialize(&mut e)
            }

            #[inline]
            fn network_deserialize<D: ::std::io::Read>(d: D) -> Result<Self, $crate::csv::serialize::Error> {
                use $crate::csv::serialize::commitment::Commitment;
                Self::commitment_deserialize(d)
            }
        }
    };
}

macro_rules! network_serialize_list {
    ( $encoder:ident; $($item:expr),+ ) => {
        {
            let mut len = 0usize;
            $(
                len += $item.network_serialize(&mut $encoder)?;
            )+
            len
        }
    }
}

impl<T> Network for T where T: super::commitment::FromConsensus {
    #[inline]
    fn network_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(self.consensus_encode(&mut e)?)
    }

    #[inline]
    fn network_deserialize<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(Self::consensus_decode(d)?)
    }
}

network_serialize_from_commitment!(usize);
network_serialize_from_commitment!(f32);
network_serialize_from_commitment!(f64);
network_serialize_from_commitment!(&[u8]);
network_serialize_from_commitment!(Box<[u8]>);
network_serialize_from_commitment!(&str);


/// In terms of network serialization, we interpret `Option` as a zero-length `Vec`
/// (for `Optional::None`) or single-item `Vec` (for `Optional::Some`). For deserialization
/// an attempt to read `Option` from a serialized non-0 or non-1 length Vec will result in
/// `Error::WrongOptionalEncoding`.
impl<T> Network for Option<T> where T: Network {
    fn network_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(match self {
            None => network_serialize_list!(e; 0usize),
            Some(val) => network_serialize_list!(e; 1usize, val),
        })
    }

    fn network_deserialize<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut vec = Vec::<T>::network_deserialize(&mut d)?;
        match vec.len() {
            0 => Ok(None),
            1 => Ok(Some(
                vec.pop().expect("We are sure that there is a single item in the vec")
            )),
            _ => Err(Error::WrongOptionalEncoding),
        }
    }
}


/// In terms of network serialization, `Vec` is stored in form of usize-serialized length
/// (see `Commitment` implementation for `usize` type for serialization platform-independent
/// constant-length serialization rules) followed by a consequently-serialized vec items,
/// according to their type.
///
/// An attempt to serialize `Vec` with more items than can fit in `usize` serialization rules
/// will result in `Error::OversizedVectorAllocation`.
impl<T> Network for Vec<T> where T: Network {
    fn network_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        let len = self.len() as usize;
        let mut serialized = len.network_serialize(&mut e)?;
        for item in self {
            serialized += item.network_serialize(&mut e)?;
        }

        Ok(serialized)
    }

    fn network_deserialize<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let len = usize::network_deserialize(&mut d)?;
        let mut data = Vec::<T>::with_capacity(len as usize);
        for _ in 0..len {
            data.push(T::network_deserialize(&mut d)?);
        }
        Ok(data)
    }
}


#[inline]
pub fn network_serialize<T: Network>(data: &T) -> Result<Vec<u8>, Error> {
    let mut encoder = io::Cursor::new(vec![]);
    data.network_serialize(&mut encoder)?;
    Ok(encoder.into_inner())
}

#[inline]
pub fn network_deserialize<T: Network>(data: &[u8]) -> Result<T, Error> {
    let mut decoder = io::Cursor::new(data);
    let rv = T::network_deserialize(&mut decoder)?;
    let consumed = decoder.position() as usize;

    // Fail if data are not consumed entirely.
    if consumed == data.len() {
        Ok(rv)
    } else {
        Err(Error::ParseFailed("data not consumed entirely when explicitly deserialized"))
    }
}

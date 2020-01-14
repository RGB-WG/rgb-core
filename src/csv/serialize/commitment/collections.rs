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
use std::collections::{HashMap, BTreeMap};
use super::{Commitment, Error};


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

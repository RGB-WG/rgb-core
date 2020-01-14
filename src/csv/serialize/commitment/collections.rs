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
        // We interpret optionals as zero- or single-value arrays
        Ok(match self {
            None => commitment_serialize_list!(e; 0usize),
            Some(val) => commitment_serialize_list!(e; 1usize, val),
        })
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, Error> {
        // We interpret optionals as zero- or single-value arrays
        let mut vec = Vec::<T>::commitment_deserialize(&mut d)?;
        match vec.len() {
            0 => Ok(None),
            1 => Ok(Some(
                vec.pop().expect("We are sure that there is a single item in the vec")
            )),
            _ => Err(Error::WrongOptionalEncoding),
        }
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

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let len = usize::commitment_deserialize(&mut d)?;
        let mut map = HashMap::<usize, T>::new();
        for index in 0..len {
            map.insert(index, T::commitment_deserialize(&mut d)?);
        }
        Ok(map)
    }
}


// Tests
#[cfg(test)]
mod tests {
    use super::*;
    use crate::csv::{commitment_serialize, FromConsensus};

    // We do this for test purposes only just to have some complex data type;
    // Bitcoin transactions otherwise have no need to be committed to for client-side validation
    use bitcoin::Transaction;
    impl FromConsensus for Transaction { }

    #[test]
    /// Optionals of any type set to None must serialize to a two zero bytes and
    /// it must be possible to deserialize optional of any type from two zero bytes which
    /// must result of None value.
    fn test_option_serialize_none() {

        let o1: Option<u8> = None;
        let o2: Option<u64> = None;
        let o3: Option<Transaction> = None;

        let two_zero_bytes = &vec![0u8, 0u8][..];

        assert_eq!(commitment_serialize(&o1).unwrap(), two_zero_bytes);
        assert_eq!(commitment_serialize(&o2).unwrap(), two_zero_bytes);
        assert_eq!(commitment_serialize(&o3).unwrap(), two_zero_bytes);

        assert_eq!(Option::<u8>::commitment_deserialize(two_zero_bytes).unwrap(), None);
        assert_eq!(Option::<u64>::commitment_deserialize(two_zero_bytes).unwrap(), None);
        assert_eq!(Option::<Transaction>::commitment_deserialize(two_zero_bytes).unwrap(), None);
    }
}
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


//! File implements commitment serialization according to LNPBP-5 standard for common Rust data
//! structures: optionals `Option<T>`, vectors `Vec<T>` and ordered list in form of hash maps
//! `HashMap<usize, T>.


use std::io;
use std::collections::{HashMap, BTreeMap};
use super::{Commitment, Error};


/// In terms of commitment serialization, we interpret `Option` as a zero-length `Vec`
/// (for `Optional::None`) or single-item `Vec` (for `Optional::Some`). For deserialization
/// an attempt to read `Option` from a serialized non-0 or non-1 length Vec will result in
/// `Error::WrongOptionalEncoding`.
impl<T> Commitment for Option<T> where T: Commitment {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(match self {
            None => commitment_serialize_list!(e; 0usize),
            Some(val) => commitment_serialize_list!(e; 1usize, val),
        })
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, Error> {
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


/// In terms of commitment serialization, `Vec` is stored in form of usize-serialized length
/// (see `Commitemtn` implementation for `usize` type for serialization platform-independent
/// constant-length serialization rules) followed by a consequently-serialized vec items,
/// according to their type.
///
/// An attempt to serialize `Vec` with more items than can fit in `usize` serialization rules
/// will result in `Error::OversizedVectorAllocation`.
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


/// LNP/BP library uses `HashMap<usize, T: Commitment>`s to serialize ordered lists, where the
/// position of the list item must be fixed, since the item is referenced from elsewhere by its
/// index. Thus, the library does not supports and recommends not to support commitment
/// serialization of any other `HashMap` variants.
///
/// Commitment serialization of the `HashMap<usize, T>` type is performed by converting into
/// a fixed-order `Vec<T>` and serializing it according to the `Vec` commitment serialization rules.
/// This operation is internally performed via conversion into `BTreeMap<usize, T: Commitment>`.
impl<T> Commitment for HashMap<usize, T> where T: Commitment + Clone {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        let ordered: BTreeMap<usize, T> = self.iter().map(|(key , val)| {
            (*key, val.clone())
        }).collect();
        ordered.commitment_serialize(&mut e)
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let map: HashMap<usize, T> =
            BTreeMap::<usize, T>::commitment_deserialize(&mut d)?.iter().map(|(key, val)| {
                (*key, val.clone())
            }).collect();
        Ok(map)
    }
}

/// LNP/BP library uses `BTreeMap<usize, T: Commitment>`s to serialize ordered lists, where the
/// position of the list item must be fixed, since the item is referenced from elsewhere by its
/// index. Thus, the library does not supports and recommends not to support commitment
/// serialization of any other `BTreeMap` variants.
///
/// Commitment serialization of the `BTreeMap<usize, T>` type is performed by converting into
/// a fixed-order `Vec<T>` and serializing it according to the `Vec` commitment serialization rules.
impl<T> Commitment for BTreeMap<usize, T> where T: Commitment {
    fn commitment_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        let len = self.len() as usize;
        let serialized = len.commitment_serialize(&mut e)?;

        self.values().try_fold(serialized, |acc, item| {
            item.commitment_serialize(&mut e).map(|len| acc + len)
        })
    }

    fn commitment_deserialize<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let len = usize::commitment_deserialize(&mut d)?;
        let mut map = BTreeMap::<usize, T>::new();
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

    /// Test for checking the following rule from LNPBP-5:
    ///
    /// `Option<T>` of any type T, which are set to `Option::None` value MUST serialize as a two
    /// zero bytes and it MUST be possible to deserialize optional of any type from two zero bytes
    /// which MUST result in `Option::None` value.
    #[test]
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
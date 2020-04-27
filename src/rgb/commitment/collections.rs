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
/// (see `Commitment` implementation for `usize` type for serialization platform-independent
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
    /// `Option<T>` of any type T, which are set to `Option::None` value MUST serialize as two
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

    /// Test for checking the following rule from LNPBP-5:
    ///
    /// `Option<T>` of any type T, which are set to `Option::Some<T>` value MUST serialize as a
    /// `Vec<T>` structure containing a single item equal to the `Option::unwrap()` value.
    #[test]
    fn test_option_serialize_some() {
        let o1: Option<u8>    = Some(0);
        let o2: Option<u8>    = Some(13);
        let o3: Option<u8>    = Some(0xFF);
        let o4: Option<u64>   = Some(13);
        let o5: Option<u64>   = Some(0x1FF);
        let o6: Option<u64>   = Some(0xFFFFFFFFFFFFFFFF);
        let o7: Option<usize> = Some(13);
        let o8: Option<usize> = Some(0xFFFFFFFFFFFFFFFF);

        let byte_0    = bytes![1u8, 0u8,    0u8];
        let byte_13   = bytes![1u8, 0u8,   13u8];
        let byte_255  = bytes![1u8, 0u8, 0xFFu8];
        let word_13   = bytes![1u8, 0u8,   13u8,    0u8];
        let qword_13  = bytes![1u8, 0u8,   13u8,    0u8,    0u8,    0u8,    0u8,    0u8,    0u8,    0u8];
        let qword_256 = bytes![1u8, 0u8, 0xFFu8, 0x01u8,    0u8,    0u8,    0u8,    0u8,    0u8,    0u8];
        let qword_max = bytes![1u8, 0u8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8];

        assert_eq!(commitment_serialize(&o1).unwrap(), byte_0);
        assert_eq!(commitment_serialize(&o2).unwrap(), byte_13);
        assert_eq!(commitment_serialize(&o3).unwrap(), byte_255);
        assert_eq!(commitment_serialize(&o4).unwrap(), qword_13);
        assert_eq!(commitment_serialize(&o5).unwrap(), qword_256);
        assert_eq!(commitment_serialize(&o6).unwrap(), qword_max);
        assert_eq!(commitment_serialize(&o7).unwrap(), word_13);
        assert!(commitment_serialize(&o8).err().is_some());

        assert_eq!(Option::<u8>::commitment_deserialize(byte_0).unwrap(), Some(0));
        assert_eq!(Option::<u8>::commitment_deserialize(byte_13).unwrap(), Some(13));
        assert_eq!(Option::<u8>::commitment_deserialize(byte_255).unwrap(), Some(0xFF));
        assert_eq!(Option::<u64>::commitment_deserialize(qword_13).unwrap(), Some(13));
        assert_eq!(Option::<u64>::commitment_deserialize(qword_256).unwrap(), Some(0x1FF));
        assert_eq!(Option::<u64>::commitment_deserialize(qword_max).unwrap(), Some(0xFFFFFFFFFFFFFFFF));
        assert_eq!(Option::<usize>::commitment_deserialize(word_13).unwrap(), Some(13));
        assert_eq!(Option::<usize>::commitment_deserialize(qword_max).unwrap(), Some(0xFFFF));
    }

    /// Test trying deserialization of non-zero and non-single item vector structures, which MUST
    /// fail with a specific error.
    #[test]
    fn test_option_deserialize_vec() {
        assert!(Option::<u8>::commitment_deserialize(bytes![2u8, 0u8, 0u8, 0u8]).err().is_some());
        assert!(Option::<u8>::commitment_deserialize(bytes![3u8, 0u8, 0u8, 0u8]).err().is_some());
        assert!(Option::<u8>::commitment_deserialize(bytes![0xFFu8, 0u8, 0u8, 0u8]).err().is_some());
    }

    /// Test for checking the following rule from LNPBP-5:
    ///
    /// Array of any commitment-serializable type T MUST contain strictly less than `0x10000` items
    /// and must serialize as 16-bit little-endian value corresponding to the number of items
    /// followed by a direct serialization of each of the items.
    #[test]
    fn test_vec_serialize() {
        let v1: Vec<u8>    = vec![0, 13, 0xFF];
        let v2: Vec<u8>    = vec![13];
        let v3: Vec<u64>   = vec![0, 13, 13, 0x1FF, 0xFFFFFFFFFFFFFFFF];
        let v4: Vec<u8>    = (0..0x1FFFF).map(|item| (item % 0xFF) as u8).collect();

        let s1 = bytes![3u8, 0u8, 0u8, 13u8, 0xFFu8];
        let s2 = bytes![1u8, 0u8, 13u8];
        let s3 = bytes![
            5u8, 0u8,
            0, 0, 0, 0, 0, 0, 0, 0,
            13, 0, 0, 0, 0, 0, 0, 0,
            13, 0, 0, 0, 0, 0, 0, 0,
            0xFF, 1, 0, 0, 0, 0, 0, 0,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        ];

        assert_eq!(commitment_serialize(&v1).unwrap(), s1);
        assert_eq!(commitment_serialize(&v2).unwrap(), s2);
        assert_eq!(commitment_serialize(&v3).unwrap(), s3);
        assert!(commitment_serialize(&v4).err().is_some());

        assert_eq!(Vec::<u8>::commitment_deserialize(s1).unwrap(), v1);
        assert_eq!(Vec::<u8>::commitment_deserialize(s2).unwrap(), v2);
        assert_eq!(Vec::<u64>::commitment_deserialize(s3).unwrap(), v3);
    }
}
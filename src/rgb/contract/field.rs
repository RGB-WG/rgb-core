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

//! Convenience metadata accessor methods for Genesis and state transitions.

use core::fmt::Debug;
use core::hash::Hash;
use core::ops::Try;
use core::option::NoneError;
use std::collections::{BTreeMap, BTreeSet};

use super::data;
use crate::client_side_validation::{commit_strategy, CommitEncodeWithStrategy};
use crate::rgb::schema;

wrapper!(Metadata, BTreeMap<schema::FieldType, BTreeSet<data::Revealed>>, doc="Transition & genesis metadata fields", derive=[Default, PartialEq]);
impl CommitEncodeWithStrategy for Metadata {
    type Strategy = commit_strategy::Merklization;
}

impl CommitEncodeWithStrategy for BTreeSet<data::Revealed> {
    type Strategy = commit_strategy::Merklization;
}

// The data below are not part of the commitments!

macro_rules! field_extract {
    ($self:ident, $field:ident, $name:ident) => {
        $self
            .get(&$field)
            .and_then(|set| {
                let res: Vec<_> = set
                    .into_iter()
                    .filter_map(|data| match data {
                        data::Revealed::$name(val) => Some(val),
                        _ => None,
                    })
                    .cloned()
                    .collect();
                if res.is_empty() {
                    None
                } else if res.len() == 1 {
                    Some(FieldData::one(
                        res.first().expect("Rust core library is broken").clone(),
                    ))
                } else {
                    Some(FieldData::many(res))
                }
            })
            .unwrap_or(FieldData::empty())
    };
}

impl Metadata {
    pub fn u8(&self, field_type: schema::FieldType) -> FieldData<u8> {
        field_extract!(self, field_type, U8)
    }
    pub fn u16(&self, field_type: schema::FieldType) -> FieldData<u16> {
        field_extract!(self, field_type, U16)
    }
    pub fn u32(&self, field_type: schema::FieldType) -> FieldData<u32> {
        field_extract!(self, field_type, U32)
    }
    pub fn u64(&self, field_type: schema::FieldType) -> FieldData<u64> {
        field_extract!(self, field_type, U64)
    }
    pub fn i8(&self, field_type: schema::FieldType) -> FieldData<i8> {
        field_extract!(self, field_type, I8)
    }
    pub fn i16(&self, field_type: schema::FieldType) -> FieldData<i16> {
        field_extract!(self, field_type, I16)
    }
    pub fn i32(&self, field_type: schema::FieldType) -> FieldData<i32> {
        field_extract!(self, field_type, I32)
    }
    pub fn i64(&self, field_type: schema::FieldType) -> FieldData<i64> {
        field_extract!(self, field_type, I64)
    }
    pub fn f32(&self, field_type: schema::FieldType) -> FieldData<f32> {
        field_extract!(self, field_type, F32)
    }
    pub fn f64(&self, field_type: schema::FieldType) -> FieldData<f64> {
        field_extract!(self, field_type, F64)
    }
    pub fn bytes(&self, field_type: schema::FieldType) -> FieldData<Vec<u8>> {
        field_extract!(self, field_type, Bytes)
    }
    pub fn string(&self, field_type: schema::FieldType) -> FieldData<String> {
        field_extract!(self, field_type, String)
    }
}

#[derive(Clone, PartialEq, Hash, Debug, Display, Default)]
#[display_from(Debug)]
pub struct FieldData<T>
where
    T: Clone + Debug + PartialEq + Default,
{
    data: Vec<T>,
    next: usize,
}

impl<T> FieldData<T>
where
    T: Clone + Debug + PartialEq + Default,
{
    pub fn empty() -> Self {
        Self {
            data: vec![],
            ..Self::default()
        }
    }

    pub fn one(item: T) -> Self {
        Self {
            data: vec![item],
            ..Self::default()
        }
    }

    pub fn many(set: impl IntoIterator<Item = T>) -> Self {
        Self {
            data: set.into_iter().collect(),
            ..Self::default()
        }
    }
}

impl<T> Iterator for FieldData<T>
where
    T: Clone + Debug + PartialEq + Default,
{
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.data.get(self.next);
        self.next += 1;
        item.cloned()
    }
}

impl<T> Try for FieldData<T>
where
    T: Clone + Debug + Hash + PartialEq + Default,
{
    type Ok = T;
    type Error = NoneError;

    fn into_result(self) -> Result<Self::Ok, Self::Error> {
        Ok(self.data.first()?.clone())
    }

    fn from_error(_: Self::Error) -> Self {
        Self::empty()
    }

    fn from_ok(v: Self::Ok) -> Self {
        Self::one(v)
    }
}

impl<T> FieldData<T>
where
    T: Clone + Debug + Hash + PartialEq + Default,
{
    #[inline]
    pub fn as_vec(&self) -> &Vec<T> {
        &self.data
    }

    #[inline]
    pub fn into_vec(self) -> Vec<T> {
        self.data
    }

    #[inline]
    pub fn to_vec(&self) -> Vec<T> {
        self.data.clone()
    }
}

mod strict_encoding {
    use super::*;
    use crate::strict_encoding::{StrictDecode, StrictEncode};
    use amplify::Wrapper;
    use std::io;

    impl StrictEncode for Metadata {
        fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Self::Error> {
            self.to_inner().strict_encode(e)
        }
    }

    impl StrictDecode for Metadata {
        fn strict_decode<D: io::Read>(d: D) -> Result<Self, Self::Error> {
            Ok(Self::from_inner(<Self as Wrapper>::Inner::strict_decode(
                d,
            )?))
        }
    }
}

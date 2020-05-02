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

pub type Metadata = BTreeMap<schema::FieldType, BTreeSet<data::Revealed>>;
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
            .metadata()
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

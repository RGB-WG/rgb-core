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
                    Some(FieldData::Item(
                        res.first().expect("Rust core library is broken").clone(),
                    ))
                } else {
                    Some(FieldData::Set(res))
                }
            })
            .unwrap_or(FieldData::None)
    };
}

#[derive(Clone, PartialEq, Hash, Debug, Display)]
#[display_from(Debug)]
pub enum FieldData<T>
where
    T: Clone + Debug + PartialEq + Default,
{
    None,
    Item(T),
    Set(Vec<T>),
}

impl<T> Try for FieldData<T>
where
    T: Clone + Debug + Hash + PartialEq + Default,
{
    type Ok = T;
    type Error = ();

    fn into_result(self) -> Result<Self::Ok, Self::Error> {
        match self {
            FieldData::None => Err(()),
            FieldData::Item(item) => Ok(item),
            FieldData::Set(set) => Ok(set.first().cloned().unwrap_or_default()),
        }
    }

    fn from_error(_: Self::Error) -> Self {
        Self::None
    }

    fn from_ok(v: Self::Ok) -> Self {
        Self::Item(v)
    }
}

impl<T> FieldData<T>
where
    T: Clone + Debug + Hash + PartialEq + Default,
{
    #[inline]
    pub fn into_vec(self) -> Vec<T> {
        match self {
            FieldData::None => vec![],
            FieldData::Item(item) => vec![item],
            FieldData::Set(set) => set,
        }
    }

    #[inline]
    pub fn to_vec(&self) -> Vec<T> {
        match self {
            FieldData::None => vec![],
            FieldData::Item(item) => vec![item.clone()],
            FieldData::Set(set) => set.clone(),
        }
    }
}

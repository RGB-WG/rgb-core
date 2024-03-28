// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2019-2024 Dr Maxim Orlovsky. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::btree_map;

use amplify::confinement::{SmallBlob, TinyOrdMap};
use amplify::{confinement, Wrapper};
use commit_verify::StrictHash;

use crate::{schema, LIB_NAME_RGB};

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum MetadataError {
    /// value of metadata type #{0} is already set.
    AlreadyExists(schema::MetaType),

    /// too many metadata values.
    #[from(confinement::Error)]
    TooManyValues,
}

#[derive(
    Wrapper, WrapperMut, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Default, From
)]
#[display(LowerHex)]
#[wrapper(Deref, AsSlice, BorrowSlice, Hex)]
#[wrapper_mut(DerefMut)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
pub struct MetaValue(SmallBlob);

#[cfg(feature = "serde")]
mod _serde {
    use amplify::hex::FromHex;
    use serde_crate::de::Error;
    use serde_crate::{Deserialize, Deserializer, Serialize, Serializer};

    use super::*;

    impl Serialize for MetaValue {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer {
            serializer.serialize_str(&self.to_string())
        }
    }

    impl<'de> Deserialize<'de> for MetaValue {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de> {
            let s = String::deserialize(deserializer)?;
            Self::from_hex(&s).map_err(D::Error::custom)
        }
    }
}

#[derive(Wrapper, WrapperMut, Clone, PartialEq, Eq, Hash, Default, Debug, From)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = StrictHash)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct Metadata(TinyOrdMap<schema::MetaType, MetaValue>);

impl Metadata {
    pub fn add_value(
        &mut self,
        ty: schema::MetaType,
        meta: MetaValue,
    ) -> Result<(), MetadataError> {
        if self.0.contains_key(&ty) {
            return Err(MetadataError::AlreadyExists(ty));
        }
        self.0.insert(ty, meta)?;
        Ok(())
    }
}

impl<'a> IntoIterator for &'a Metadata {
    type Item = (&'a schema::MetaType, &'a MetaValue);
    type IntoIter = btree_map::Iter<'a, schema::MetaType, MetaValue>;

    fn into_iter(self) -> Self::IntoIter { self.0.iter() }
}

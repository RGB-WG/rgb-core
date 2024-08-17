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
use std::vec;

use amplify::confinement::{Confined, TinyOrdMap, U16};
use amplify::{confinement, Wrapper};
use strict_encoding::StrictDumb;

use crate::{schema, DataState, LIB_NAME_RGB_COMMIT};

#[derive(Wrapper, WrapperMut, Clone, PartialEq, Eq, Hash, Debug, From)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct GlobalValues(Confined<Vec<DataState>, 1, U16>);

impl StrictDumb for GlobalValues {
    fn strict_dumb() -> Self { Self(Confined::with(DataState::strict_dumb())) }
}

impl GlobalValues {
    pub fn with(state: DataState) -> Self { GlobalValues(Confined::with(state)) }
}

impl IntoIterator for GlobalValues {
    type Item = DataState;
    type IntoIter = vec::IntoIter<DataState>;

    fn into_iter(self) -> Self::IntoIter { self.0.into_iter() }
}

#[derive(Wrapper, WrapperMut, Clone, PartialEq, Eq, Hash, Default, Debug, From)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct GlobalState(TinyOrdMap<schema::GlobalStateType, GlobalValues>);

impl GlobalState {
    pub fn add_state(
        &mut self,
        ty: schema::GlobalStateType,
        state: DataState,
    ) -> Result<(), confinement::Error> {
        match self.0.get_mut(&ty) {
            Some(vec) => vec.push(state),
            None => self.insert(ty, GlobalValues::with(state)).map(|_| ()),
        }
    }

    pub fn extend_state(
        &mut self,
        ty: schema::GlobalStateType,
        iter: impl IntoIterator<Item = DataState>,
    ) -> Result<(), confinement::Error> {
        match self.0.get_mut(&ty) {
            Some(vec) => vec.extend(iter),
            None => self
                .insert(ty, GlobalValues::from_inner(Confined::try_from_iter(iter)?))
                .map(|_| ()),
        }
    }
}

impl<'a> IntoIterator for &'a GlobalState {
    type Item = (&'a schema::GlobalStateType, &'a GlobalValues);
    type IntoIter = btree_map::Iter<'a, schema::GlobalStateType, GlobalValues>;

    fn into_iter(self) -> Self::IntoIter { self.0.iter() }
}

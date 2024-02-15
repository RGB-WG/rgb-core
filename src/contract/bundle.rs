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

use std::collections::{btree_map, BTreeMap};

use amplify::confinement::{Confined, U16};
use amplify::{Bytes32, Wrapper};
use bp::Vout;
use commit_verify::{mpc, CommitEncode, CommitEngine, CommitId, CommitmentId, DigestExt, Sha256};
use strict_encoding::{StrictDumb, StrictEncode};

use crate::{OpId, Transition, LIB_NAME_RGB};

pub type Vin = Vout;

/// Unique state transition bundle identifier equivalent to the bundle
/// commitment hash
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, BorrowSlice, Display, Hex, Index, RangeOps)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct BundleId(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl From<Sha256> for BundleId {
    fn from(hasher: Sha256) -> Self { hasher.finish().into() }
}

impl CommitmentId for BundleId {
    const TAG: &'static str = "urn:lnp-bp:rgb:bundle#2024-02-03";
}

impl From<BundleId> for mpc::Message {
    fn from(id: BundleId) -> Self { mpc::Message::from_inner(id.into_inner()) }
}

impl From<mpc::Message> for BundleId {
    fn from(id: mpc::Message) -> Self { BundleId(id.into_inner()) }
}

#[derive(Wrapper, WrapperMut, Clone, PartialEq, Eq, Hash, Debug, From)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct InputMap(Confined<BTreeMap<Vin, OpId>, 1, U16>);

impl StrictDumb for InputMap {
    fn strict_dumb() -> Self { Self(confined_bmap!(strict_dumb!() => strict_dumb!())) }
}

impl InputMap {
    pub fn with(input: Vin, id: OpId) -> Self { InputMap(Confined::with((input, id))) }
}

impl IntoIterator for InputMap {
    type Item = (Vin, OpId);
    type IntoIter = btree_map::IntoIter<Vin, OpId>;

    fn into_iter(self) -> Self::IntoIter { self.0.into_iter() }
}

impl<'a> IntoIterator for &'a InputMap {
    type Item = (&'a Vin, &'a OpId);
    type IntoIter = btree_map::Iter<'a, Vin, OpId>;

    fn into_iter(self) -> Self::IntoIter { self.0.iter() }
}

#[derive(Clone, PartialEq, Eq, Debug, From)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct TransitionBundle {
    pub input_map: InputMap,
    pub known_transitions: Confined<BTreeMap<OpId, Transition>, 1, U16>,
}

impl CommitEncode for TransitionBundle {
    type CommitmentId = BundleId;

    fn commit_encode(&self, e: &mut CommitEngine) { e.commit_to(&self.input_map); }
}

impl StrictDumb for TransitionBundle {
    fn strict_dumb() -> Self {
        Self {
            input_map: strict_dumb!(),
            known_transitions: confined_bmap! { strict_dumb!() => strict_dumb!() },
        }
    }
}

impl TransitionBundle {
    pub fn bundle_id(&self) -> BundleId { self.commit_id() }
}

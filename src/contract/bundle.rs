// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2023 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2019-2023 Dr Maxim Orlovsky. All rights reserved.
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

use std::collections::BTreeMap;
use std::io::Write;

use amplify::confinement::{Confined, U16};
use amplify::{Bytes32, Wrapper};
use bp::Vout;
use commit_verify::{mpc, CommitEncode, CommitmentId};
use strict_encoding::{StrictEncode, StrictWriter};

use super::OpId;
use crate::{Transition, LIB_NAME_RGB};

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

impl From<BundleId> for mpc::Message {
    fn from(id: BundleId) -> Self { mpc::Message::from_inner(id.into_inner()) }
}

impl From<mpc::Message> for BundleId {
    fn from(id: mpc::Message) -> Self { BundleId(id.into_inner()) }
}

#[derive(Clone, PartialEq, Eq, Debug, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct TransitionBundle {
    input_map: Confined<BTreeMap<Vin, OpId>, 1, U16>,
    known_transitions: Confined<BTreeMap<OpId, Transition>, 1, U16>,
}

impl CommitEncode for TransitionBundle {
    fn commit_encode(&self, e: &mut impl Write) {
        let w = StrictWriter::with(u32::MAX as usize, e);
        self.input_map.strict_encode(w).ok();
    }
}

impl CommitmentId for TransitionBundle {
    const TAG: [u8; 32] = *b"urn:lnpbp:rgb:bundle:v1#20230306";
    type Id = BundleId;
}

impl TransitionBundle {
    pub fn bundle_id(&self) -> BundleId { self.commitment_id() }
}

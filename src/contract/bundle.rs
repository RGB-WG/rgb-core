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

use amplify::confinement::{TinyOrdMap, TinyOrdSet};
use amplify::{Bytes32, Wrapper};
use commit_verify::{mpc, CommitStrategy, CommitmentId};

use super::{NodeId, Transition};
use crate::LIB_NAME_RGB;

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

#[derive(Clone, PartialEq, Eq, Debug, AsAny)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct TransitionBundle {
    // TODO: #141 Provide type guarantees on the sum of revealed and concealed transitions
    pub revealed: TinyOrdMap<Transition, TinyOrdSet<u16>>,
    pub concealed: TinyOrdMap<NodeId, TinyOrdSet<u16>>,
}

impl CommitStrategy for TransitionBundle {
    type Strategy = commit_verify::strategies::Strict;
}

impl CommitmentId for TransitionBundle {
    const TAG: [u8; 32] = *b"urn:lnpbp:rgb:bundle:v1#20230306";
    type Id = BundleId;
}

impl TransitionBundle {
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize { self.concealed.len() + self.revealed.len() }

    pub fn bundle_id(&self) -> BundleId { self.commitment_id() }
}

impl TransitionBundle {
    pub fn validate(&self) -> bool {
        let mut used_inputs = bset! {};
        for set in self.revealed.values() {
            if used_inputs.intersection(set).count() > 0 {
                return false;
            }
            used_inputs.extend(set);
        }
        for set in self.concealed.values() {
            if used_inputs.intersection(set).count() > 0 {
                return false;
            }
            used_inputs.extend(set);
        }
        true
    }
}

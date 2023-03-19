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
use commit_verify::{mpc, CommitStrategy, CommitmentId, Conceal};

use super::{OpId, Transition};
use crate::{Operation, LIB_NAME_RGB};

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

#[derive(Clone, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB, tags = custom, dumb = Self::Concealed(strict_dumb!()))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum BundledTransition {
    #[strict_type(tag = 0)]
    Concealed(OpId),
    #[strict_type(tag = 1)]
    Revealed(Transition),
}

impl PartialEq for BundledTransition {
    fn eq(&self, other: &Self) -> bool { self.id() == other.id() }
}

impl CommitStrategy for BundledTransition {
    type Strategy = commit_verify::strategies::ConcealStrict;
}

impl Conceal for BundledTransition {
    type Concealed = Self;

    fn conceal(&self) -> Self {
        match self {
            BundledTransition::Revealed(ts) => Self::Concealed(ts.id()),
            BundledTransition::Concealed(ts) => BundledTransition::Concealed(*ts),
        }
    }
}

impl BundledTransition {
    pub fn id(&self) -> OpId {
        match self {
            BundledTransition::Concealed(id) => *id,
            BundledTransition::Revealed(ts) => ts.id(),
        }
    }

    pub fn as_revealed(&self) -> Option<&Transition> {
        match self {
            BundledTransition::Concealed(_) => None,
            BundledTransition::Revealed(ts) => Some(ts),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct BundleItem {
    pub inputs: TinyOrdSet<u16>,
    pub transition: BundledTransition,
}

impl CommitStrategy for BundleItem {
    type Strategy = commit_verify::strategies::ConcealStrict;
}

impl Conceal for BundleItem {
    type Concealed = Self;

    fn conceal(&self) -> Self::Concealed {
        BundleItem {
            inputs: self.inputs.clone(),
            transition: self.transition.conceal(),
        }
    }
}

#[derive(Wrapper, WrapperMut, Clone, PartialEq, Eq, Debug, From)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct TransitionBundle(TinyOrdMap<OpId, BundleItem>);

impl Conceal for TransitionBundle {
    type Concealed = Self;

    fn conceal(&self) -> Self::Concealed {
        let concealed = self.iter().map(|(id, item)| (*id, item.conceal()));
        TransitionBundle(TinyOrdMap::try_from_iter(concealed).expect("same size"))
    }
}

impl CommitStrategy for TransitionBundle {
    type Strategy = commit_verify::strategies::Strict;
}

impl CommitmentId for TransitionBundle {
    const TAG: [u8; 32] = *b"urn:lnpbp:rgb:bundle:v1#20230306";
    type Id = BundleId;
}

impl TransitionBundle {
    pub fn bundle_id(&self) -> BundleId { self.commitment_id() }
}

impl TransitionBundle {
    pub fn validate(&self) -> bool {
        let mut used_inputs = bset! {};
        for item in self.values() {
            if used_inputs.intersection(&item.inputs).count() > 0 {
                return false;
            }
            used_inputs.extend(&item.inputs);
        }
        true
    }
}

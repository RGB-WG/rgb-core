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

use std::collections::BTreeSet;

use amplify::confinement::{NonEmptyOrdMap, NonEmptyVec, U16 as U16MAX};
use amplify::{Bytes32, Wrapper};
use bp::Vout;
use commit_verify::{mpc, CommitEncode, CommitEngine, CommitId, CommitmentId, DigestExt, Sha256};
use strict_encoding::{StrictDumb, StrictEncode};

use super::{GraphSeal, Opout};
use crate::operation::operations::Operation;
use crate::{OpId, Transition, LIB_NAME_RGB_COMMIT};

pub type Vin = Vout;

/// Unique state transition bundle identifier equivalent to the bundle
/// commitment hash
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, BorrowSlice, Display, Hex, Index, RangeOps)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
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

#[derive(Clone, Eq, PartialEq, Debug, Display, Error)]
#[display("state transition {0} is not a part of the bundle.")]
pub struct UnrelatedTransition(OpId);

#[derive(Clone, Eq, PartialEq, Debug, Display, Error)]
#[display("detected uncommitted state transitions.")]
pub struct UnrelatedTransitions;

#[derive(Clone, PartialEq, Eq, Debug, From)]
#[derive(StrictType, StrictEncode, StrictDecode, StrictDumb)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct KnownTransition {
    pub opid: OpId,
    pub transition: Transition,
}

impl KnownTransition {
    pub fn new(opid: OpId, transition: Transition) -> Self { Self { opid, transition } }
}

#[derive(Clone, PartialEq, Eq, Debug, From)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct TransitionBundle {
    pub input_map: NonEmptyOrdMap<Opout, OpId, U16MAX>,
    pub known_transitions: NonEmptyVec<KnownTransition, U16MAX>,
}

impl CommitEncode for TransitionBundle {
    type CommitmentId = BundleId;

    fn commit_encode(&self, e: &mut CommitEngine) { e.commit_to_map(&self.input_map); }
}

impl StrictDumb for TransitionBundle {
    fn strict_dumb() -> Self {
        Self {
            input_map: NonEmptyOrdMap::with_key_value(strict_dumb!(), strict_dumb!()),
            known_transitions: NonEmptyVec::with(strict_dumb!()),
        }
    }
}

impl TransitionBundle {
    pub fn bundle_id(&self) -> BundleId { self.commit_id() }

    pub fn input_map_opids(&self) -> BTreeSet<OpId> { self.input_map.values().copied().collect() }

    pub fn known_transitions_opids(&self) -> BTreeSet<OpId> {
        self.known_transitions
            .iter()
            .map(|kt| kt.opid)
            .collect::<BTreeSet<_>>()
    }

    pub fn check_opid_commitments(&self) -> Result<(), UnrelatedTransitions> {
        let ids1 = self.known_transitions_opids();
        let ids2 = self.input_map_opids();
        if !ids1.is_subset(&ids2) {
            return Err(UnrelatedTransitions);
        }
        Ok(())
    }

    pub fn known_transitions_contain_opid(&self, opid: &OpId) -> bool {
        self.known_transitions.iter().any(|kt| &kt.opid == opid)
    }

    pub fn get_transition(&self, opid: OpId) -> Option<&Transition> {
        self.known_transitions.iter().find_map(|kt| {
            if kt.opid == opid {
                Some(&kt.transition)
            } else {
                None
            }
        })
    }

    pub fn reveal_seal(&mut self, bundle_id: BundleId, seal: GraphSeal) -> bool {
        if self.bundle_id() != bundle_id {
            return false;
        }
        self.known_transitions
            .iter_mut()
            .flat_map(|kt| kt.transition.assignments.values_mut())
            .for_each(|a| a.reveal_seal(seal));

        true
    }

    pub fn reveal_transition(
        &mut self,
        transition: Transition,
    ) -> Result<bool, UnrelatedTransition> {
        let opid = transition.id();
        if !self.input_map_opids().contains(&opid) {
            return Err(UnrelatedTransition(opid));
        }
        if self.known_transitions_contain_opid(&opid) {
            return Ok(false);
        }
        self.known_transitions
            .push(KnownTransition { opid, transition })
            .expect("same size as input map");
        Ok(true)
    }
}

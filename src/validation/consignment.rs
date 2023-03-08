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

//! Common API for accessing RGB contract operation graph, including individual
//! state transitions, extensions, genesis, outputs, assignments &
//! single-use-seal data.

use std::collections::BTreeSet;

use commit_verify::mpc;

use crate::{
    Anchor, BundleId, Extension, Genesis, OpId, OpRef, SecretSeal, SubSchema, Transition,
    TransitionBundle, LIB_NAME_RGB,
};

#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct AnchoredBundle {
    pub anchor: Anchor<mpc::MerkleProof>,
    pub bundle: TransitionBundle,
}

/// Trait defining common data access API for all storage-related RGB structures
///
/// # Verification
///
/// The function does not verify the internal consistency, schema conformance or
/// validation status of the RGB contract data withing the storage or container;
/// these checks must be performed as a separate step before calling any of the
/// [`ContainerApi`] methods. If the methods are called on
/// non-validated/unchecked data this may result in returned [`Error`] or
/// [`None`] values from the API methods.
pub trait ConsignmentApi {
    type BundleIter<'container>: Iterator<Item = &'container AnchoredBundle>
    where Self: 'container;

    fn schema(&self) -> &SubSchema;

    /// Retrieves reference to a operation (genesis, state transition or state
    /// extension) matching the provided id, or `None` otherwise
    fn operation(&self, opid: OpId) -> Option<OpRef>;

    /// Contract genesis.
    fn genesis(&self) -> &Genesis;

    /// Returns reference to a state transition, if known, matching the provided
    /// id. If id is unknown, or corresponds to other type of the operation
    /// (genesis or state extensions) a error is returned.
    ///
    /// # Errors
    ///
    /// - [`Error::WrongNodeType`] when operation is present, but has some other
    ///   operation type
    /// - [`Error::TransitionAbsent`] when operation with the given id is absent
    ///   from the storage/container
    fn transition(&self, opid: OpId) -> Option<&Transition>;

    /// Returns reference to a state extension, if known, matching the provided
    /// id. If id is unknown, or corresponds to other type of the operation
    /// (genesis or state transition) a error is returned.
    ///
    /// # Errors
    ///
    /// - [`Error::WrongNodeType`] when operation is present, but has some other
    ///   operation type
    /// - [`Error::ExtensionAbsent`] when operation with the given id is absent
    ///   from the storage/container
    fn extension(&self, opid: OpId) -> Option<&Extension>;

    /// The final state ("endpoints") provided by this consignment.
    ///
    /// There are two reasons for having endpoints:
    /// - navigation towards genesis from the final state is more
    ///   computationally efficient, since state transition/extension graph is
    ///   directed towards genesis (like bitcoin transaction graph)
    /// - if the consignment contains concealed state (known by the receiver),
    ///   it will be computationally inefficient to understand which of the
    ///   state transitions represent the final state
    fn terminals(&self) -> BTreeSet<(BundleId, SecretSeal)>;

    /// Data on all anchored state transitions contained in the consignment
    fn anchored_bundles(&self) -> Self::BundleIter<'_>;

    fn bundle_by_id(&self, bundle_id: BundleId) -> Option<&TransitionBundle>;

    fn op_ids_except(&self, ids: &BTreeSet<OpId>) -> BTreeSet<OpId>;

    fn has_operation(&self, opid: OpId) -> bool;

    fn known_transitions_by_bundle_id(&self, bundle_id: BundleId) -> Option<Vec<&Transition>>;
}

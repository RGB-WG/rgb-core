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

//! Common API for accessing RGB contract operation graph, including individual
//! state transitions, extensions, genesis, outputs, assignments &
//! single-use-seal data.

use crate::{
    AnchorSet, AssetTag, AssignmentType, BundleId, Genesis, OpId, OpRef, Operation, Schema,
    SecretSeal, TransitionBundle, XChain, XWitnessId,
};

pub struct CheckedConsignment<'consignment, C: ConsignmentApi>(&'consignment C);

impl<'consignment, C: ConsignmentApi> CheckedConsignment<'consignment, C> {
    pub fn new(consignment: &'consignment C) -> Self { Self(consignment) }
}

impl<'consignment, C: ConsignmentApi> ConsignmentApi for CheckedConsignment<'consignment, C> {
    fn schema(&self) -> &Schema { self.0.schema() }

    fn asset_tags<'iter>(&self) -> impl Iterator<Item = (AssignmentType, AssetTag)> + 'iter {
        self.0.asset_tags()
    }

    fn operation(&self, opid: OpId) -> Option<OpRef> {
        self.0.operation(opid).filter(|op| op.id() == opid)
    }

    fn genesis(&self) -> &Genesis { self.0.genesis() }

    fn terminals<'iter>(&self) -> impl Iterator<Item = (BundleId, XChain<SecretSeal>)> + 'iter {
        self.0.terminals()
    }

    fn bundle_ids<'iter>(&self) -> impl Iterator<Item = BundleId> + 'iter { self.0.bundle_ids() }

    fn bundle(&self, bundle_id: BundleId) -> Option<&TransitionBundle> {
        self.0
            .bundle(bundle_id)
            .filter(|b| b.bundle_id() == bundle_id)
    }

    fn anchors(&self, bundle_id: BundleId) -> Option<(XWitnessId, &AnchorSet)> {
        self.0.anchors(bundle_id)
    }

    fn op_witness_id(&self, opid: OpId) -> Option<XWitnessId> { self.0.op_witness_id(opid) }
}

/// Trait defining common data access API for all storage-related RGB structures
///
/// The API provided for the consignment should not verify the internal
/// consistency, schema conformance or validation status of the RGB contract
/// data within the storage or container. If the methods are called on an
/// invalid or absent data, the API must always return [`None`] or empty
/// collections/iterators.
pub trait ConsignmentApi {
    /// Returns reference to the schema object used by the consignment.
    fn schema(&self) -> &Schema;

    /// Asset tags uses in the confidential asset validation.
    fn asset_tags<'iter>(&self) -> impl Iterator<Item = (AssignmentType, AssetTag)> + 'iter;

    /// Retrieves reference to an operation (genesis, state transition or state
    /// extension) matching the provided id, or `None` otherwise
    fn operation(&self, opid: OpId) -> Option<OpRef>;

    /// Contract genesis.
    fn genesis(&self) -> &Genesis;

    /// The final state ("endpoints") provided by this consignment.
    ///
    /// There are two reasons for having endpoints:
    /// - navigation towards genesis from the final state is more
    ///   computationally efficient, since state transition/extension graph is
    ///   directed towards genesis (like bitcoin transaction graph)
    /// - if the consignment contains concealed state (known by the receiver),
    ///   it will be computationally inefficient to understand which of the
    ///   state transitions represent the final state
    fn terminals<'iter>(&self) -> impl Iterator<Item = (BundleId, XChain<SecretSeal>)> + 'iter;

    /// Returns iterator over all bundle ids present in the consignment.
    fn bundle_ids<'iter>(&self) -> impl Iterator<Item = BundleId> + 'iter;

    /// Returns reference to a bundle given a bundle id.
    fn bundle(&self, bundle_id: BundleId) -> Option<&TransitionBundle>;

    /// Returns a grip given a bundle id.
    fn anchors(&self, bundle_id: BundleId) -> Option<(XWitnessId, &AnchorSet)>;

    /// Returns witness id for a given operation.
    fn op_witness_id(&self, opid: OpId) -> Option<XWitnessId>;
}

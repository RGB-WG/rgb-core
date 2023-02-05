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

use std::collections::BTreeSet;

use commit_verify::mpc;

use crate::{
    Anchor, BundleId, Extension, Genesis, GraphApi, NodeId, Schema, SealEndpoint, TransitionBundle,
};

pub type ConsignmentEndpoint = (BundleId, SealEndpoint);

pub type AnchoredBundle<'me> = (&'me Anchor<mpc::MerkleProof>, &'me TransitionBundle);

pub trait Consignment<'consignment>: 'consignment + GraphApi {
    type EndpointIter: Iterator<Item = &'consignment ConsignmentEndpoint>;
    type BundleIter: Iterator<Item = &'consignment (Anchor<mpc::MerkleProof>, TransitionBundle)>;
    type ExtensionsIter: Iterator<Item = &'consignment Extension>;

    fn schema(&'consignment self) -> &'consignment Schema;

    fn root_schema(&'consignment self) -> Option<&'consignment Schema>;

    /// Genesis data
    fn genesis(&'consignment self) -> &'consignment Genesis;

    fn node_ids(&'consignment self) -> BTreeSet<NodeId>;

    /// The final state ("endpoints") provided by this consignment.
    ///
    /// There are two reasons for having endpoints:
    /// - navigation towards genesis from the final state is more
    ///   computationally efficient, since state transition/extension graph is
    ///   directed towards genesis (like bitcoin transaction graph)
    /// - if the consignment contains concealed state (known by the receiver),
    ///   it will be computationally inefficient to understand which of the
    ///   state transitions represent the final state
    fn endpoints(&'consignment self) -> Self::EndpointIter;

    /// Data on all anchored state transitions contained in the consignment
    fn anchored_bundles(&'consignment self) -> Self::BundleIter;

    /// Data on all state extensions contained in the consignment
    fn state_extensions(&'consignment self) -> Self::ExtensionsIter;
}

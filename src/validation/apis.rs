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

//! Common API for accessing RGB contract node graph, including individual state
//! transitions, extensions, genesis, outputs, assignments & single-use-seal
//! data.

use std::collections::BTreeSet;

use bp::dbc::AnchorId;
use bp::{Outpoint, Txid};
use commit_verify::mpc;

use crate::schema::OwnedStateType;
use crate::{
    seal, Anchor, BundleId, Extension, Genesis, OpId, Operation, PrevAssignment, Schema,
    Transition, TransitionBundle,
};

/// Errors accessing graph data via [`ContainerApi`].
///
/// All this errors imply internal inconsistency in the underlying data: they
/// are malformed (forged or damaged) and were not validated. The other reason
/// for these error are mistakes in the logic of the caller, which may not match
/// schema used by the contract.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum ConsistencyError {
    /// Bundle with id {0} is not present in the storage/container
    BundleIdAbsent(BundleId),

    /// Transition with id {0} is not present in the storage/container
    TransitionAbsent(OpId),

    /// Extension with id {0} is not present in the storage/container
    ExtensionAbsent(OpId),

    /// Anchor with id {0} is not present in the storage/container
    AnchorAbsent(AnchorId),

    /// No seals of the provided type {0} are closed by transition id {1}
    NoSealsClosed(OwnedStateType, OpId),

    /// Output {0} is not present in the storage
    OutputNotPresent(PrevAssignment),

    /// Seal definition for {0} is confidential while was required to be in
    /// revealed state
    ConfidentialSeal(PrevAssignment),

    /// The provided node with id {0} is not an endpoint of the consignment
    NotEndpoint(OpId),
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
/// [`Option::None`] values from the API methods.
pub trait ContainerApi {
    /// Returns reference to a node (genesis, state transition or state
    /// extension) matching the provided id, or `None` otherwise
    fn node_by_id(&self, node_id: OpId) -> Option<&dyn Operation>;

    fn bundle_by_id(&self, bundle_id: BundleId) -> Result<&TransitionBundle, ConsistencyError>;

    fn known_transitions_by_bundle_id(
        &self,
        bundle_id: BundleId,
    ) -> Result<Vec<&Transition>, ConsistencyError>;

    /// Returns reference to a state transition, if known, matching the provided
    /// id. If id is unknown, or corresponds to other type of the node (genesis
    /// or state extensions) a error is returned.
    ///
    /// # Errors
    ///
    /// - [`Error::WrongNodeType`] when node is present, but has some other node
    ///   type
    /// - [`Error::TransitionAbsent`] when node with the given id is absent from
    ///   the storage/container
    fn transition_by_id(&self, node_id: OpId) -> Result<&Transition, ConsistencyError>;

    /// Returns reference to a state extension, if known, matching the provided
    /// id. If id is unknown, or corresponds to other type of the node (genesis
    /// or state transition) a error is returned.
    ///
    /// # Errors
    ///
    /// - [`Error::WrongNodeType`] when node is present, but has some other node
    ///   type
    /// - [`Error::ExtensionAbsent`] when node with the given id is absent from
    ///   the storage/container
    fn extension_by_id(&self, node_id: OpId) -> Result<&Extension, ConsistencyError>;

    /// Returns reference to a state transition, like
    /// [`ContainerApi::transition_by_id`], extended with [`Txid`] of the
    /// witness transaction. If the node id is unknown, or corresponds to
    /// other type of the node (genesis or state extensions) a error is
    /// returned.
    ///
    /// # Errors
    ///
    /// - [`Error::WrongNodeType`] when node is present, but has some other node
    ///   type
    /// - [`Error::TransitionAbsent`] when node with the given id is absent from
    ///   the storage/container
    fn transition_witness_by_id(
        &self,
        node_id: OpId,
    ) -> Result<(&Transition, Txid), ConsistencyError>;

    /// Resolves seals closed by a given node with the given owned rights type
    ///
    /// # Arguments
    /// - `node_id`: node identifier closing previously defined single-use-seals
    /// - `owned_right_type`: type of the owned rights which must be assigned to
    ///   the closed seals. If seals are present, but have a different type, a
    ///   error is returned
    /// - `witness`: witness transaction id, needed for generating full
    ///   [`bp::Outpoint`] data for single-use-seal definitions providing
    ///   relative seals to the witness transaction (see [crate::seal::Revealed]
    ///   for the details).
    ///
    /// # Returns
    ///
    /// Returns a set of bitcoin transaction outpoints, which were defined as
    /// single-use-seals by RGB contract nodes, which were closed by the
    /// provided `node_id`, and which had an assigned state of type
    /// `owned_right_type`.
    ///
    /// # Errors
    ///
    /// - [`Error::TransitionAbsent`], if either `node_id` or one of its inputs
    ///   are not present in the storage or container
    /// - [`Error::OutputNotPresent`], if parent node, specified as an input for
    ///   the `node_id` does not contain the output with type
    ///   `owned_rights_type` and the number referenced by the node. Means that
    ///   the data in the container or storage are not valid/consistent.
    /// - [`Error::NoSealsClosed`], if the `node_id` does not closes any of the
    ///   seals with the provided `owned_rights_type`. Usually means that the
    ///   logic of the schema class library does not matches the actual schema
    ///   requirement, or that the container or data storage is not validated
    ///   against the schema and contains data which do not conform to the
    ///   schema requirements
    /// - [`Error::ConfidentialSeal`], if the provided data are present and
    ///   valid, however container/storage has concealed information about the
    ///   closed seal, when the revealed data are required
    fn seals_closed_with(
        &self,
        node_id: OpId,
        owned_right_type: impl Into<OwnedStateType>,
        witness: Txid,
    ) -> Result<BTreeSet<Outpoint>, ConsistencyError>;
}

pub trait HistoryApi: ContainerApi {
    type EndpointIter<'container>: Iterator<Item = &'container (BundleId, seal::Confidential)>
    where Self: 'container;
    type BundleIter<'container>: Iterator<
        Item = &'container (Anchor<mpc::MerkleProof>, TransitionBundle),
    >
    where Self: 'container;
    type ExtensionsIter<'container>: Iterator<Item = &'container Extension>
    where Self: 'container;

    fn schema(&self) -> &Schema;

    fn root_schema(&self) -> Option<&Schema>;

    /// Genesis data
    fn genesis(&self) -> &Genesis;

    fn node_ids(&self) -> BTreeSet<OpId>;

    /// The final state ("endpoints") provided by this consignment.
    ///
    /// There are two reasons for having endpoints:
    /// - navigation towards genesis from the final state is more
    ///   computationally efficient, since state transition/extension graph is
    ///   directed towards genesis (like bitcoin transaction graph)
    /// - if the consignment contains concealed state (known by the receiver),
    ///   it will be computationally inefficient to understand which of the
    ///   state transitions represent the final state
    fn endpoints(&self) -> Self::EndpointIter<'_>;

    /// Data on all anchored state transitions contained in the consignment
    fn anchored_bundles(&self) -> Self::BundleIter<'_>;

    /// Data on all state extensions contained in the consignment
    fn state_extensions(&self) -> Self::ExtensionsIter<'_>;
}

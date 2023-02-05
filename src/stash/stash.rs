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

//! API for working with stash: storage of RGB contract client-side-validated
//! data and data containers.
//!
//! Client-side-validated data, and (especially) data containers may grow large
//! (multiple gigabytes) and can't be fit in a memory as a single data
//! structure. Thus, we utilize a special API which abstracts the specific stash
//! storage mechanism (file-based, SQL or NoSQL database, special disk
//! partitions, cloud-provided storage, like with Bifrost protocol, etc).
//! With this API the data can be accessed using iterators or by providing the
//! specific data id.
//!
//! NB: Stash implementations must be able to operate multiple independent RGB
//! contract.

use bp::dbc::{Anchor, AnchorId};
use bp::Outpoint;
use commit_verify::mpc;

use crate::temp::ResolveTx;
use crate::{ContractId, Extension, Genesis, NodeId, Schema, SchemaId, Transition};

/// Top-level structure used by client wallets to manage all known RGB smart
/// contracts and related data.
///
/// Stash operates blobs, so it does not keep in the memory whole copy of all
/// data. Access to the underlying data structures happens through iterators:
/// - [`Stash::ContractIterator`]
///
/// Stash API is an alternative to the RGB contract data access API provided by
/// [`crate::GraphApi`], which is implemented by the structures keeping all the
/// data in memory ([`Consignment`] and [`Disclosure`]).
pub trait Stash {
    /// Error type returned by different stash functions
    type Error: std::error::Error;

    /// Iterator implementation able to run over known schemata and subschemata
    type SchemaIterator: Iterator<Item = Schema>;
    /// Iterator implementation able to run over all contract geneses
    type GenesisIterator: Iterator<Item = Genesis>;
    /// Iterator implementation able to run over all known anchors
    type AnchorIterator: Iterator<Item = Anchor<mpc::MerkleBlock>>;
    /// Iterator implementation able to run over all state transitions under
    /// particular contract
    type TransitionIterator: Iterator<Item = Transition>;
    /// Iterator implementation able to run over all state extensions under
    /// particular contract
    type ExtensionIterator: Iterator<Item = Extension>;
    /// Iterator implementation able to run over all node ids under
    /// particular contract
    type NodeIdIterator: Iterator<Item = NodeId>;

    /// Returns schema or subschema matching the provided id, if any, or
    /// storage-specific error otherwise
    fn get_schema(&self, schema_id: SchemaId) -> Result<Schema, Self::Error>;

    /// Returns genesis matching the provided id, if any, or storage-specific
    /// error otherwise
    fn get_genesis(&self, contract_id: ContractId) -> Result<Genesis, Self::Error>;

    /// Returns state transition matching the provided `node_id`, if any, or
    /// storage-specific error otherwise.
    ///
    /// NB: Here the state transition is identified by the node id and not
    /// relates to a specific contract_id. To get the transitions by a contract
    /// id please use transition iterator.
    fn get_transition(&self, node_id: NodeId) -> Result<Transition, Self::Error>;

    /// Returns state extension matching the provided `node_id`, if any, or
    /// storage-specific error otherwise.
    ///
    /// NB: Here the state extension is identified by the node id and not
    /// relates to a specific contract_id. To get the extensions by a contract
    /// id please use extension iterator.
    fn get_extension(&self, node_id: NodeId) -> Result<Extension, Self::Error>;

    /// Returns anchor matching the provided `anchor_id`, if any, or
    /// storage-specific error otherwise.
    ///
    /// NB: Anchors may be related to multiple contract ids; specific set of the
    /// contracts to which this anchor is related to may be known from the
    /// anchor data, unless they are kept in the confidential form. See
    /// [`Anchor`] documentation for the details.
    fn get_anchor(&self, anchor_id: AnchorId) -> Result<Anchor<mpc::MerkleBlock>, Self::Error>;

    /// Iterator over all contract geneses (i.e. iterator over all known RGB
    /// contracts).
    fn genesis_iter(&self) -> Self::GenesisIterator;

    /// Iterator over all known anchors
    ///
    /// NB: each anchor may be related to multiple contracts, thus here we do
    /// not provide contract id constraint for the iterator.
    fn anchor_iter(&self) -> Self::AnchorIterator;

    /// Iterator over all known state transition under particular RGB contract
    fn transition_iter(&self, contract_id: ContractId) -> Self::TransitionIterator;

    /// Iterator over all known state extensions under particular RGB contract
    fn extension_iter(&self, contract_id: ContractId) -> Self::ExtensionIterator;

    /// Clears all data that are not related to the contract state owned by
    /// us in this moment — under all known contracts. Uses provided
    /// `tx_resolver` to resolve validity of the related transactions (witness
    /// and single-use-seal) and `ownership_resolver` for checking whether
    /// specific transaction output is owned by the current user (stash data
    /// holder)
    fn prune(
        &mut self,
        tx_resolver: &mut impl ResolveTx,
        ownership_resolver: impl Fn(Outpoint) -> bool,
    ) -> Result<usize, Self::Error>;
}

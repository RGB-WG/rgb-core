// LNP/BP Rust Library
// Written in 2020-2021 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the MIT License
// along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

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

use std::collections::BTreeSet;

use bitcoin::OutPoint;
use bp::seals::OutpointReveal;
use wallet::onchain::ResolveTxFee;

use crate::{
    Anchor, AnchorId, Consignment, ContractId, Disclosure, Extension, Genesis,
    Node, NodeId, Schema, SchemaId, SealEndpoint, Transition,
};

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
    type AnchorIterator: Iterator<Item = Anchor>;
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
    fn get_genesis(
        &self,
        contract_id: ContractId,
    ) -> Result<Genesis, Self::Error>;

    /// Returns state transition matching the provided `node_id`, if any, or
    /// storage-specific error otherwise.
    ///
    /// NB: Here the state transition is identified by the node id and not
    /// relates to a specific contract_id. To get the transitions by a contract
    /// id please use transition iterator.
    fn get_transition(
        &self,
        node_id: NodeId,
    ) -> Result<Transition, Self::Error>;

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
    fn get_anchor(&self, anchor_id: AnchorId) -> Result<Anchor, Self::Error>;

    /// Iterator over all contract geneses (i.e. iterator over all known RGB
    /// contracts).
    fn genesis_iter(&self) -> Self::GenesisIterator;

    /// Iterator over all known anchors
    ///
    /// NB: each anchor may be related to multiple contracts, thus here we do
    /// not provide contract id constraint for the iterator.
    fn anchor_iter(&self) -> Self::AnchorIterator;

    /// Iterator over all known state transition under particular RGB contract
    fn transition_iter(
        &self,
        contract_id: ContractId,
    ) -> Self::TransitionIterator;

    /// Iterator over all known state extensions under particular RGB contract
    fn extension_iter(
        &self,
        contract_id: ContractId,
    ) -> Self::ExtensionIterator;

    /// When we need to send over to somebody else an update (like we have
    /// transferred him some state, for instance an asset) for each transfer we
    /// ask [`Stash`] to create a new [`Consignment`] for the given set of seals
    /// (`endpoints`) under some specific [`ContractId`], starting from a graph
    /// vertex `node`. If the node is state transition, we must also include
    /// `anchor` information.
    fn consign(
        &self,
        contract_id: ContractId,
        node: &impl Node,
        anchor: Option<&Anchor>,
        endpoints: &BTreeSet<SealEndpoint>,
    ) -> Result<Consignment, Self::Error>;

    /// When we have received data from other peer (which usually relate to our
    /// newly owned state, like assets) we do `accept` a [`Consignment`],
    /// and it gets into the known data.
    fn accept(
        &mut self,
        consignment: &Consignment,
        known_seals: &Vec<OutpointReveal>,
    ) -> Result<(), Self::Error>;

    /// Acquire knowledge from a given disclosure (**enclose** procedure)
    fn enclose(&mut self, disclosure: &Disclosure) -> Result<(), Self::Error>;

    /// Clears all data that are not related to the contract state owned by
    /// us in this moment — under all known contracts. Uses provided
    /// `tx_resolver` to resolve validity of the related transactions (witness
    /// and single-use-seal) and `ownership_resolver` for checking whether
    /// specific transaction output is owned by the current user (stash data
    /// holder)
    fn prune(
        &mut self,
        tx_resolver: &mut impl ResolveTxFee,
        ownership_resolver: impl Fn(OutPoint) -> bool,
    ) -> Result<usize, Self::Error>;
}

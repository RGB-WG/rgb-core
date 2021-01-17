// LNP/BP Rust Library
// Written in 2020 by
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

use lnpbp::bp::blind::OutpointHash;

use crate::{
    Anchor, Consignment, ContractId, Disclosure, Extension, Genesis, Node,
    NodeId, SchemaId, Transition,
};

/// Top-level structure used by client wallets to manage all known RGB smart
/// contracts and related data.
///
/// Stash operates blobs, so it does not keep in the memory whole copy of all
/// data. Access to the underlying data structures happens through iterators:
/// - [`Stash::ContractIterator`]
pub trait Stash {
    /// Error type returned by different stash functions
    type Error: std::error::Error;

    type GenesisIterator: Iterator<Item = Genesis>;
    type AnchorIterator: Iterator<Item = Anchor>;
    type TransitionIterator: Iterator<Item = Transition>;
    type ExtensionIterator: Iterator<Item = Extension>;
    type NidIterator: Iterator<Item = NodeId>;

    fn get_schema(&self, schema_id: SchemaId) -> Result<SchemaId, Self::Error>;

    fn get_genesis(
        &self,
        contract_id: ContractId,
    ) -> Result<Genesis, Self::Error>;

    fn get_transition(
        &self,
        node_id: NodeId,
    ) -> Result<Transition, Self::Error>;

    fn get_extension(&self, node_id: NodeId) -> Result<Extension, Self::Error>;

    fn get_anchor(&self, anchor_id: ContractId) -> Result<Anchor, Self::Error>;

    /// A contract is a genesis
    fn genesis_iter(&self) -> Self::GenesisIterator;

    /// We have to keep anchors at this level, since they may link many
    /// state transitions under multiple contracts at the same time (via
    /// LNPBP-4 multimessage commitments)
    fn anchor_iter(&self) -> Self::AnchorIterator;

    fn transition_iter(&self) -> Self::TransitionIterator;

    fn extension_iter(&self) -> Self::ExtensionIterator;

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
        expose: &Vec<OutpointHash>,
    ) -> Result<Consignment, Self::Error>;

    /// When we have received data from other peer (which usually relate to our
    /// newly owned state, like assets) we do `merge` with a [`Consignment`],
    /// and it gets into the known data.
    fn merge(
        &mut self,
        consignment: Consignment,
    ) -> Result<Vec<Box<dyn Node>>, Self::Error>;

    /// If we need to forget about the state which is not owned by us anymore
    /// (we have done the transfer and would like to prune this specific info)
    /// we call this function
    fn forget(
        &mut self,
        consignment: Consignment,
    ) -> Result<usize, Self::Error>;

    /// Clears all data that are not related to the contract state owned by
    /// us in this moment — under all known contracts
    fn prune(&mut self) -> Result<usize, Self::Error>;

    /// Prepares disclosure with confidential information
    fn disclose(&self) -> Result<Disclosure, Self::Error>;
}

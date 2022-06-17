// RGB Core Library: a reference implementation of RGB smart contract standards.
// Written in 2019-2022 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the MIT License along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

use std::collections::BTreeSet;

use commit_verify::lnpbp4;

use crate::{
    Anchor, BundleId, Extension, Genesis, GraphApi, NodeId, Schema, SealEndpoint, TransitionBundle,
};

pub type ConsignmentEndpoint = (BundleId, SealEndpoint);

pub type AnchoredBundle<'me> = (&'me Anchor<lnpbp4::MerkleProof>, &'me TransitionBundle);

pub trait Consignment<'consignment>: 'consignment + GraphApi {
    type EndpointIter: Iterator<Item = ConsignmentEndpoint>;
    type BundleIter: Iterator<Item = AnchoredBundle<'consignment>>;
    type ExtensionsIter: Iterator<Item = &'consignment Extension>;

    fn schema(&self) -> &Schema;

    fn root_schema(&self) -> Option<&Schema>;

    /// Genesis data
    fn genesis(&self) -> &Genesis;

    fn node_ids(&self) -> &BTreeSet<NodeId>;

    /// The final state ("endpoints") provided by this consignment.
    ///
    /// There are two reasons for having endpoints:
    /// - navigation towards genesis from the final state is more
    ///   computationally efficient, since state transition/extension graph is
    ///   directed towards genesis (like bitcoin transaction graph)
    /// - if the consignment contains concealed state (known by the receiver),
    ///   it will be computationally inefficient to understand which of the
    ///   state transitions represent the final state
    fn endpoints(&self) -> Self::EndpointIter;

    /// Data on all anchored state transitions contained in the consignment
    fn anchored_bundles(&self) -> Self::BundleIter;

    /// Data on all state extensions contained in the consignment
    fn state_extensions(&self) -> Self::ExtensionsIter;
}

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

//! Common API for accessing RGB contract node graph, including individual state
//! transitions, extensions, genesis, outputs, assignments & single-use-seal
//! data.
//!
//! Implemented by all storage-managing [`rgb::stash`] structures, including:
//! - [`Consignment`]
//! - [`Disclosure`]
//!
//! [`Stash`] API is the alternative form of API used by stash implementations,
//! which may operate much larger volumes of client-side-validated data, which
//! may not fit into the memory, and thus using specially-designed iterators and
//! different storage drivers returning driver-specific error types.

use std::collections::BTreeSet;

use bitcoin::{OutPoint, Txid};
use bp::dbc::AnchorId;
use bp::seals::txout::TxoSeal;

use crate::schema::{NodeType, OwnedRightType};
use crate::{Consignment, Extension, Node, NodeId, NodeOutpoint, Transition};

/// Errors accessing graph data via [`GraphApi`].
///
/// All this errors imply internal inconsistency in the underlying data: they
/// are malformed (forged or damaged) and were not validated. The other reason
/// for these error are mistakes in the logic of the caller, which may not match
/// schema used by the contract.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum ConsistencyError {
    /// Node with id {0} is not present in the storage/container
    NodeIdAbsent(NodeId),

    /// Requested node with id {node_id} has a different type {actual} from the
    /// requested type {requested}. This error usually means that the
    /// implementation of the schema-specific library has internal logical
    /// errors
    WrongNodeType {
        /// Node id
        node_id: NodeId,
        /// Requested type of the node
        requested: NodeType,
        /// Actually present node type
        actual: NodeType,
    },

    /// Transition with id {0} is not present in the storage/container
    TransitionAbsent(NodeId),

    /// Extension with id {0} is not present in the storage/container
    ExtensionAbsent(NodeId),

    /// Anchor with id {0} is not present in the storage/container
    AnchorAbsent(AnchorId),

    /// No seals of the provided type {0} are closed by transition id {1}
    NoSealsClosed(OwnedRightType, NodeId),

    /// Output {0} is not present in the storage
    OutputNotPresent(NodeOutpoint),

    /// Seal definition for {0} is confidential while was required to be in
    /// revealed state
    ConfidentialSeal(NodeOutpoint),

    /// The provided node with id {0} is not an endpoint of the consignment
    NotEndpoint(NodeId),
}

/// Trait defining common data access API for all storage-related RGB structures
///
/// # Verification
///
/// The function does not verify the internal consistency, schema conformance or
/// validation status of the RGB contract data withing the storage or container;
/// these checks must be performed as a separate step before calling any of the
/// [`GraphApi`] methods. If the methods are called on non-validated/unchecked
/// data this may result in returned [`Error`] or [`Option::None`] values from
/// the API methods.
pub trait GraphApi {
    /// Returns reference to a node (genesis, state transition or state
    /// extension) matching the provided id, or `None` otherwise
    fn node_by_id(&self, node_id: NodeId) -> Option<&dyn Node>;

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
    fn transition_by_id(&self, node_id: NodeId) -> Result<&Transition, ConsistencyError>;

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
    fn extension_by_id(&self, node_id: NodeId) -> Result<&Extension, ConsistencyError>;

    /// Returns reference to a state transition, like
    /// [`GraphApi::transition_by_id`], extended with [`Txid`] of the witness
    /// transaction. If the node id is unknown, or corresponds to other type of
    /// the node (genesis or state extensions) a error is returned.
    ///
    /// # Errors
    ///
    /// - [`Error::WrongNodeType`] when node is present, but has some other node
    ///   type
    /// - [`Error::TransitionAbsent`] when node with the given id is absent from
    ///   the storage/container
    fn transition_witness_by_id(
        &self,
        node_id: NodeId,
    ) -> Result<(&Transition, Txid), ConsistencyError>;

    /// Resolves seals closed by a given node with the given owned rights type
    ///
    /// # Arguments
    /// - `node_id`: node identifier closing previously defined single-use-seals
    /// - `owned_right_type`: type of the owned rights which must be assigned to
    ///   the closed seals. If seals are present, but have a different type, a
    ///   error is returned
    /// - `witness`: witness transaction id, needed for generating full
    ///   [`bitcoin::OutPoint`] data for single-use-seal definitions providing
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
        node_id: NodeId,
        owned_right_type: impl Into<OwnedRightType>,
        witness: Txid,
    ) -> Result<BTreeSet<OutPoint>, ConsistencyError>;
}

impl GraphApi for Consignment {
    fn node_by_id(&self, node_id: NodeId) -> Option<&dyn Node> {
        if self.genesis.node_id() == node_id {
            return Some(&self.genesis);
        }
        self.state_transitions
            .iter()
            .find(|(_, transition)| transition.node_id() == node_id)
            .map(|(_, transition)| transition as &dyn Node)
            .or_else(|| {
                self.state_extensions
                    .iter()
                    .find(|extension| extension.node_id() == node_id)
                    .map(|extension| extension as &dyn Node)
            })
    }

    fn transition_by_id(&self, node_id: NodeId) -> Result<&Transition, ConsistencyError> {
        Ok(self.transition_witness_by_id(node_id)?.0)
    }

    fn extension_by_id(&self, node_id: NodeId) -> Result<&Extension, ConsistencyError> {
        self.state_extensions
            .iter()
            .find(|extension| extension.node_id() == node_id)
            .ok_or(ConsistencyError::ExtensionAbsent(node_id))
            .or_else(|err| {
                self.state_transitions
                    .iter()
                    .find(|(_, transition)| transition.node_id() == node_id)
                    .map(|_| {
                        Err(ConsistencyError::WrongNodeType {
                            node_id,
                            requested: NodeType::StateExtension,
                            actual: NodeType::StateTransition,
                        })
                    })
                    .transpose()?
                    .or_else(
                        || {
                            if self.genesis.node_id() == node_id {
                                Some(Err(err))
                            } else {
                                None
                            }
                        },
                    )
                    .transpose()?
                    .ok_or(ConsistencyError::WrongNodeType {
                        node_id,
                        requested: NodeType::StateExtension,
                        actual: NodeType::Genesis,
                    })?
            })
    }

    fn transition_witness_by_id(
        &self,
        node_id: NodeId,
    ) -> Result<(&Transition, Txid), ConsistencyError> {
        self.state_transitions
            .iter()
            .find(|(_, transition)| transition.node_id() == node_id)
            .map(|(anchor, transition)| (transition, anchor.txid))
            .ok_or(ConsistencyError::TransitionAbsent(node_id))
            .or_else(|err| {
                self.state_extensions
                    .iter()
                    .find(|extension| extension.node_id() == node_id)
                    .map(|_| {
                        Err(ConsistencyError::WrongNodeType {
                            node_id,
                            requested: NodeType::StateTransition,
                            actual: NodeType::StateExtension,
                        })
                    })
                    .transpose()?
                    .or_else(
                        || {
                            if self.genesis.node_id() == node_id {
                                Some(Err(err))
                            } else {
                                None
                            }
                        },
                    )
                    .transpose()?
                    .ok_or(ConsistencyError::WrongNodeType {
                        node_id,
                        requested: NodeType::StateTransition,
                        actual: NodeType::Genesis,
                    })?
            })
    }

    fn seals_closed_with(
        &self,
        node_id: NodeId,
        owned_right_type: impl Into<OwnedRightType>,
        witness: Txid,
    ) -> Result<BTreeSet<OutPoint>, ConsistencyError> {
        let owned_right_type = owned_right_type.into();
        let transition = self.transition_by_id(node_id)?;
        let mut closed_seals = bset!();
        for output in transition.parent_outputs_by_type(owned_right_type) {
            let parent = self.transition_by_id(output.node_id)?;
            let outpoint = parent
                .owned_rights_by_type(owned_right_type)
                .ok_or(ConsistencyError::NoSealsClosed(owned_right_type, node_id))?
                .revealed_seal_at(output.output_no)
                .map_err(|_| ConsistencyError::OutputNotPresent(output))?
                .ok_or(ConsistencyError::ConfidentialSeal(output))?
                .outpoint_or(witness)
                .into();
            closed_seals.insert(outpoint);
        }
        Ok(closed_seals)
    }
}

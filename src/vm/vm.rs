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

//! API for interfacing different virtual machines
//!
//! Concrete virtual machine implementations must be wrapped into this API

use std::collections::{BTreeMap, BTreeSet};

use bitcoin::OutPoint;

use crate::script::{Action, EntryPoint};
use crate::{
    schema, validation, AssignmentVec, Metadata, NodeId, NodeOutput, OwnedRights, PublicRights,
    Transition,
};

/// Trait for concrete types wrapping virtual machines to be used from inside
/// RGB schema validation routines
pub trait VmApi {
    /// Initializes virtual machine with the provided byte code and ABI table.
    ///
    /// NB: If any of the ABI procedures from [`Procedure`] are not defined than
    /// virtual machine MUST return `Result::Ok(())` (meaning that the function
    /// succeeded)
    fn with(
        byte_code: &[u8],
        abi: &BTreeMap<impl Into<Action> + Copy, EntryPoint>,
    ) -> Result<Self, validation::Failure>
    where
        Self: Sized;

    /// Validates contract node
    fn validate_node(
        &self,
        node_id: NodeId,
        node_subtype: schema::NodeSubtype,
        previous_owned_rights: &OwnedRights,
        current_owned_rights: &OwnedRights,
        previous_public_rights: &PublicRights,
        current_public_rights: &PublicRights,
        current_meta: &Metadata,
    ) -> Result<(), validation::Failure>;

    /// Validates single state assignment
    fn validate_assignment(
        &self,
        node_id: NodeId,
        node_subtype: schema::NodeSubtype,
        owned_rights_type: schema::OwnedRightType,
        previous_state: &AssignmentVec,
        current_state: &AssignmentVec,
        current_meta: &Metadata,
    ) -> Result<(), validation::Failure>;

    /// Constructs blank state transition transferring all owned rights from
    /// `inputs` to a new set of UTXOs in `outpoints`. Fails if the number of
    /// outpoints does not allow to fit all of the state
    fn blank_transition(
        &self,
        node_id: NodeId,
        inputs: &BTreeSet<NodeOutput>,
        outpoints: &BTreeSet<OutPoint>,
    ) -> Result<Transition, validation::Failure>;
}

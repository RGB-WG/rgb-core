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

pub mod embedded;
pub mod alure;

pub use embedded::EmbeddedVm;

use crate::{schema, validation, Metadata, NodeId, OwnedRights, PublicRights};

/// Trait for concrete types wrapping virtual machines to be used from inside
/// RGB schema validation routines
pub trait VmApi {
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
}

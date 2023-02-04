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

// pub mod embedded;
pub mod alure;

// pub use embedded::EmbeddedVm;

use crate::{
    validation, Metadata, NodeId, NodeSubtype, OwnedRights, PublicRights, ValidationScript,
};

/// Trait for concrete types wrapping virtual machines to be used from inside
/// RGB schema validation routines.
pub trait Validate {
    /// Validates state change in a contract node.
    #[allow(clippy::too_many_arguments)]
    fn validate(
        &self,
        node_id: NodeId,
        node_subtype: NodeSubtype,
        previous_owned_rights: &OwnedRights,
        current_owned_rights: &OwnedRights,
        previous_public_rights: &PublicRights,
        current_public_rights: &PublicRights,
        current_meta: &Metadata,
    ) -> Result<(), validation::Failure>;
}

impl Validate for ValidationScript {
    fn validate(
        &self,
        node_id: NodeId,
        node_subtype: NodeSubtype,
        previous_owned_rights: &OwnedRights,
        current_owned_rights: &OwnedRights,
        previous_public_rights: &PublicRights,
        current_public_rights: &PublicRights,
        current_meta: &Metadata,
    ) -> Result<(), validation::Failure> {
        match self {
            ValidationScript::AluVM(script) => alure::Runtime::new(script).validate(
                node_id,
                node_subtype,
                previous_owned_rights,
                current_owned_rights,
                previous_public_rights,
                current_public_rights,
                current_meta,
            ),
        }
    }
}

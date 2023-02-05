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

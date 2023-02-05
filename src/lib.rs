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

#![recursion_limit = "256"]
// Coding conventions
#![deny(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    unused_mut,
    unused_imports,
    dead_code,
    //missing_docs
)]
// TODO: Upgrade tests to use new strict_encoding_test crate
#![cfg_attr(test, allow(deprecated))]

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate strict_encoding;

#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_crate as serde;

pub(crate) mod ext;

// pub mod contract;
pub mod schema;
// pub mod stash;
// pub mod verify;
// pub mod validation;
// pub mod vm;
// #[macro_use]
// mod macros;

pub const LIB_NAME_RGB: &str = "RGB";

pub mod prelude {
    pub use bp::dbc::{Anchor, AnchorId};
    /*pub use contract::{
        data, reveal, seal, value, Assignment, AtomicValue, AttachmentId, AttachmentStrategy,
        Bulletproofs, ConcealSeals, ConcealState, ConfidentialDataError, ConfidentialState,
        ContractId, DeclarativeStrategy, EndpointValueMap, Extension, Genesis, HashStrategy,
        IntoRevealedSeal, MergeReveal, Metadata, NoDataError, Node, NodeId, NodeOutpoint,
        OwnedRights, ParentOwnedRights, ParentPublicRights, PedersenStrategy, PublicRights,
        RevealSeals, RevealedState, SealEndpoint, SealValueMap, State, StateRetrievalError,
        StateType, Transition, TypedAssignments,
    };*/
    pub use schema::{
        ExtensionSchema, ExtensionType, NodeSubtype, NodeType, PublicRightType,
        PublicRightsStructure, Schema, SchemaId, ValidationScript, VmType,
    };

    pub use super::schema;
    /*pub use stash::{
        bundle, AnchoredBundle, BundleId, ConcealAnchors, ConcealTransitions, Consignment,
        ConsignmentEndpoint, ConsistencyError, GraphApi, Stash, TransitionBundle,
    };
    pub use validation::{Validator, Validity};
    pub use vm::Validate;

    pub use super::{vm};
    use super::*;*/
}

pub use prelude::*;

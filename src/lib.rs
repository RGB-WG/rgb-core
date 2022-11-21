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
#[macro_use]
extern crate confined_encoding;

#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_with;
#[cfg(feature = "serde")]
extern crate serde_crate as serde;

pub use secp256k1zkp;

pub mod contract;
pub mod schema;
pub mod stash;
pub mod validation;
pub mod vm;
#[macro_use]
mod macros;

pub mod prelude {
    pub use bp::dbc::{Anchor, AnchorId};
    pub use contract::{
        data, reveal, seal, value, Assignment, AtomicValue, AttachmentId, AttachmentStrategy,
        ConcealSeals, ConcealState, ConfidentialDataError, ConfidentialState, ContractId,
        DeclarativeStrategy, EndpointValueMap, Extension, Genesis, HashStrategy,
        HomomorphicBulletproofGrin, IntoRevealedSeal, MergeReveal, Metadata, NoDataError, Node,
        NodeId, NodeOutpoint, OwnedRights, ParentOwnedRights, ParentPublicRights, PedersenStrategy,
        PublicRights, RevealSeals, RevealedState, SealEndpoint, SealValueMap, State,
        StateRetrievalError, StateType, Transition, TypedAssignments,
    };
    pub use schema::{
        script, ExtensionSchema, ExtensionType, NodeSubtype, NodeType, PublicRightType,
        PublicRightsStructure, Schema, SchemaId, ValidationScript, VmType,
    };
    pub use stash::{
        bundle, AnchoredBundle, BundleId, ConcealAnchors, ConcealTransitions, Consignment,
        ConsignmentEndpoint, ConsistencyError, GraphApi, Stash, TransitionBundle,
    };
    pub use validation::{Validator, Validity};
    pub use vm::Validate;

    use super::*;
    pub use super::{schema, vm};
}

pub use prelude::*;

// LNP/BP Core Library implementing LNPBP specifications & standards
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

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate amplify_derive;
#[macro_use]
extern crate lnpbp;
#[macro_use]
extern crate lnpbp_derive;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate num_derive;
#[macro_use]
extern crate bitcoin_hashes;

#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_with;
#[cfg(feature = "serde")]
extern crate serde_crate as serde;

pub use lnpbp::secp256k1zkp;

pub mod bech32;
pub mod contract;
pub mod schema;
pub mod stash;
pub mod validation;
pub mod vm;

pub mod prelude {
    use super::*;
    pub use super::{bech32, schema, vm};

    pub use super::bech32::{Bech32, FromBech32, ToBech32};
    pub use contract::{
        data, seal, value, Assignments, AtomicValue, AutoConceal,
        ConfidentialState, ContractId, DeclarativeStrategy, Extension, Genesis,
        HashStrategy, Metadata, NoDataError, Node, NodeId, OwnedRights,
        OwnedState, ParentOwnedRights, ParentPublicRights, PedersenStrategy,
        RevealedState, SealDefinition, StateTypes, Transition,
    };
    pub use schema::{
        script, AssignmentAbi, AssignmentAction, ExtensionAbi, ExtensionAction,
        ExtensionSchema, ExtensionType, GenesisAbi, GenesisAction,
        PublicRightType, PublicRightsStructure, Schema, SchemaId,
        SimplicityScript, TransitionAbi, TransitionAction,
    };
    pub use stash::{
        Anchor, AnchorId, Consignment, ConsignmentEndpoints, Disclosure,
        ExtensionData, Stash, TransitionData, PSBT_OUT_PUBKEY, PSBT_OUT_TWEAK,
    };
    pub use validation::{Validator, Validity};
    pub use vm::VirtualMachine;
}

pub use prelude::*;

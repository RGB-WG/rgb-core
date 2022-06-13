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
extern crate lazy_static;
#[macro_use]
extern crate bitcoin_hashes;

#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_with;
#[cfg(feature = "serde")]
extern crate serde_crate as serde;

pub use secp256k1zkp;

// TODO: Move to strict_encoding_test
#[cfg(test)]
#[macro_export]
macro_rules! test_encode {
    ( $(( $data:ident, $ty:ty )),+ ) => {
        $( let _: $ty = ::strict_encoding::test_helpers::test_vec_decoding_roundtrip($data).unwrap(); )+
    }
}

/// Macro to run test suite with garbage vector against all non-consensus
/// enum values
#[cfg(test)]
#[macro_export]
macro_rules! test_garbage_exhaustive {
    ($range:expr; $( ($x:ident, $ty:ty, $err:ident) ),+ ) => (
        {$(
            let mut cp = $x.clone();
            for byte in $range {
                cp[0] = byte as u8;
                assert_eq!(
                    <$ty>::strict_decode(&cp[..]).unwrap_err(),
                    ::strict_encoding::Error::EnumValueNotKnown($err, byte)
                );
            }
        )+}
    );
}

pub mod bech32;
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
        data, reveal, seal, value, AllocatedValue, Allocation, AllocationMap, AllocationValueMap,
        AllocationValueVec, Assignment, AssignmentVec, AtomicValue, ConcealSeals, ConcealState,
        ConfidentialDataError, ConfidentialState, ContractId, DeclarativeStrategy,
        EndpointValueMap, Extension, Genesis, HashStrategy, HomomorphicBulletproofGrin,
        IntoRevealedSeal, IntoSealValueMap, MergeReveal, Metadata, NoDataError, Node, NodeId,
        NodeOutpoint, OutpointValue, OutpointValueMap, OutpointValueVec, OwnedRights,
        ParentOwnedRights, ParentPublicRights, PedersenStrategy, PublicRights, RevealedState,
        SealEndpoint, SealValueMap, State, StateRetrievalError, StateType, Transition, UtxobValue,
    };
    pub use schema::{
        script, ExtensionSchema, ExtensionType, NodeSubtype, NodeType, PublicRightType,
        PublicRightsStructure, Schema, SchemaId, ValidationScript, VmType,
    };
    pub use stash::{
        AnchoredBundles, BundleId, ChainIter, ConcealAnchors, ConcealTransitions, Consignment,
        ConsignmentEndpoints, ConsistencyError, Disclosure, ExtensionList, GraphApi, Stash,
        TransitionBundle, PSBT_OUT_PUBKEY, PSBT_OUT_TWEAK, PSBT_PREFIX,
    };
    pub use validation::{Validator, Validity};
    pub use vm::Validate;

    pub use super::bech32::{Bech32, FromBech32, ToBech32};
    use super::*;
    pub use super::{bech32, schema, vm};
}

pub use prelude::*;

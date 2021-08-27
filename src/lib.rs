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
extern crate strict_encoding;
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

pub use secp256k1zkp;

macro_rules! impl_enum_strict_encoding {
    ($type:ty) => {
        impl ::strict_encoding::StrictEncode for $type {
            #[inline]
            fn strict_encode<E: ::std::io::Write>(
                &self,
                e: E,
            ) -> Result<usize, ::strict_encoding::Error> {
                use ::num_traits::ToPrimitive;

                match self.to_u8() {
                    Some(result) => result.strict_encode(e),
                    None => Err(::strict_encoding::Error::EnumValueOverflow(
                        stringify!($type),
                    )),
                }
            }
        }

        impl ::strict_encoding::StrictDecode for $type {
            #[inline]
            fn strict_decode<D: ::std::io::Read>(
                d: D,
            ) -> Result<Self, ::strict_encoding::Error> {
                use ::num_traits::FromPrimitive;

                let value = u8::strict_decode(d)?;
                match Self::from_u8(value) {
                    Some(result) => Ok(result),
                    None => Err(::strict_encoding::Error::EnumValueNotKnown(
                        stringify!($type),
                        value.into(),
                    )),
                }
            }
        }
    };
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
    use super::*;
    pub use super::{bech32, schema, vm};

    pub use super::bech32::{Bech32, FromBech32, ToBech32};
    pub use contract::{
        data, reveal, seal, value, AllocatedValue, Allocation, AllocationMap,
        AllocationValueMap, AllocationValueVec, Assignment, AssignmentVec,
        AtomicValue, ConcealSeals, ConcealState, ConfidentialDataError,
        ConfidentialState, ContractId, DeclarativeStrategy, EndpointValueMap,
        Extension, Genesis, HashStrategy, IntoSealValueMap, Metadata,
        NoDataError, Node, NodeId, NodeOutput, OutpointValue, OutpointValueMap,
        OutpointValueVec, OwnedRights, ParentOwnedRights, ParentPublicRights,
        PedersenStrategy, PublicRights, RevealedByMerge, RevealedState, Seal,
        SealDefinition, SealEndpoint, SealPoint, SealValueMap, State,
        StateRetrievalError, StateType, ToSealDefinition, Transition,
        UtxobValue,
    };
    pub use schema::{
        script, AssignmentAbi, AssignmentAction, ExecutableCode, ExtensionAbi,
        ExtensionAction, ExtensionSchema, ExtensionType, GenesisAbi,
        GenesisAction, NodeSubtype, NodeType, PublicRightType,
        PublicRightsStructure, Schema, SchemaId, TransitionAbi,
        TransitionAction, VmType,
    };
    pub use stash::{
        Anchor, AnchorId, ConcealAnchors, Consignment, ConsignmentEndpoints,
        ConsistencyError, Disclosure, ExtensionData, GraphApi, Stash,
        TransitionData, PSBT_OUT_PUBKEY, PSBT_OUT_TWEAK, PSBT_PREFIX,
    };
    pub use validation::{Validator, Validity};
    pub use vm::VmApi;
}

pub use prelude::*;

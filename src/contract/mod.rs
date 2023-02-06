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

pub mod seal {
    pub use bp::seals::txout::blind::{ConcealedSeal as Confidential, RevealedSeal as Revealed};
}
pub mod value;
pub mod attachment;
pub mod data;
mod global_state;
pub mod owned_state;
mod assignments;
mod operations;
mod bundle;

pub use assignments::TypedAssignments;
pub use attachment::AttachId;
pub use bundle::{BundleId, TransitionBundle};
pub use global_state::{FieldValues, Metadata};
pub use operations::{
    ContractId, Extension, Genesis, Node, NodeId, NodeOutpoint, OutpointParseError, OwnedRights,
    ParentOwnedRights, ParentPublicRights, PublicRights, Transition,
};
pub use owned_state::{Assignment, State, StateType};
pub use value::{
    BlindingFactor, FieldOrderOverflow, NoiseDumb, PedersenCommitment, RangeProof, RangeProofError,
    ValueAtom,
};

/// Marker trait for types of state which are just a commitment to the actual
/// state data.
pub trait ConfidentialState:
    core::fmt::Debug
    + strict_encoding::StrictDumb
    + strict_encoding::StrictEncode
    + strict_encoding::StrictDecode
    + amplify::AsAny
    + Clone
{
}

/// Marker trait for types of state holding explicit state data.
pub trait RevealedState:
    core::fmt::Debug
    + strict_encoding::StrictDumb
    + strict_encoding::StrictEncode
    + strict_encoding::StrictDecode
    + commit_verify::Conceal
    + amplify::AsAny
    + Clone
{
}

/// Errors retrieving state data.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum StateRetrievalError {
    /// the requested state has a mismatched data type.
    StateTypeMismatch,

    /// some of the requested data are confidential, when they must be present
    /// in revealed form.
    #[from(ConfidentialDataError)]
    ConfidentialData,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
/// the requested data are not present.
pub struct UnknownDataError;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
/// some of the requested data are confidential, when they must be present in
/// revealed form.
pub struct ConfidentialDataError;

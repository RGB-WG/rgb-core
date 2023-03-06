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
pub mod fungible;
pub mod attachment;
pub mod data;
pub mod assignment;
mod global;
mod operations;
mod bundle;

use std::hash::Hash;

pub use assignment::{Assign, StateType, TypedAssigns};
pub use attachment::AttachId;
pub use bundle::{BundleId, TransitionBundle};
pub use fungible::{
    BlindingFactor, FieldOrderOverflow, FungibleState, NoiseDumb, PedersenCommitment, RangeProof,
    RangeProofError,
};
pub use global::{GlobalState, GlobalValues};
pub use operations::{
    ContractId, Extension, Genesis, OpId, Operation, OwnedState, PrevOuts, Redeemed, Transition,
    Valencies,
};

/// Marker trait for types of state which are just a commitment to the actual
/// state data.
pub trait ConfidentialState:
    core::fmt::Debug
    + strict_encoding::StrictDumb
    + strict_encoding::StrictEncode
    + strict_encoding::StrictDecode
    + amplify::AsAny
    + Eq
    + Hash
    + Clone
{
}

/// Marker trait for types of state holding explicit state data.
pub trait RevealedState:
    core::fmt::Debug
    + strict_encoding::StrictDumb
    + strict_encoding::StrictEncode
    + strict_encoding::StrictDecode
    + commit_verify::Conceal<Concealed = Self::Confidential>
    + amplify::AsAny
    + Eq
    + Ord
    + Clone
{
    type Confidential: ConfidentialState;
}

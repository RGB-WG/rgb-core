// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2019-2024 Dr Maxim Orlovsky. All rights reserved.
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

mod meta;
mod global;
mod data;
mod fungible;
mod state;
pub mod seal;
pub mod assignments;
mod operations;
mod bundle;
mod layer1;
mod commit;

pub use assignments::{
    Assign, AssignData, AssignFungible, AssignRights, Assignments, AssignmentsRef, TypedAssigns,
};
pub use bundle::{BundleId, KnownTransition, TransitionBundle, UnrelatedTransition, Vin};
pub use commit::{
    AssignmentCommitment, AssignmentIndex, BaseCommitment, BundleDisclosure, ContractId,
    DiscloseHash, GlobalCommitment, OpCommitment, OpDisclose, OpId, TypeCommitment,
};
pub use data::{RevealedData, VoidState};
pub use fungible::{FungibleState, RevealedValue};
pub use global::{GlobalState, GlobalValues};
pub use layer1::{ChainNet, Layer1};
pub use meta::{MetaValue, Metadata, MetadataError};
pub use operations::{
    Genesis, Identity, Inputs, Operation, Opout, OpoutParseError, SealClosingStrategy, Signature,
    Transition,
};
pub use seal::{ExposedSeal, GenesisSeal, GraphSeal, OutputSeal, SecretSeal, TxoSeal};
pub use state::{ExposedState, RevealedState, StateType};

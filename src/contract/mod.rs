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

mod global;
mod data;
mod fungible;
mod attachment;
mod state;
mod anchor;
pub mod seal;
pub mod assignments;
mod operations;
mod bundle;
#[allow(clippy::module_inception)]
mod contract;
mod xchain;
mod id;

pub use anchor::{AnchorSet, AnchoredBundle, Layer1, WitnessAnchor, XAnchor};
pub use assignments::{
    Assign, AssignAttach, AssignData, AssignFungible, AssignRights, Assignments, AssignmentsRef,
    TypedAssigns,
};
pub use attachment::{AttachId, ConcealedAttach, RevealedAttach};
pub use bundle::{BundleId, InputMap, TransitionBundle, Vin};
pub use contract::{
    AssignmentWitness, ContractHistory, ContractState, GlobalOrd, KnownState, Opout,
    OpoutParseError, OutputAssignment,
};
pub use data::{ConcealedData, DataState, RevealedData, VoidState};
pub use fungible::{
    AssetTag, BlindingFactor, BlindingParseError, ConcealedValue, FungibleState,
    InvalidFieldElement, NoiseDumb, PedersenCommitment, RangeProof, RangeProofError, RevealedValue,
};
pub use global::{GlobalState, GlobalValues};
pub use id::{
    AssignmentCommitment, BaseCommitment, ContractId, DiscloseHash, GlobalCommitment, OpCommitment,
    OpId, TypeCommitment,
};
pub use operations::{
    Extension, Genesis, Input, Inputs, Metadata, OpRef, Operation, Redeemed, Transition, Valencies,
};
pub use seal::{
    ExposedSeal, GenesisSeal, GraphSeal, OutputSeal, SecretSeal, TxoSeal, WitnessId, WitnessOrd,
    WitnessPos, XGenesisSeal, XGraphSeal, XOutputSeal, XPubWitness, XWitness,
};
pub use state::{ConcealedState, ConfidentialState, ExposedState, RevealedState, StateType};
pub use xchain::{
    AltLayer1, AltLayer1Set, XChain, XChainParseError, XOutpoint, XCHAIN_BITCOIN_PREFIX,
    XCHAIN_LIQUID_PREFIX,
};

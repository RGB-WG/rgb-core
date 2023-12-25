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

use std::io::Write;

use amplify::confinement::TinyOrdSet;
pub use anchor::{AnchorSet, AnchoredBundle, Layer1, WitnessAnchor, XAnchor};
pub use assignments::{
    Assign, AssignAttach, AssignData, AssignFungible, AssignRights, Assignments, AssignmentsRef,
    TypedAssigns,
};
pub use attachment::{AttachId, ConcealedAttach, RevealedAttach};
pub use bundle::{BundleId, TransitionBundle, Vin};
use commit_verify::CommitEncode;
pub use contract::{
    AttachOutput, ContractHistory, ContractState, DataOutput, FungibleOutput, GlobalOrd, Opout,
    OpoutParseError, OutputAssignment, RightsOutput,
};
pub use data::{ConcealedData, RevealedData, VoidState};
pub use fungible::{
    AssetTag, BlindingFactor, BlindingParseError, ConcealedValue, FungibleState,
    InvalidFieldElement, NoiseDumb, PedersenCommitment, RangeProof, RangeProofError, RevealedValue,
};
pub use global::{GlobalState, GlobalValues};
pub use operations::{
    ContractId, Extension, Genesis, Input, Inputs, OpId, OpRef, Operation, Redeemed, Transition,
    Valencies,
};
pub use seal::{
    ExposedSeal, GenesisSeal, GraphSeal, OutputSeal, SecretSeal, TxoSeal, WitnessId, WitnessOrd,
    WitnessPos, XSeal, XchainParseError,
};
pub use state::{ConfidentialState, ExposedState, StateCommitment, StateData, StateType};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(lowercase)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = super::LIB_NAME_RGB, tags = repr, into_u8, try_from_u8)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[repr(u8)]
pub enum AltLayer1 {
    #[strict_type(dumb)]
    Liquid = 1,
    // Abraxas = 0x10,
    // Prime = 0x11,
}

impl AltLayer1 {
    pub fn layer1(&self) -> Layer1 {
        match self {
            AltLayer1::Liquid => Layer1::Liquid,
        }
    }
}

#[derive(Wrapper, WrapperMut, Clone, PartialEq, Eq, Hash, Debug, Default, From)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = super::LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct AltLayer1Set(TinyOrdSet<AltLayer1>);

impl CommitEncode for AltLayer1Set {
    fn commit_encode(&self, e: &mut impl Write) {
        for c in self.iter() {
            e.write_all(&[*c as u8]).ok();
        }
    }
}

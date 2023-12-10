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

use amplify::confinement::{TinyOrdMap, TinyOrdSet};
use amplify::{Bytes32, Wrapper};
use commit_verify::{mpc, CommitStrategy, CommitmentId, Conceal};

use super::{OpId, Transition};
use crate::{ContractId, LIB_NAME_RGB};

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error)]
#[display(doc_comments)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum BundleError {
    /// state transitions created under different contracts.
    DivergentContracts,
    /// no state transitions.
    EmptyBundle,
    /// state transitions reference to the same input multiple times ({0}).
    RepeatedInputs(usize),
}

/// Unique state transition bundle identifier equivalent to the bundle
/// commitment hash
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, BorrowSlice, Display, Hex, Index, RangeOps)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct BundleId(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl From<BundleId> for mpc::Message {
    fn from(id: BundleId) -> Self { mpc::Message::from_inner(id.into_inner()) }
}

impl From<mpc::Message> for BundleId {
    fn from(id: mpc::Message) -> Self { BundleId(id.into_inner()) }
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct BundleItem {
    pub inputs: TinyOrdSet<u16>,
    pub transition: Option<Transition>,
}

impl Conceal for BundleItem {
    type Concealed = Self;

    fn conceal(&self) -> Self::Concealed {
        BundleItem {
            inputs: self.inputs.clone(),
            transition: None,
        }
    }
}

#[derive(Wrapper, WrapperMut, Clone, PartialEq, Eq, Debug, From)]
#[wrapper(Deref)]
#[wrapper_mut(DerefMut)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct TransitionBundle(TinyOrdMap<OpId, BundleItem>);

impl Conceal for TransitionBundle {
    type Concealed = Self;

    fn conceal(&self) -> Self::Concealed {
        let concealed = self.iter().map(|(id, item)| (*id, item.conceal()));
        TransitionBundle(TinyOrdMap::try_from_iter(concealed).expect("same size"))
    }
}

impl CommitStrategy for TransitionBundle {
    // TODO: Use merklization strategy
    type Strategy = commit_verify::strategies::ConcealStrict;
}

impl CommitmentId for TransitionBundle {
    const TAG: [u8; 32] = *b"urn:lnpbp:rgb:bundle:v1#20230306";
    type Id = BundleId;
}

impl TransitionBundle {
    pub fn bundle_id(&self) -> BundleId { self.commitment_id() }
}

impl TransitionBundle {
    pub fn validate(&self) -> Result<ContractId, BundleError> {
        let mut contract_id = None;
        let mut used_inputs = bset! {};
        for item in self.values() {
            if !contract_id
                .and_then(|id| {
                    item.transition
                        .as_ref()
                        .map(|t| (id, t))
                        .map(|(id, t)| id == t.contract_id)
                })
                .unwrap_or_default()
            {
                return Err(BundleError::DivergentContracts);
            }
            contract_id = item.transition.as_ref().map(|t| t.contract_id);
            let repeated_inputs = used_inputs.intersection(&item.inputs).count();
            if repeated_inputs > 0 {
                return Err(BundleError::RepeatedInputs(repeated_inputs));
            }
            used_inputs.extend(&item.inputs);
        }
        contract_id.ok_or(BundleError::EmptyBundle)
    }
}

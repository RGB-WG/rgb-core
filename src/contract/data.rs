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

use core::fmt::{self, Debug, Display, Formatter};

use amplify::confinement::SmallVec;
use amplify::hex::ToHex;
use amplify::{Bytes32, Wrapper};
use commit_verify::{CommitVerify, Conceal, StrictEncodedProtocol};
use strict_encoding::{StrictSerialize, StrictType};

use super::{ConfidentialState, ExposedState};
use crate::{StateCommitment, StateData, StateType, LIB_NAME_RGB};

/// Struct using for storing Void (i.e. absent) state
#[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, Display, Default)]
#[display("void")]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct VoidState(());

impl ConfidentialState for VoidState {
    fn state_type(&self) -> StateType { StateType::Void }
    fn state_commitment(&self) -> StateCommitment { StateCommitment::Void }
}

impl ExposedState for VoidState {
    type Confidential = VoidState;
    fn state_type(&self) -> StateType { StateType::Void }
    fn state_data(&self) -> StateData { StateData::Void }
}

impl Conceal for VoidState {
    type Concealed = VoidState;
    fn conceal(&self) -> Self::Concealed { *self }
}

#[derive(Wrapper, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[derive(CommitEncode)]
#[commit_encode(conceal)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct RevealedData(SmallVec<u8>);

impl ExposedState for RevealedData {
    type Confidential = ConcealedData;
    fn state_type(&self) -> StateType { StateType::Structured }
    fn state_data(&self) -> StateData { StateData::Structured(self.clone()) }
}

impl Conceal for RevealedData {
    type Concealed = ConcealedData;
    fn conceal(&self) -> Self::Concealed { ConcealedData::commit(self) }
}

impl StrictSerialize for RevealedData {}

impl Debug for RevealedData {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let val = match String::from_utf8(self.0.to_inner()) {
            Ok(s) => s,
            Err(_) => self.0.to_hex(),
        };

        f.debug_tuple("RevealedData").field(&val).finish()
    }
}

impl Display for RevealedData {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { f.write_str(&self.as_ref().to_hex()) }
}

/// Confidential version of an structured state data.
///
/// See also revealed version [`RevealedData`].
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB, rename = "ConcealedData")]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct ConcealedData(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl ConfidentialState for ConcealedData {
    fn state_type(&self) -> StateType { StateType::Structured }
    fn state_commitment(&self) -> StateCommitment { StateCommitment::Structured(*self) }
}

impl CommitVerify<RevealedData, StrictEncodedProtocol> for ConcealedData {
    fn commit(revealed: &RevealedData) -> Self { Bytes32::commit(revealed).into() }
}

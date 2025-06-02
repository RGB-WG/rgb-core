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

use amplify::confinement::SmallBlob;
use amplify::Wrapper;
use strict_encoding::StrictType;

use super::ExposedState;
use crate::{AnyState, StateType, LIB_NAME_RGB_COMMIT};

/// Struct using for storing Void (i.e. absent) state
#[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, Display, Default)]
#[display("void")]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct VoidState(());

impl ExposedState for VoidState {
    fn state_type(&self) -> StateType { StateType::Void }
    fn state_data(&self) -> AnyState { AnyState::Void }
}

#[derive(Wrapper, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, From, Display, Default)]
#[display(LowerHex)]
#[wrapper(Deref, AsSlice, BorrowSlice, Hex)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
pub struct StructuredData(SmallBlob);

impl StructuredData {
    /// Convenience constructor.
    pub fn new(value: impl Into<SmallBlob>) -> Self { Self(value.into()) }
}

impl ExposedState for StructuredData {
    fn state_type(&self) -> StateType { StateType::Structured }
    fn state_data(&self) -> AnyState { AnyState::Structured(self.clone()) }
}

#[cfg(feature = "serde")]
mod _serde {
    use amplify::hex::FromHex;
    use serde_crate::de::Error;
    use serde_crate::{Deserialize, Deserializer, Serialize, Serializer};

    use super::*;

    impl Serialize for StructuredData {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer {
            serializer.serialize_str(&self.to_string())
        }
    }

    impl<'de> Deserialize<'de> for StructuredData {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de> {
            let s = String::deserialize(deserializer)?;
            Self::from_hex(&s).map_err(D::Error::custom)
        }
    }
}

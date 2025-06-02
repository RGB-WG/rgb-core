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

use amplify::num::u24;
use strict_types::SemId;

use crate::{StateType, LIB_NAME_RGB_COMMIT};

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT, tags = order)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum OwnedStateSchema {
    #[strict_type(dumb)]
    Declarative,
    Fungible,
    Structured(SemId),
}

impl OwnedStateSchema {
    pub fn state_type(&self) -> StateType {
        match self {
            OwnedStateSchema::Declarative => StateType::Void,
            OwnedStateSchema::Fungible => StateType::Fungible,
            OwnedStateSchema::Structured(_) => StateType::Structured,
        }
    }

    pub fn sem_id(&self) -> Option<SemId> {
        if let Self::Structured(id) = self {
            Some(*id)
        } else {
            None
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct GlobalStateSchema {
    pub sem_id: SemId,
    pub max_items: u24,
}

impl GlobalStateSchema {
    pub fn once(sem_id: SemId) -> Self {
        GlobalStateSchema {
            sem_id,
            max_items: u24::ONE,
        }
    }

    pub fn many(sem_id: SemId) -> Self {
        GlobalStateSchema {
            sem_id,
            max_items: u24::MAX,
        }
    }
}

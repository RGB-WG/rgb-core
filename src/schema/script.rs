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

#![allow(clippy::unnecessary_cast)]

//! Components related to the scripting system used by schema or applied at the
//! specific contract operation level

use std::ops::Deref;

use strict_types::TypeSysId;

use crate::vm::AluScript;
use crate::LIB_NAME_RGB;

/// Virtual machine types.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[display(Debug)]
pub enum VmType {
    /// AluVM: pure functional register-based virtual machine designed for RGB
    /// and multiparty computing.
    AluVM,
}

/// Virtual machine and machine-specific script data.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB, tags = custom)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum Script {
    /// AluVM: pure functional register-based virtual machine designed for RGB
    /// and multiparty computing.
    ///
    /// The inner data contains actual executable code in form of complete set
    /// of AliVM libraries, which must be holistic and not dependent on any
    /// external libraries (i.e. must contain all libraries embedded).
    ///
    /// Its routines can be accessed only through well-typed ABI entrance
    /// pointers, defined as a part of the schema.
    #[strict_type(tag = 0x01)]
    AluVM(AluScript),
}

impl Default for Script {
    fn default() -> Self { Script::AluVM(none!()) }
}

impl Script {
    pub fn vm_type(&self) -> VmType {
        match self {
            Script::AluVM(_) => VmType::AluVM,
        }
    }

    pub fn as_alu_script(&self) -> &AluScript {
        let Script::AluVM(alu) = self;
        alu
    }
}

/// Types used by a schema and virtual machine
#[derive(Clone, Eq, PartialEq, Debug, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB, tags = custom, dumb = Self::Strict(strict_dumb!()))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase", tag = "type")
)]
pub enum Types {
    #[from]
    #[strict_type(tag = 0x01)]
    Strict(TypeSysId),
}

impl Deref for Types {
    type Target = TypeSysId;

    fn deref(&self) -> &Self::Target {
        match self {
            Types::Strict(sys) => sys,
        }
    }
}

impl Types {
    pub fn as_strict(&self) -> &TypeSysId {
        match self {
            Types::Strict(id) => id,
        }
    }
}

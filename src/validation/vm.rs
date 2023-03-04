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

use crate::validation::OpInfo;
use crate::vm::AluRuntime;
use crate::{validation, Script};

/// Trait for concrete types wrapping virtual machines to be used from inside
/// RGB schema validation routines.
pub trait VirtualMachine {
    /// Validates state change in a contract node.
    fn validate(&self, info: OpInfo) -> Result<(), validation::Failure>;
}

impl VirtualMachine for Script {
    fn validate(&self, info: OpInfo) -> Result<(), validation::Failure> {
        match self {
            Script::AluVM(script) => AluRuntime::new(script).validate(info),
        }
    }
}

impl<'script> VirtualMachine for AluRuntime<'script> {
    fn validate(&self, info: OpInfo) -> Result<(), validation::Failure> {
        let id = info.id;
        self.run_validations(&info)
            .map_err(|msg| validation::Failure::ScriptFailure(id, msg))
    }
}

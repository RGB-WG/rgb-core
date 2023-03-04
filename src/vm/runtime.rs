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

use std::collections::{BTreeMap, BTreeSet};

use aluvm::data::{ByteStr, Number};
use aluvm::reg::{Reg32, RegAFR, RegS};
use aluvm::Vm;

use crate::validation::OpInfo;
use crate::vm::{AluScript, EntryPoint};
use crate::OpFullType;

pub struct AluRuntime<'script> {
    script: &'script AluScript,
}

impl<'script> AluRuntime<'script> {
    pub fn new(script: &'script AluScript) -> Self { AluRuntime { script } }

    pub fn run_validations(&self, info: &OpInfo) -> Result<(), String> {
        let regs = RegSetup::default();

        match info.ty {
            OpFullType::Genesis => {
                // TODO: set up registries
                self.run(EntryPoint::ValidateGenesis, &regs, info)?;
            }
            OpFullType::StateTransition(ty) => {
                // TODO: set up registries
                self.run(EntryPoint::ValidateTransition(ty), &regs, info)?;
            }
            OpFullType::StateExtension(ty) => {
                // TODO: set up registries
                self.run(EntryPoint::ValidateExtension(ty), &regs, info)?;
            }
        }

        for ty in info.global.keys() {
            // TODO: set up registries
            self.run(EntryPoint::ValidateGlobalState(*ty), &regs, info)?;
        }

        let used_state = info
            .owned_state
            .keys()
            .chain(info.prev_state.keys())
            .copied()
            .collect::<BTreeSet<_>>();
        for ty in used_state {
            // TODO: set up registries
            self.run(EntryPoint::ValidateGlobalState(ty), &regs, info)?;
        }

        Ok(())
    }

    fn run(&self, entry: EntryPoint, regs: &RegSetup, info: &OpInfo) -> Result<(), String> {
        let mut vm = Vm::new();

        for ((reg, idx), val) in &regs.nums {
            vm.registers.set(*reg, *idx, *val);
        }
        for (reg, val) in &regs.data {
            vm.registers.set_s(
                *reg,
                Some(
                    ByteStr::try_from(val.as_slice()).expect("state must be less than 2^16 bytes"),
                ),
            );
        }

        match self.script.entry_points.get(&entry) {
            Some(site) => match vm.call(self.script, *site, info) {
                true => Ok(()),
                false => Err(vm
                    .registers
                    .get_s(0)
                    .and_then(|bs| String::from_utf8(bs.to_vec()).ok())
                    .unwrap_or_else(|| s!("unspecified error"))),
            },
            None => Ok(()),
        }
    }
}

#[derive(Debug, Default)]
struct RegSetup {
    pub nums: BTreeMap<(RegAFR, Reg32), Number>,
    pub data: BTreeMap<RegS, Vec<u8>>,
}

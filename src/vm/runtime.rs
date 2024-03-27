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

use std::collections::{BTreeMap, BTreeSet};

use aluvm::data::{ByteStr, Number};
use aluvm::isa::Instr;
use aluvm::reg::{Reg32, RegA, RegAFR, RegS};
use aluvm::Vm;
use amplify::Wrapper;

use crate::validation::OpInfo;
use crate::vm::{AluScript, EntryPoint, RgbIsa};
use crate::OpFullType;

pub struct AluRuntime<'script> {
    script: &'script AluScript,
}

impl<'script> AluRuntime<'script> {
    pub fn new(script: &'script AluScript) -> Self { AluRuntime { script } }

    pub fn run_validations(&self, info: &OpInfo) -> Result<(), Option<u8>> {
        let mut regs = RegSetup::default();

        match info.ty {
            OpFullType::Genesis => {
                self.run(EntryPoint::ValidateGenesis, &regs, info)?;
            }
            OpFullType::StateTransition(ty) => {
                regs.nums
                    .insert((RegAFR::A(RegA::A16), Reg32::Reg1), ty.into_inner().into());
                self.run(EntryPoint::ValidateTransition(ty), &regs, info)?;
            }
            OpFullType::StateExtension(ty) => {
                regs.nums
                    .insert((RegAFR::A(RegA::A16), Reg32::Reg1), ty.into_inner().into());
                self.run(EntryPoint::ValidateExtension(ty), &regs, info)?;
            }
        }

        for ty in info.global.keys() {
            regs.nums
                .insert((RegAFR::A(RegA::A16), Reg32::Reg1), ty.into_inner().into());
            self.run(EntryPoint::ValidateGlobalState(*ty), &regs, info)?;
        }

        let used_state = info
            .owned_state
            .types()
            .iter()
            .chain(info.prev_state.keys())
            .copied()
            .collect::<BTreeSet<_>>();
        for ty in used_state {
            regs.nums
                .insert((RegAFR::A(RegA::A16), Reg32::Reg1), ty.into_inner().into());
            self.run(EntryPoint::ValidateOwnedState(ty), &regs, info)?;
        }

        Ok(())
    }

    fn run(&self, entry: EntryPoint, regs: &RegSetup, info: &OpInfo) -> Result<(), Option<u8>> {
        let mut vm = Vm::<Instr<RgbIsa>>::new();

        for ((reg, idx), val) in &regs.nums {
            vm.registers.set_n(*reg, *idx, *val);
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
                false => {
                    let val: Option<Number> = vm.registers.get_n(RegA::A8, Reg32::Reg31).into();
                    Err(val.map(|n| n[0]))
                }
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

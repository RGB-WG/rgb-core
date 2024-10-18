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

use std::borrow::Borrow;
use std::collections::BTreeSet;

use aluvm::isa;
use aluvm::isa::{ExecStep, Instr, InstructionSet};
use aluvm::library::{IsaSeg, Lib, LibSite};
use aluvm::reg::{CoreRegs, Reg};

use super::{
    ContractOp, ContractStateAccess, GlobalContractState, GlobalStateIter, ImpossibleIter,
    UnknownGlobalStateType, VmContext,
};
use crate::{AssignmentType, GlobalStateType, State, XOutpoint};

pub fn assemble(asm: impl AsRef<[Instr<RgbIsa<CompileOnly>>]>) -> Lib {
    Lib::assemble(asm.as_ref()).expect("invalid script")
}

/// Operations constituting `RgbIsa` architecture extension.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[display(inner)]
#[non_exhaustive]
pub enum RgbIsa<S: ContractStateAccess> {
    Contract(ContractOp<S>),

    /// All other future unsupported operations, which must set `st0` to
    /// `false`.
    Fail(u8),
}

#[derive(Debug)]
pub enum CompileOnly {}
impl ContractStateAccess for CompileOnly {
    fn global(
        &self,
        _: GlobalStateType,
    ) -> Result<GlobalContractState<impl GlobalStateIter>, UnknownGlobalStateType> {
        Ok(GlobalContractState::new(ImpossibleIter::default()))
    }

    fn state(
        &self,
        _: XOutpoint,
        _: AssignmentType,
    ) -> impl DoubleEndedIterator<Item = impl Borrow<State>> {
        ImpossibleIter::default()
    }
}

impl<S: ContractStateAccess> InstructionSet for RgbIsa<S> {
    type Context<'ctx> = VmContext<'ctx, S>;

    fn isa_ids() -> IsaSeg { IsaSeg::with("RGB") }

    fn src_regs(&self) -> BTreeSet<Reg> {
        match self {
            RgbIsa::Contract(op) => op.src_regs(),
            RgbIsa::Fail(_) => bset![],
        }
    }

    fn dst_regs(&self) -> BTreeSet<Reg> {
        match self {
            RgbIsa::Contract(op) => op.dst_regs(),
            RgbIsa::Fail(_) => bset![],
        }
    }

    fn complexity(&self) -> u64 {
        match self {
            RgbIsa::Contract(op) => op.complexity(),
            RgbIsa::Fail(_) => u64::MAX,
        }
    }

    fn exec(&self, regs: &mut CoreRegs, site: LibSite, context: &Self::Context<'_>) -> ExecStep {
        match self {
            RgbIsa::Contract(op) => op.exec(regs, site, context),
            RgbIsa::Fail(_) => {
                isa::ControlFlowOp::Fail.exec(regs, site, &());
                ExecStep::Stop
            }
        }
    }
}

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
use std::cell::RefCell;
use std::collections::BTreeSet;

use aluvm::isa::{ExecStep, InstructionSet};
use aluvm::library::{IsaSeg, LibSite};
use aluvm::reg::{CoreRegs, Reg, RegA};
use amplify::num::{u24, u3};
use amplify::Wrapper;

use crate::vm::{ContractOp, ContractStateAccess, VmContext};
use crate::{AssignmentType, GlobalStateType, MetaType};

impl<S: ContractStateAccess> InstructionSet for ContractOp<S> {
    type Context<'ctx> = VmContext<'ctx, S>;

    fn isa_ids() -> IsaSeg { IsaSeg::with("RGB") }

    fn src_regs(&self) -> BTreeSet<Reg> {
        match *self {
            ContractOp::CnI { dst: _, ty }
            | ContractOp::CnO { dst: _, ty }
            | ContractOp::CnG { dst: _, ty }
            | ContractOp::CnC { dst: _, ty }
            | ContractOp::CnReserved {
                instr: _,
                dst: _,
                ty,
                _phantom: _,
            } => {
                bset![a16![ty]]
            }

            ContractOp::CtReserved { instr: _, dst: _ } => bset![],

            ContractOp::LdI { dst: _, ty, pos }
            | ContractOp::LdO { dst: _, ty, pos }
            | ContractOp::LdG { dst: _, ty, pos } => {
                bset![a16![ty], a16![pos]]
            }
            ContractOp::LdC { dst: _, ty, pos } => {
                bset![a16![ty], a32![pos]]
            }
            ContractOp::LdM { dst: _, ty } => {
                bset![a16![ty]]
            }
        }
    }

    fn dst_regs(&self) -> BTreeSet<Reg> {
        match *self {
            ContractOp::CnI { dst, ty: _ }
            | ContractOp::CnO { dst, ty: _ }
            | ContractOp::CnG { dst, ty: _ }
            | ContractOp::CnC { dst, ty: _ }
            | ContractOp::CnReserved {
                instr: _,
                dst,
                ty: _,
                _phantom: _,
            } => {
                bset![a16![dst]]
            }

            ContractOp::CtReserved { instr, dst } if instr == u3::ZERO => bset![a32![dst]],
            ContractOp::CtReserved { instr: _, dst } => bset![a16![dst]],

            ContractOp::LdI { dst, ty: _, pos: _ }
            | ContractOp::LdO { dst, ty: _, pos: _ }
            | ContractOp::LdG { dst, ty: _, pos: _ }
            | ContractOp::LdC { dst, ty: _, pos: _ }
            | ContractOp::LdM { dst, ty: _ } => {
                bset![dst.into()]
            }
        }
    }

    fn complexity(&self) -> u64 {
        match self {
            // This takes running an iterator on in-memory data
            ContractOp::CnI { .. } | ContractOp::CnO { .. } | ContractOp::CnG { .. } => 2_000,
            // This takes at least one lookup into a database
            ContractOp::CnC { .. } => 10_000,
            // This takes copying of up to 64kb of data
            ContractOp::LdI { .. } | ContractOp::LdO { .. } | ContractOp::LdG { .. } => 6_000,
            // This takes possible multiple lookups into database
            ContractOp::LdC { .. } => 100_000,
            // This takes copying of up to 64kb of data
            ContractOp::LdM { .. } => 6_000,
            ContractOp::CnReserved { .. } | ContractOp::CtReserved { .. } => u64::MAX,
        }
    }

    fn exec(&self, regs: &mut CoreRegs, _site: LibSite, context: &Self::Context<'_>) -> ExecStep {
        match *self {
            ContractOp::CnC { dst, ty } => {
                let Some(state_type) = regs.a16(ty).map(GlobalStateType::with) else {
                    return ExecStep::Fail;
                };
                let state = RefCell::borrow(&context.contract_state);
                let cnt = state.global(state_type).map(|mut s| s.size());
                regs.set_a32(dst, cnt.unwrap_or_default().to_u32());
            }
            ContractOp::CnG { dst, ty } => {
                let Some(state_type) = regs.a16(ty).map(GlobalStateType::with) else {
                    return ExecStep::Fail;
                };
                let state = context.op_info.global;
                let cnt = state.get(&state_type).map(|a| a.len_u16());
                regs.set_a16(dst, cnt.unwrap_or_default());
            }
            ContractOp::CnI { dst, ty } => {
                let Some(state_type) = regs.a16(ty).map(AssignmentType::with) else {
                    return ExecStep::Fail;
                };
                let state = context.op_info.prev_state;
                let cnt = state.get(&state_type).map(|a| a.len_u16());
                regs.set_a16(dst, cnt.unwrap_or_default());
            }
            ContractOp::CnO { dst, ty } => {
                let Some(state_type) = regs.a16(ty).map(AssignmentType::with) else {
                    return ExecStep::Fail;
                };
                let state = context.op_info.owned_state;
                let cnt = state.get(state_type).map(|a| a.len_u16());
                regs.set_a16(dst, cnt.unwrap_or_default());
            }

            ContractOp::LdC { dst, ty, pos } => {
                let Some(state_type) = regs.a16(ty).map(GlobalStateType::with) else {
                    return ExecStep::Fail;
                };
                let Some(index) = regs.a32(pos).and_then(|pos| u24::try_from(pos).ok()) else {
                    return ExecStep::Fail;
                };
                let state = RefCell::borrow(&context.contract_state);
                let Some(mut iter) = state.global(state_type).ok() else {
                    return ExecStep::Fail;
                };
                let Some(state) = iter.nth(index) else {
                    return ExecStep::Fail;
                };
                regs.set_s16(dst, state.borrow().as_inner());
            }

            ContractOp::LdG { dst, ty, pos } => {
                let Some(state_type) = regs.a16(ty).map(GlobalStateType::with) else {
                    return ExecStep::Fail;
                };
                let Some(index) = regs.a16(pos) else {
                    return ExecStep::Fail;
                };
                let state = context.op_info.global;
                let Some(state) = state.get(&state_type).and_then(|a| a.get(index as usize)) else {
                    return ExecStep::Fail;
                };
                regs.set_s16(dst, state.as_inner());
            }
            ContractOp::LdI { dst, ty, pos } => {
                let Some(state_type) = regs.a16(ty).map(AssignmentType::with) else {
                    return ExecStep::Fail;
                };
                let Some(index) = regs.a16(pos) else {
                    return ExecStep::Fail;
                };
                let state = context.op_info.prev_state;
                let Some(assign) = state.get(&state_type).and_then(|a| a.get(index as usize))
                else {
                    return ExecStep::Fail;
                };
                regs.set_s16(dst, assign.as_state().unverified.as_inner());
            }
            ContractOp::LdO { dst, ty, pos } => {
                let Some(state_type) = regs.a16(ty).map(AssignmentType::with) else {
                    return ExecStep::Fail;
                };
                let Some(index) = regs.a16(pos) else {
                    return ExecStep::Fail;
                };
                let state = context.op_info.owned_state;
                let Some(assign) = state.get(state_type) else {
                    return ExecStep::Fail;
                };
                let Some(assign) = assign.get(index as usize) else {
                    return ExecStep::Fail;
                };
                regs.set_s16(dst, assign.as_state().unverified.as_inner());
            }

            ContractOp::LdM { dst, ty } => {
                let Some(state_type) = regs.a16(ty).map(MetaType::with) else {
                    return ExecStep::Fail;
                };
                let state = context.op_info.metadata;
                let Some(assign) = state.get(&state_type) else {
                    return ExecStep::Fail;
                };
                regs.set_s16(dst, assign.as_inner());
            }

            // All other future unsupported operations, which must set `st0` to `false`.
            ContractOp::CnReserved { .. } => return ExecStep::Fail,
            ContractOp::CtReserved { .. } => return ExecStep::Fail,
        }
        ExecStep::Next
    }
}

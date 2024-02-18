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

use std::collections::{BTreeSet, HashSet};
use std::ops::RangeInclusive;

use aluvm::isa;
use aluvm::isa::{Bytecode, BytecodeError, ExecStep, InstructionSet};
use aluvm::library::{CodeEofError, LibSite, Read, Write};
use aluvm::reg::{CoreRegs, Reg};

use super::{ContractOp, TimechainOp};
use crate::validation::OpInfo;
use crate::vm::opcodes::{INSTR_RGBISA_FROM, INSTR_RGBISA_TO};

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[display(inner)]
#[non_exhaustive]
pub enum RgbIsa {
    Contract(ContractOp),

    Timechain(TimechainOp),

    /// All other future unsupported operations, which must set `st0` to
    /// `false`.
    Fail(u8),
}

impl InstructionSet for RgbIsa {
    type Context<'ctx> = OpInfo<'ctx, 'ctx>;

    fn isa_ids() -> BTreeSet<&'static str> {
        bset! {"RGB"}
    }

    fn src_regs(&self) -> HashSet<Reg> {
        match self {
            RgbIsa::Contract(op) => op.src_regs(),
            RgbIsa::Timechain(op) => op.src_regs(),
            RgbIsa::Fail(_) => set![],
        }
    }

    fn dst_regs(&self) -> HashSet<Reg> {
        match self {
            RgbIsa::Contract(op) => op.dst_regs(),
            RgbIsa::Timechain(op) => op.dst_regs(),
            RgbIsa::Fail(_) => set![],
        }
    }

    fn exec(&self, regs: &mut CoreRegs, site: LibSite, context: &Self::Context<'_>) -> ExecStep {
        match self {
            RgbIsa::Contract(op) => op.exec(regs, site, context),
            RgbIsa::Timechain(op) => op.exec(regs, site, &()),
            RgbIsa::Fail(_) => {
                isa::ControlFlowOp::Fail.exec(regs, site, &());
                ExecStep::Stop
            }
        }
    }
}

impl Bytecode for RgbIsa {
    fn byte_count(&self) -> u16 {
        match self {
            RgbIsa::Contract(op) => op.byte_count(),
            RgbIsa::Timechain(op) => op.byte_count(),
            RgbIsa::Fail(_) => 0,
        }
    }

    fn instr_range() -> RangeInclusive<u8> { INSTR_RGBISA_FROM..=INSTR_RGBISA_TO }

    fn instr_byte(&self) -> u8 {
        match self {
            RgbIsa::Contract(op) => op.instr_byte(),
            RgbIsa::Timechain(op) => op.instr_byte(),
            RgbIsa::Fail(code) => *code,
        }
    }

    fn encode_args<W>(&self, writer: &mut W) -> Result<(), BytecodeError>
    where W: Write {
        match self {
            RgbIsa::Contract(op) => op.encode_args(writer),
            RgbIsa::Timechain(op) => op.encode_args(writer),
            RgbIsa::Fail(_) => Ok(()),
        }
    }

    fn decode<R>(reader: &mut R) -> Result<Self, CodeEofError>
    where
        Self: Sized,
        R: Read,
    {
        let instr = reader.peek_u8()?;
        Ok(match instr {
            instr if ContractOp::instr_range().contains(&instr) => {
                RgbIsa::Contract(ContractOp::decode(reader)?)
            }
            instr if TimechainOp::instr_range().contains(&instr) => {
                RgbIsa::Timechain(TimechainOp::decode(reader)?)
            }
            x => RgbIsa::Fail(x),
        })
    }
}

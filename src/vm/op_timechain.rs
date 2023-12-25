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

use std::collections::{BTreeSet, HashSet};
use std::ops::RangeInclusive;

use aluvm::isa::{Bytecode, BytecodeError, ExecStep, InstructionSet};
use aluvm::library::{CodeEofError, LibSite, Read, Write};
use aluvm::reg::{CoreRegs, Reg};

use crate::vm::opcodes::{INSTR_TIMECHAIN_FROM, INSTR_TIMECHAIN_TO};

// TODO: Implement bitcoin blockchain introspection

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[display(inner)]
#[non_exhaustive]
pub enum TimechainOp {
    Fail,
}

impl InstructionSet for TimechainOp {
    type Context<'ctx> = ();

    fn isa_ids() -> BTreeSet<&'static str> { none!() }

    fn src_regs(&self) -> HashSet<Reg> { set![] }

    fn dst_regs(&self) -> HashSet<Reg> { set![] }

    fn exec(&self, regs: &mut CoreRegs, _site: LibSite, _context: &Self::Context<'_>) -> ExecStep {
        match self {
            TimechainOp::Fail => {
                regs.set_failure();
                ExecStep::Stop
            }
        }
    }
}

impl Bytecode for TimechainOp {
    fn byte_count(&self) -> u16 { 1 }

    fn instr_range() -> RangeInclusive<u8> { INSTR_TIMECHAIN_FROM..=INSTR_TIMECHAIN_TO }

    fn instr_byte(&self) -> u8 {
        match self {
            TimechainOp::Fail => INSTR_TIMECHAIN_FROM,
        }
    }

    fn encode_args<W>(&self, _writer: &mut W) -> Result<(), BytecodeError>
    where W: Write {
        match self {
            TimechainOp::Fail => Ok(()),
        }
    }

    fn decode<R>(reader: &mut R) -> Result<Self, CodeEofError>
    where
        Self: Sized,
        R: Read,
    {
        match reader.read_u8()? {
            INSTR_TIMECHAIN_FROM..=INSTR_TIMECHAIN_TO => Ok(Self::Fail),
            _ => unreachable!(),
        }
    }
}

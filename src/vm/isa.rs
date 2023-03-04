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

#![allow(clippy::unusual_byte_groupings)]

use std::collections::BTreeSet;
use std::ops::RangeInclusive;

use aluvm::isa::{Bytecode, BytecodeError, ExecStep, InstructionSet};
use aluvm::program::{CodeEofError, LibSite, Read, Write};
use aluvm::reg::CoreRegs;

pub const INSTR_PCVS: u8 = 0b11_001_000;
// NB: For now we prohibit all other ISAE than this one. More ISAEs can be
// allowed in a future with fast-forwards.
pub use aluvm::isa::opcodes::{INSTR_ISAE_FROM, INSTR_ISAE_TO};
// pub const INSTR_ISAE_FROM: u8 = 0b11_000_000;
// pub const INSTR_ISAE_TO: u8 = 0b11_000_000;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
pub enum RgbIsa {
    /// Verify sum of pedersen commitments from inputs and outputs.
    ///
    /// The only argument specifies owned state type for the sum operation. If
    /// this state does not exists, either inputs or outputs does not have
    /// any data for the state, or the state is not
    /// of `FungibleState::Bits64` fails the verification.
    ///
    /// If verification succeeds, doesn't changes `st0` value; otherwise sets it
    /// to `false`.
    #[display("pcvs     {0}")]
    PcVs(u16),

    /*
    /// Verifies corrected sum of pedersen commitments adding a value taken from `RegR` to the list
    /// of inputs (negatives).
    PcCs(u16, RegR),

    /// Loads owned state into a register.
    LdOs(),

    /// Loads global state item into a register.
    LdGs(),

    /// Loads operation info into a string register.
    LdOp(),
     */
    /// All other future unsupported operations, which must set `st0` to
    /// `false`.
    Fail(u8),
}

impl InstructionSet for RgbIsa {
    fn isa_ids() -> BTreeSet<&'static str> {
        bset! {"RGB"}
    }

    // TODO: Implement
    #[allow(unused_variables)]
    fn exec(&self, regs: &mut CoreRegs, site: LibSite) -> ExecStep { ExecStep::Next }
}

impl Bytecode for RgbIsa {
    fn byte_count(&self) -> u16 {
        match self {
            RgbIsa::PcVs(_) => 2,
            RgbIsa::Fail(_) => 0,
        }
    }

    fn instr_range() -> RangeInclusive<u8> { INSTR_ISAE_FROM..=INSTR_ISAE_TO }

    fn instr_byte(&self) -> u8 {
        match self {
            Self::PcVs(_) => INSTR_PCVS,
            RgbIsa::Fail(other) => *other,
        }
    }

    fn encode_args<W>(&self, writer: &mut W) -> Result<(), BytecodeError>
    where W: Write {
        match self {
            RgbIsa::PcVs(state_type) => writer.write_u16(*state_type)?,
            RgbIsa::Fail(_) => {}
        }
        Ok(())
    }

    fn decode<R>(reader: &mut R) -> Result<Self, CodeEofError>
    where
        Self: Sized,
        R: Read,
    {
        Ok(match reader.read_u8()? {
            INSTR_PCVS => Self::PcVs(reader.read_u16()?),
            other => Self::Fail(other),
        })
    }
}

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

use aluvm::isa;
use aluvm::isa::{Bytecode, BytecodeError, ExecStep, InstructionSet};
use aluvm::library::{CodeEofError, LibSite, Read, Write};
use aluvm::reg::{CoreRegs, Reg16, RegS};
use amplify::Wrapper;

pub const INSTR_CNP: u8 = 0b11_000_000;
pub const INSTR_CNS: u8 = 0b11_000_001;
pub const INSTR_CNG: u8 = 0b11_000_010;
pub const INSTR_CNC: u8 = 0b11_000_011;
pub const INSTR_LDP: u8 = 0b11_000_100;
pub const INSTR_LDS: u8 = 0b11_000_101;
pub const INSTR_LDG: u8 = 0b11_000_110;
pub const INSTR_LDC: u8 = 0b11_000_111;
pub const INSTR_LDM: u8 = 0b11_001_000;

pub const INSTR_PCVS: u8 = 0b11_010_000;

// NB: For now we prohibit all other ISAE than this one. More ISAEs can be
// allowed in a future with fast-forwards.
pub use aluvm::isa::opcodes::{INSTR_ISAE_FROM, INSTR_ISAE_TO};
use amplify::num::{u24, u4};

use crate::validation::OpInfo;
use crate::{Assign, TypedState};
// pub const INSTR_ISAE_FROM: u8 = 0b11_000_000;
// pub const INSTR_ISAE_TO: u8 = 0b11_000_000;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
pub enum RgbIsa {
    /// Counts number of inputs (previous state entries) of the provided type
    /// and assigns the number to the destination `a32` register.
    #[display("cnp      {0},a32{1}")]
    CnP(u16, Reg16),

    /// Counts number of outputs (owned state entries) of the provided type
    /// and assigns the number to the destination `a32` register.
    #[display("cns      {0},a32{1}")]
    CnS(u16, Reg16),

    /// Counts number of inputs (previous state entries) of the provided type
    /// and assigns the number to the destination `a8` register.
    #[display("cng      {0},a8{1}")]
    CnG(u16, Reg16),

    /// Counts number of inputs (previous state entries) of the provided type
    /// and assigns the number to the destination `a32` register.
    #[display("cnc      {0},a32{1}")]
    CnC(u16, Reg16),

    /// Loads input (previous) state with type id from the first argument and
    /// index from the second argument into a register provided in the third
    /// argument.
    ///
    /// If the state is absent or concealed sets destination to `None`.
    /// Does not modify content of `st0` register.
    #[display("ldp      {0},{1},{2}")]
    LdP(u16, u24, RegS),

    /// Loads owned state with type id from the first argument and index from
    /// the second argument into a register provided in the third argument.
    ///
    /// If the state is absent or concealed sets destination to `None`.
    /// Does not modify content of `st0` register.
    #[display("lds      {0},{1},{2}")]
    LdS(u16, u24, RegS),

    /// Loads global state from the current operation with type id from the
    /// first argument and index from the second argument into a register
    /// provided in the third argument.
    ///
    /// If the state is absent or concealed sets destination to `None`.
    /// Does not modify content of `st0` register.
    #[display("ldg      {0},{1},{2}")]
    LdG(u16, u8, RegS),

    /// Loads part of the contract global state with type id from the first
    /// argument at the depth from the second argument into a register
    /// provided in the third argument.
    ///
    /// If the state is absent or concealed sets destination to `None`.
    /// Does not modify content of `st0` register.
    #[display("ldc      {0},{1},{2}")]
    LdC(u16, u24, RegS),

    /// Loads operation metadata into a register provided in the third argument.
    ///
    /// If the operation doesn't have metadata sets destination to `None`.
    /// Does not modify content of `st0` register.
    #[display("ldm      {0}")]
    LdM(RegS),

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
     */
    /// All other future unsupported operations, which must set `st0` to
    /// `false`.
    Fail(u8),
}

impl InstructionSet for RgbIsa {
    type Context<'ctx> = OpInfo<'ctx>;

    fn isa_ids() -> BTreeSet<&'static str> {
        bset! {"RGB"}
    }

    fn exec(&self, regs: &mut CoreRegs, site: LibSite, context: &Self::Context<'_>) -> ExecStep {
        macro_rules! fail {
            () => {{
                isa::ControlFlowOp::Fail.exec(regs, site, &());
                return ExecStep::Stop;
            }};
        }

        match self {
            RgbIsa::PcVs(state_type) => {
                if !context.prev_state.contains_key(state_type) &&
                    !context.owned_state.contains_key(state_type)
                {
                    return ExecStep::Next;
                }

                let Some(prev_state) = context.prev_state.get(state_type) else {
                    fail!()
                };
                let Some(new_state) = context.owned_state.get(state_type) else {
                    fail!()
                };

                let inputs = match prev_state {
                    TypedState::Fungible(state) => state
                        .iter()
                        .map(Assign::to_confidential_state)
                        .map(|s| s.commitment.into_inner())
                        .collect::<Vec<_>>(),
                    _ => fail!(),
                };
                let outputs = match new_state {
                    TypedState::Fungible(state) => state
                        .iter()
                        .map(Assign::to_confidential_state)
                        .map(|s| s.commitment.into_inner())
                        .collect::<Vec<_>>(),
                    _ => fail!(),
                };

                if !secp256k1_zkp::verify_commitments_sum_to_equal(
                    secp256k1_zkp::SECP256K1,
                    &inputs,
                    &outputs,
                ) {
                    fail!()
                }

                ExecStep::Next
            }
            // All other future unsupported operations, which must set `st0` to `false`.
            _ => fail!(),
        }
    }
}

impl Bytecode for RgbIsa {
    fn byte_count(&self) -> u16 {
        match self {
            RgbIsa::CnP(_, _) | RgbIsa::CnS(_, _) | RgbIsa::CnG(_, _) | RgbIsa::CnC(_, _) => 3,

            RgbIsa::LdP(_, _, _) | RgbIsa::LdS(_, _, _) | RgbIsa::LdC(_, _, _) => 6,
            RgbIsa::LdG(_, _, _) => 4,
            RgbIsa::LdM(_) => 1,

            RgbIsa::PcVs(_) => 2,
            RgbIsa::Fail(_) => 0,
        }
    }

    fn instr_range() -> RangeInclusive<u8> { INSTR_ISAE_FROM..=INSTR_ISAE_TO }

    fn instr_byte(&self) -> u8 {
        match self {
            RgbIsa::CnP(_, _) => INSTR_CNP,
            RgbIsa::CnS(_, _) => INSTR_CNS,
            RgbIsa::CnG(_, _) => INSTR_CNG,
            RgbIsa::CnC(_, _) => INSTR_CNC,

            RgbIsa::LdP(_, _, _) => INSTR_LDP,
            RgbIsa::LdS(_, _, _) => INSTR_LDS,
            RgbIsa::LdG(_, _, _) => INSTR_LDG,
            RgbIsa::LdC(_, _, _) => INSTR_LDC,
            RgbIsa::LdM(_) => INSTR_LDM,

            RgbIsa::PcVs(_) => INSTR_PCVS,

            RgbIsa::Fail(other) => *other,
        }
    }

    fn encode_args<W>(&self, writer: &mut W) -> Result<(), BytecodeError>
    where W: Write {
        match self {
            RgbIsa::CnP(state_type, reg) => {
                writer.write_u16(*state_type)?;
                writer.write_u4(reg)?;
                writer.write_u4(u4::ZERO)?;
            }
            RgbIsa::CnS(state_type, reg) => {
                writer.write_u16(*state_type)?;
                writer.write_u4(reg)?;
                writer.write_u4(u4::ZERO)?;
            }
            RgbIsa::CnG(state_type, reg) => {
                writer.write_u16(*state_type)?;
                writer.write_u4(reg)?;
                writer.write_u4(u4::ZERO)?;
            }
            RgbIsa::CnC(state_type, reg) => {
                writer.write_u16(*state_type)?;
                writer.write_u4(reg)?;
                writer.write_u4(u4::ZERO)?;
            }
            RgbIsa::LdP(state_type, index, reg) => {
                writer.write_u16(*state_type)?;
                writer.write_u24(*index)?;
                writer.write_u4(reg)?;
                writer.write_u4(u4::ZERO)?;
            }
            RgbIsa::LdS(state_type, index, reg) => {
                writer.write_u16(*state_type)?;
                writer.write_u24(*index)?;
                writer.write_u4(reg)?;
                writer.write_u4(u4::ZERO)?;
            }
            RgbIsa::LdG(state_type, index, reg) => {
                writer.write_u16(*state_type)?;
                writer.write_u8(*index)?;
                writer.write_u4(reg)?;
                writer.write_u4(u4::ZERO)?;
            }
            RgbIsa::LdC(state_type, index, reg) => {
                writer.write_u16(*state_type)?;
                writer.write_u24(*index)?;
                writer.write_u4(reg)?;
                writer.write_u4(u4::ZERO)?;
            }
            RgbIsa::LdM(reg) => {
                writer.write_u4(reg)?;
                writer.write_u4(u4::ZERO)?;
            }

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
            INSTR_CNP => {
                let i = Self::CnP(reader.read_u16()?, reader.read_u4()?.into());
                reader.read_u4()?; // Discard garbage bits
                i
            }
            INSTR_CNS => {
                let i = Self::CnS(reader.read_u16()?, reader.read_u4()?.into());
                reader.read_u4()?; // Discard garbage bits
                i
            }
            INSTR_CNG => {
                let i = Self::CnG(reader.read_u16()?, reader.read_u4()?.into());
                reader.read_u4()?; // Discard garbage bits
                i
            }
            INSTR_CNC => {
                let i = Self::CnC(reader.read_u16()?, reader.read_u4()?.into());
                reader.read_u4()?; // Discard garbage bits
                i
            }

            INSTR_LDP => {
                let i = Self::LdP(reader.read_u16()?, reader.read_u24()?, reader.read_u4()?.into());
                reader.read_u4()?; // Discard garbage bits
                i
            }
            INSTR_LDS => {
                let i = Self::LdS(reader.read_u16()?, reader.read_u24()?, reader.read_u4()?.into());
                reader.read_u4()?; // Discard garbage bits
                i
            }
            INSTR_LDG => {
                let i = Self::LdG(reader.read_u16()?, reader.read_u8()?, reader.read_u4()?.into());
                reader.read_u4()?; // Discard garbage bits
                i
            }
            INSTR_LDC => {
                let i = Self::LdC(reader.read_u16()?, reader.read_u24()?, reader.read_u4()?.into());
                reader.read_u4()?; // Discard garbage bits
                i
            }
            INSTR_LDM => {
                let i = Self::LdM(reader.read_u4()?.into());
                reader.read_u4()?; // Discard garbage bits
                i
            }

            INSTR_PCVS => Self::PcVs(reader.read_u16()?),
            other => Self::Fail(other),
        })
    }
}

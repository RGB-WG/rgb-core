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

#![allow(clippy::unusual_byte_groupings)]

use std::borrow::Borrow;
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::marker::PhantomData;
use std::ops::RangeInclusive;

use aluvm::isa::{Bytecode, BytecodeError, ExecStep, InstructionSet};
use aluvm::library::{CodeEofError, IsaSeg, LibSite, Read, Write};
use aluvm::reg::{CoreRegs, Reg, Reg16, Reg32, RegA, RegS};
use amplify::num::{u24, u3, u4};
use amplify::Wrapper;

use super::opcodes::*;
use super::{ContractStateAccess, VmContext};
use crate::{AssignmentType, GlobalStateType, MetaType};

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
pub enum ContractOp<S: ContractStateAccess> {
    /// Counts number of inputs (previous state entries) of the provided type and puts the number
    /// to the destination `a16` register.
    ///
    /// If the operation doesn't contain inputs with a given assignment type, sets destination
    /// index to zero. Does not change `st0` register.
    #[display("cnp     {0},a16{1}")]
    CnP(AssignmentType, Reg32),

    /// Counts number of outputs (owned state entries) of the provided type and puts the number to
    /// the destination `a16` register.
    ///
    /// If the operation doesn't contain inputs with a given assignment type, sets destination
    /// index to zero. Does not change `st0` register.
    #[display("cns     {0},a16{1}")]
    CnS(AssignmentType, Reg32),

    /// Counts number of global state items of the provided type affected by the current operation
    /// and puts the number to the destination `a8` register.
    ///
    /// If the operation doesn't contain inputs with a given assignment type, sets destination
    /// index to zero. Does not change `st0` register.
    #[display("cng     {0},a8{1}")]
    CnG(GlobalStateType, Reg32),

    /// Counts number of global state items of the provided type in the contract state and puts the
    /// number to the destination `a32` register.
    ///
    /// If the operation doesn't contain inputs with a given assignment type, sets destination
    /// index to zero. Does not change `st0` register.
    #[display("cnc     {0},a32{1}")]
    CnC(GlobalStateType, Reg32),

    /// Loads input (previous) state with type id from the first argument and index from the second
    /// argument `a16` register into a register provided in the third argument.
    ///
    /// If the state is absent or is not a structured state sets `st0` to `false` and terminates
    /// the program.
    ///
    /// If the state at the index is concealed, sets destination to `None`.
    #[display("ldp     {0},a16{1},{2}")]
    LdP(AssignmentType, Reg16, RegS),

    /// Loads owned state with type id from the first argument and index from the second argument
    /// `a16` register into a register provided in the third argument.
    ///
    /// If the state is absent or is not a structured state sets `st0` to `false` and terminates
    /// the program.
    ///
    /// If the state at the index is concealed, sets destination to `None`.
    #[display("lds     {0},a16{1},{2}")]
    LdS(AssignmentType, Reg16, RegS),

    /// Loads global state from the current operation with type id from the first argument and
    /// index from the second argument `a8` register into a register provided in the third
    /// argument.
    ///
    /// If the state is absent sets `st0` to `false` and terminates the program.
    #[display("ldg     {0},a8{1},{2}")]
    LdG(GlobalStateType, Reg16, RegS),

    /// Loads part of the contract global state with type id from the first argument at the depth
    /// from the second argument `a32` register into a register provided in the third argument.
    ///
    /// If the contract doesn't have the provided global state type, or it doesn't contain a value
    /// at the requested index, sets `st0` to fail state and terminates the program. The value
    /// of the destination register is not changed.
    #[display("ldc     {0},a32{1},{2}")]
    LdC(GlobalStateType, Reg16, RegS),

    /// Loads operation metadata with a type id from the first argument into a register provided in
    /// the second argument.
    ///
    /// If the operation doesn't have metadata, sets `st0` to fail state and terminates the
    /// program. The value of the destination register is not changed.
    #[display("ldm     {0},{1}")]
    LdM(MetaType, RegS),

    /// All other future unsupported operations, which must set `st0` to `false` and stop the
    /// execution.
    #[display("fail    {0}")]
    Fail(u8, PhantomData<S>),
}

impl<S: ContractStateAccess> InstructionSet for ContractOp<S> {
    type Context<'ctx> = VmContext<'ctx, S>;

    fn isa_ids() -> IsaSeg { IsaSeg::with("RGB") }

    fn src_regs(&self) -> BTreeSet<Reg> {
        match self {
            ContractOp::LdP(_, reg, _) | ContractOp::LdS(_, reg, _) => {
                bset![Reg::A(RegA::A16, (*reg).into())]
            }
            ContractOp::LdG(_, reg, _) => bset![Reg::A(RegA::A8, (*reg).into())],
            ContractOp::LdC(_, reg, _) => bset![Reg::A(RegA::A32, (*reg).into())],

            ContractOp::CnP(_, _)
            | ContractOp::CnS(_, _)
            | ContractOp::CnG(_, _)
            | ContractOp::CnC(_, _)
            | ContractOp::LdM(_, _) => bset![],
            ContractOp::Fail(_, _) => bset![],
        }
    }

    fn dst_regs(&self) -> BTreeSet<Reg> {
        match self {
            ContractOp::CnG(_, reg) => {
                bset![Reg::A(RegA::A8, *reg)]
            }
            ContractOp::CnP(_, reg) | ContractOp::CnS(_, reg) | ContractOp::CnC(_, reg) => {
                bset![Reg::A(RegA::A16, *reg)]
            }
            ContractOp::LdG(_, _, reg)
            | ContractOp::LdS(_, _, reg)
            | ContractOp::LdP(_, _, reg)
            | ContractOp::LdC(_, _, reg)
            | ContractOp::LdM(_, reg) => {
                bset![Reg::S(*reg)]
            }
            ContractOp::Fail(_, _) => bset![],
        }
    }

    fn complexity(&self) -> u64 {
        match self {
            ContractOp::CnP(_, _)
            | ContractOp::CnS(_, _)
            | ContractOp::CnG(_, _)
            | ContractOp::CnC(_, _) => 2,
            ContractOp::LdP(_, _, _)
            | ContractOp::LdS(_, _, _)
            | ContractOp::LdG(_, _, _)
            | ContractOp::LdC(_, _, _) => 8,
            ContractOp::LdM(_, _) => 6,
            ContractOp::Fail(_, _) => u64::MAX,
        }
    }

    fn exec(&self, regs: &mut CoreRegs, _site: LibSite, context: &Self::Context<'_>) -> ExecStep {
        macro_rules! fail {
            () => {{
                regs.set_failure();
                return ExecStep::Stop;
            }};
        }

        match self {
            ContractOp::CnP(state_type, reg) => {
                regs.set_n(
                    RegA::A16,
                    *reg,
                    context
                        .op_info
                        .prev_state
                        .get(state_type)
                        .map(|a| a.len_u16()),
                );
            }
            ContractOp::CnS(state_type, reg) => {
                regs.set_n(
                    RegA::A16,
                    *reg,
                    context
                        .op_info
                        .owned_state
                        .get(*state_type)
                        .map(|a| a.len_u16()),
                );
            }
            ContractOp::CnG(state_type, reg) => {
                regs.set_n(
                    RegA::A8,
                    *reg,
                    context.op_info.global.get(state_type).map(|a| a.len_u16()),
                );
            }
            ContractOp::CnC(state_type, reg) => {
                if let Ok(mut global) = RefCell::borrow(&context.contract_state).global(*state_type)
                {
                    regs.set_n(RegA::A32, *reg, global.size().to_u32());
                } else {
                    regs.set_n(RegA::A32, *reg, None::<u32>);
                }
            }
            ContractOp::LdP(state_type, reg_32, reg) => {
                let Some(reg_32) = *regs.get_n(RegA::A16, *reg_32) else {
                    fail!()
                };
                let index: u16 = reg_32.into();

                let Some(state) = context
                    .op_info
                    .prev_state
                    .get(state_type)
                    .and_then(|a| a.as_state_at(index).ok())
                else {
                    fail!()
                };
                regs.set_s(*reg, Some(&state.value));
            }
            ContractOp::LdS(state_type, reg_32, reg) => {
                let Some(reg_32) = *regs.get_n(RegA::A16, *reg_32) else {
                    fail!()
                };
                let index: u16 = reg_32.into();

                let Some(state) = context
                    .op_info
                    .owned_state
                    .get(*state_type)
                    .and_then(|a| a.into_state_at(index).ok())
                else {
                    fail!()
                };
                regs.set_s(*reg, Some(state.value));
            }
            ContractOp::LdG(state_type, reg_8, reg_s) => {
                let Some(reg_32) = *regs.get_n(RegA::A8, *reg_8) else {
                    fail!()
                };
                let index: u8 = reg_32.into();

                let Some(state) = context
                    .op_info
                    .global
                    .get(state_type)
                    .and_then(|a| a.get(index as usize))
                else {
                    fail!()
                };
                regs.set_s(*reg_s, Some(state));
            }

            ContractOp::LdC(state_type, reg_32, reg_s) => {
                let state = RefCell::borrow(&context.contract_state);
                let Ok(mut global) = state.global(*state_type) else {
                    fail!()
                };
                let Some(reg_32) = *regs.get_n(RegA::A32, *reg_32) else {
                    fail!()
                };
                let index: u32 = reg_32.into();
                let Ok(index) = u24::try_from(index) else {
                    fail!()
                };
                let Some(state) = global.nth(index) else {
                    fail!()
                };
                regs.set_s(*reg_s, Some(state.borrow()));
            }
            ContractOp::LdM(type_id, reg) => {
                let Some(meta) = context.op_info.metadata.get(type_id) else {
                    fail!()
                };
                regs.set_s(*reg, Some(meta.to_inner()));
            }

            // All other future unsupported operations, which must set `st0` to `false`.
            _ => fail!(),
        }
        ExecStep::Next
    }
}

impl<S: ContractStateAccess> Bytecode for ContractOp<S> {
    fn instr_range() -> RangeInclusive<u8> { INSTR_CONTRACT_FROM..=INSTR_CONTRACT_TO }

    fn instr_byte(&self) -> u8 {
        match self {
            ContractOp::CnP(_, _) => INSTR_CNP,
            ContractOp::CnS(_, _) => INSTR_CNS,
            ContractOp::CnG(_, _) => INSTR_CNG,
            ContractOp::CnC(_, _) => INSTR_CNC,

            ContractOp::LdG(_, _, _) => INSTR_LDG,
            ContractOp::LdS(_, _, _) => INSTR_LDS,
            ContractOp::LdP(_, _, _) => INSTR_LDP,
            ContractOp::LdC(_, _, _) => INSTR_LDC,
            ContractOp::LdM(_, _) => INSTR_LDM,

            ContractOp::Fail(other, _) => *other,
        }
    }

    fn encode_args<W>(&self, writer: &mut W) -> Result<(), BytecodeError>
    where W: Write {
        match self {
            ContractOp::CnP(state_type, reg) => {
                writer.write_u16(*state_type)?;
                writer.write_u5(reg)?;
                writer.write_u3(u3::ZERO)?;
            }
            ContractOp::CnS(state_type, reg) => {
                writer.write_u16(*state_type)?;
                writer.write_u5(reg)?;
                writer.write_u3(u3::ZERO)?;
            }
            ContractOp::CnG(state_type, reg) => {
                writer.write_u16(*state_type)?;
                writer.write_u5(reg)?;
                writer.write_u3(u3::ZERO)?;
            }
            ContractOp::CnC(state_type, reg) => {
                writer.write_u16(*state_type)?;
                writer.write_u5(reg)?;
                writer.write_u3(u3::ZERO)?;
            }
            ContractOp::LdP(state_type, reg_a, reg_s) => {
                writer.write_u16(*state_type)?;
                writer.write_u4(reg_a)?;
                writer.write_u4(reg_s)?;
            }
            ContractOp::LdS(state_type, reg_a, reg_s) => {
                writer.write_u16(*state_type)?;
                writer.write_u4(reg_a)?;
                writer.write_u4(reg_s)?;
            }
            ContractOp::LdG(state_type, reg_a, reg_s) => {
                writer.write_u16(*state_type)?;
                writer.write_u4(reg_a)?;
                writer.write_u4(reg_s)?;
            }
            ContractOp::LdC(state_type, reg_a, reg_s) => {
                writer.write_u16(*state_type)?;
                writer.write_u4(reg_a)?;
                writer.write_u4(reg_s)?;
            }
            ContractOp::LdM(state_type, reg) => {
                writer.write_u16(*state_type)?;
                writer.write_u4(reg)?;
                writer.write_u4(u4::ZERO)?;
            }

            ContractOp::Fail(_, _) => {}
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
                let i = Self::CnP(reader.read_u16()?.into(), reader.read_u5()?.into());
                reader.read_u3()?; // Discard garbage bits
                i
            }
            INSTR_CNS => {
                let i = Self::CnS(reader.read_u16()?.into(), reader.read_u5()?.into());
                reader.read_u3()?; // Discard garbage bits
                i
            }
            INSTR_CNG => {
                let i = Self::CnG(reader.read_u16()?.into(), reader.read_u5()?.into());
                reader.read_u3()?; // Discard garbage bits
                i
            }
            INSTR_CNC => {
                let i = Self::CnC(reader.read_u16()?.into(), reader.read_u5()?.into());
                reader.read_u3()?; // Discard garbage bits
                i
            }

            INSTR_LDP => Self::LdP(
                reader.read_u16()?.into(),
                reader.read_u4()?.into(),
                reader.read_u4()?.into(),
            ),
            INSTR_LDG => Self::LdG(
                reader.read_u16()?.into(),
                reader.read_u4()?.into(),
                reader.read_u4()?.into(),
            ),
            INSTR_LDS => Self::LdS(
                reader.read_u16()?.into(),
                reader.read_u4()?.into(),
                reader.read_u4()?.into(),
            ),
            INSTR_LDC => Self::LdC(
                reader.read_u16()?.into(),
                reader.read_u4()?.into(),
                reader.read_u4()?.into(),
            ),
            INSTR_LDM => {
                let i = Self::LdM(reader.read_u16()?.into(), reader.read_u4()?.into());
                reader.read_u4()?; // Discard garbage bits
                i
            }

            x => Self::Fail(x, PhantomData),
        })
    }
}

// TODO: Re-enable once we will have a test ContractState object
/*
#[cfg(test)]
mod test {
    use aluvm::isa::Instr;
    use aluvm::library::Lib;
    use amplify::hex::ToHex;
    use strict_encoding::StrictSerialize;

    use super::*;
    use crate::vm::RgbIsa;

    #[test]
    fn encoding() {
        let code =
            [Instr::ExtensionCodes(RgbIsa::Contract(ContractOp::Pcvs(AssignmentType::from(4000))))];
        let alu_lib = Lib::assemble(&code).unwrap();
        eprintln!("{alu_lib}");
        let alu_id = alu_lib.id();

        assert_eq!(
            alu_id.to_string(),
            "alu:zI4PtPCR-Eut023!-Hqblf3X-N2J4GZb-TR2ZEsI-vQfhKOU#ruby-sherman-tonight"
        );
        assert_eq!(alu_lib.code.as_ref().to_hex(), "d0a00f");
        assert_eq!(
            alu_lib
                .to_strict_serialized::<{ usize::MAX }>()
                .unwrap()
                .to_hex(),
            "0303414c55084250444947455354035247420300d0a00f000000"
        );
        assert_eq!(alu_lib.disassemble::<Instr<RgbIsa<_>>>().unwrap(), code);
    }
}
*/

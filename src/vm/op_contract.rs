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
use std::marker::PhantomData;
use std::ops::RangeInclusive;

use aluvm::isa::{Bytecode, BytecodeError, ExecStep, InstructionSet};
use aluvm::library::{CodeEofError, IsaSeg, LibSite, Read, Write};
use aluvm::reg::{CoreRegs, Reg, Reg16, Reg32, RegA, RegS};
use amplify::num::{u1, u2, u24, u3};
use amplify::Wrapper;

use super::opcodes::*;
use super::{ContractStateAccess, VmContext};
use crate::{AssignmentType, GlobalStateType, MetaType};

/// Operations defined under RGB ISA extension (`RGB`).
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
pub enum ContractOp<S: ContractStateAccess> {
    /// Counts number of global items elements defined by the current operation of the type,
    /// provided by the second argument, and puts the number to the destination `a32`
    /// register from the first argument.
    ///
    /// If the operation doesn't contain inputs with a given assignment type, sets destination
    /// index to zero.
    ///
    /// # Idempotence
    ///
    /// The operation is idempotent.
    ///
    /// # Fails
    ///
    /// Operation fails by setting `st0` to fail state and terminating the program. This happens
    /// only if the `ty` index is unset. In this case, the value of the destination register
    /// remains unchanged.
    ///
    /// If operation doesn't fail, the value of `st0` remains unaffected (i.e. if it was set to
    /// failed state before the operation, the operation doesn't change that).
    #[display("cn.c    a32{dst},a16{ty}")]
    CnC {
        /// Index of an `a32` register receiving count of global state items of the type provided
        /// in `ty`, contained in the contract global state.
        dst: Reg32,
        /// Index of `a16` register containing global state type.
        ty: Reg32,
    },

    /// Counts number of global items elements defined by the current operation of the type,
    /// provided by the second argument, and puts the number to the destination `a16`
    /// register from the first argument.
    ///
    /// If the operation doesn't contain inputs with a given assignment type, sets destination
    /// index to zero.
    ///
    /// # Idempotence
    ///
    /// The operation is idempotent.
    ///
    /// # Fails
    ///
    /// Operation fails by setting `st0` to fail state and terminating the program. This happens
    /// only if the `ty` index is unset. In this case, the value of the destination register
    /// remains unchanged.
    ///
    /// If operation doesn't fail, the value of `st0` remains unaffected (i.e. if it was set to
    /// failed state before the operation, the operation doesn't change that).
    #[display("cn.g    a16{dst},a16{ty}")]
    CnG {
        /// Index of an `a16` register receiving count of global state items of the type provided
        /// in `ty`, contained in the current operation.
        dst: Reg32,
        /// Index of `a16` register containing global state type.
        ty: Reg32,
    },

    /// Counts number of inputs (closed assignment seals) of the type provided by the second
    /// argument and puts the number to the destination `a16` register from the first argument.
    ///
    /// If the operation doesn't contain inputs with a given assignment type, sets destination
    /// index to zero.
    ///
    /// # Idempotence
    ///
    /// The operation is idempotent.
    ///
    /// # Fails
    ///
    /// Operation fails by setting `st0` to fail state and terminating the program. This happens
    /// only if the `ty` index is unset. In this case, the value of the destination register
    /// remains unchanged.
    ///
    /// If operation doesn't fail, the value of `st0` remains unaffected (i.e. if it was set to
    /// failed state before the operation, the operation doesn't change that).
    #[display("cn.i    a16{dst},a16{ty}")]
    CnI {
        /// Index of an `a16` register receiving count of the assignments which seals were closed
        /// by the current operation.
        dst: Reg32,
        /// Index of `a16` register containing assignment type.
        ty: Reg32,
    },

    /// Counts number of outputs (owned state assignments) of the type provided by the second
    /// argument and puts the number to the destination `a16` register from the first argument.
    ///
    /// If the operation doesn't contain inputs with a given assignment type, sets destination
    /// index to zero.
    ///
    /// # Idempotence
    ///
    /// The operation is idempotent.
    ///
    /// # Fails
    ///
    /// Operation fails by setting `st0` to fail state and terminating the program. This happens
    /// only if the `ty` index is unset. In this case, the value of the destination register
    /// remains unchanged.
    ///
    /// If operation doesn't fail, the value of `st0` remains unaffected (i.e. if it was set to
    /// failed state before the operation, the operation doesn't change that).
    #[display("cn.o    a16{dst},a16{ty}")]
    CnO {
        /// Index of an `a16` register receiving assignments count of the type provided in `ty`.
        dst: Reg32,
        /// Index of `a16` register containing assignment type.
        ty: Reg32,
    },

    #[doc(hidden)]
    /// Reserved command inside the counting operations sub-block.
    ///
    /// Currently, always set `st0` to failed state and terminate the program.
    #[display("cn.{instr}    a16{dst},a16{ty}")]
    CnReserved {
        instr: u2,
        dst: Reg32,
        ty: Reg32,
        _phantom: PhantomData<S>,
    },

    // TODO: implement ct.* operations
    #[doc(hidden)]
    /// Reserved for counting type ids.
    ///
    /// Currently, always set `st0` to failed state and terminate the program.
    #[display("ct.{instr}    a16{dst}")]
    CtReserved { instr: u3, dst: Reg32 },

    /// Loads contract global state.
    ///
    /// # Idempotence
    ///
    /// The operation is idempotent.
    ///
    /// # Fails
    ///
    /// Operation fails by setting `st0` to fail state and terminating the program. This happens
    /// in the following cases:
    /// - `ty` index is unset;
    /// - `pos` index is unset;
    /// - the contract doesn't have the provided global state type;
    /// - the contract global state of the provided type has less than `pos` items.
    ///
    /// The value of the destination register in all these cases is not changed.
    ///
    /// If operation doesn't fail, the value of `st0` remains unaffected (i.e. if it was set to
    /// failed state before the operation, the operation doesn't change that).
    #[display("ld.c    {dst},a16{ty},a32{pos}")]
    LdC {
        /// Index of string register receiving the loaded state data.
        dst: RegS,
        /// Index of `a16` register containing global state type.
        ty: Reg32,
        /// Index of `a32` register containing position inside the list of all global state by the
        /// given `ty` type.
        pos: Reg32,
    },

    /// Loads global state from the current operation.
    ///
    /// # Idempotence
    ///
    /// The operation is idempotent.
    ///
    /// # Fails
    ///
    /// Operation fails by setting `st0` to fail state and terminating the program. This happens
    /// in the following cases:
    /// - `ty` index is unset;
    /// - `pos` index is unset;
    /// - the operation doesn't have the provided global state type;
    /// - the operation global state of the provided type has less than `pos` items.
    ///
    /// The value of the destination register in all these cases is not changed.
    ///
    /// If operation doesn't fail, the value of `st0` remains unaffected (i.e. if it was set to
    /// failed state before the operation, the operation doesn't change that).
    #[display("ld.g    {dst},a16{ty},a16{pos}")]
    LdG {
        /// Index of string register receiving the loaded state data.
        dst: RegS,
        /// Index of `a16` register containing global state type.
        ty: Reg32,
        /// Index of `a16` register containing position inside the list of all global state by the
        /// given `ty` type.
        pos: Reg32,
    },

    /// Loads owned state from an assignment which seal was closed with the current operation
    /// ("input").
    ///
    /// # Idempotence
    ///
    /// The operation is idempotent.
    ///
    /// # Fails
    ///
    /// Operation fails by setting `st0` to fail state and terminating the program. This happens
    /// in the following cases:
    /// - `ty` index is unset;
    /// - `pos` index is unset;
    /// - none of the operation's inputs has the provided assignment type;
    /// - there is less than `pos` assignments in operation inputs of the provided type.
    ///
    /// The value of the destination register in all these cases is not changed.
    ///
    /// If operation doesn't fail, the value of `st0` remains unaffected (i.e. if it was set to
    /// failed state before the operation, the operation doesn't change that).
    #[display("ld.i    {dst},a16{ty},a16{pos}")]
    LdI {
        /// Index of string register receiving the loaded state data.
        dst: RegS,
        /// Index of `a16` register containing assignment type.
        ty: Reg32,
        /// Index of `a16` register containing position inside the list of all assignments of the
        /// `ty` type.
        pos: Reg32,
    },

    /// Loads owned state assigned by the current operation.
    ///
    /// # Idempotence
    ///
    /// The operation is idempotent.
    ///
    /// # Fails
    ///
    /// Operation fails by setting `st0` to fail state and terminating the program. This happens
    /// in the following cases:
    /// - `ty` index is unset;
    /// - `pos` index is unset;
    /// - the operation doesn't have assignments of the provided type;
    /// - the operation assignments of the provided type has less than `pos` items.
    ///
    /// The value of the destination register in all these cases is not changed.
    ///
    /// If operation doesn't fail, the value of `st0` remains unaffected (i.e. if it was set to
    /// failed state before the operation, the operation doesn't change that).
    #[display("ld.o    {dst},a16{ty},a16{pos}")]
    LdO {
        /// Index of string register receiving the loaded state data.
        dst: RegS,
        /// Index of `a16` register containing assignment type.
        ty: Reg32,
        /// Index of `a16` register containing position inside the list of all assignments of the
        /// `ty` type.
        pos: Reg32,
    },

    /// Loads operation metadata.
    ///
    /// # Idempotence
    ///
    /// The operation is idempotent.
    ///
    /// # Fails
    ///
    /// Operation fails by setting `st0` to fail state and terminating the program. This happens
    /// in the following cases:
    /// - `ty` index is unset;
    /// - the operation doesn't metadata of the provided type.
    ///
    /// The value of the destination register in all these cases is not changed.
    ///
    /// If operation doesn't fail, the value of `st0` remains unaffected (i.e. if it was set to
    /// failed state before the operation, the operation doesn't change that).
    #[display("ldm     {dst},a16{ty}")]
    LdM {
        /// Index of string register receiving the loaded state data.
        dst: RegS,
        /// Index of `a16` register containing global state type.
        ty: Reg16,
    },
}

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
        macro_rules! fail {
            () => {{
                regs.set_failure();
                return ExecStep::Stop;
            }};
        }

        match *self {
            ContractOp::CnC { dst, ty } => {
                let Some(state_type) = regs.a16(ty).map(GlobalStateType::with) else {
                    fail!()
                };
                let state = RefCell::borrow(&context.contract_state);
                let cnt = state.global(state_type).map(|mut s| s.size());
                regs.set_a32(dst, cnt.unwrap_or_default().to_u32());
            }
            ContractOp::CnG { dst, ty } => {
                let Some(state_type) = regs.a16(ty).map(GlobalStateType::with) else {
                    fail!()
                };
                let state = context.op_info.global;
                let cnt = state.get(&state_type).map(|a| a.len_u16());
                regs.set_a16(dst, cnt.unwrap_or_default());
            }
            ContractOp::CnI { dst, ty } => {
                let Some(state_type) = regs.a16(ty).map(AssignmentType::with) else {
                    fail!()
                };
                let state = context.op_info.prev_state;
                let cnt = state.get(&state_type).map(|a| a.len_u16());
                regs.set_a16(dst, cnt.unwrap_or_default());
            }
            ContractOp::CnO { dst, ty } => {
                let Some(state_type) = regs.a16(ty).map(AssignmentType::with) else {
                    fail!()
                };
                let state = context.op_info.owned_state;
                let cnt = state.get(state_type).map(|a| a.len_u16());
                regs.set_a16(dst, cnt.unwrap_or_default());
            }

            ContractOp::LdC { dst, ty, pos } => {
                let Some(state_type) = regs.a16(ty).map(GlobalStateType::with) else {
                    fail!()
                };
                let Some(index) = regs.a32(pos).and_then(|pos| u24::try_from(pos).ok()) else {
                    fail!()
                };
                let state = RefCell::borrow(&context.contract_state);
                let Some(mut iter) = state.global(state_type).ok() else {
                    fail!()
                };
                let Some(state) = iter.nth(index) else {
                    fail!()
                };
                regs.set_s16(dst, state.borrow().as_inner());
            }

            ContractOp::LdG { dst, ty, pos } => {
                let Some(state_type) = regs.a16(ty).map(GlobalStateType::with) else {
                    fail!()
                };
                let Some(index) = regs.a16(pos) else { fail!() };
                let state = context.op_info.global;
                let Some(state) = state.get(&state_type).and_then(|a| a.get(index as usize)) else {
                    fail!()
                };
                regs.set_s16(dst, state.as_inner());
            }
            ContractOp::LdI { dst, ty, pos } => {
                let Some(state_type) = regs.a16(ty).map(AssignmentType::with) else {
                    fail!()
                };
                let Some(index) = regs.a16(pos) else { fail!() };
                let state = context.op_info.prev_state;
                let Some(assign) = state.get(&state_type).and_then(|a| a.get(index as usize))
                else {
                    fail!()
                };
                regs.set_s16(dst, assign.as_state().data.as_inner());
            }
            ContractOp::LdO { dst, ty, pos } => {
                let Some(state_type) = regs.a16(ty).map(AssignmentType::with) else {
                    fail!()
                };
                let Some(index) = regs.a16(pos) else { fail!() };
                let state = context.op_info.owned_state;
                let Some(assign) = state.get(state_type) else {
                    fail!()
                };
                let Some(assign) = assign.get(index as usize) else {
                    fail!()
                };
                regs.set_s16(dst, assign.as_state().data.as_inner());
            }

            ContractOp::LdM { dst, ty } => {
                let Some(state_type) = regs.a16(ty).map(MetaType::with) else {
                    fail!()
                };
                let state = context.op_info.metadata;
                let Some(assign) = state.get(&state_type) else {
                    fail!()
                };
                regs.set_s16(dst, assign.as_inner());
            }

            // All other future unsupported operations, which must set `st0` to `false`.
            ContractOp::CnReserved { .. } => fail!(),
            ContractOp::CtReserved { .. } => fail!(),
        }
        ExecStep::Next
    }
}

impl<S: ContractStateAccess> Bytecode for ContractOp<S> {
    fn instr_range() -> RangeInclusive<u8> { INSTR_CONTRACT_FROM..=INSTR_CONTRACT_TO }

    fn instr_byte(&self) -> u8 {
        match *self {
            ContractOp::CnI { .. }
            | ContractOp::CnO { .. }
            | ContractOp::CnG { .. }
            | ContractOp::CnC { .. }
            | ContractOp::CnReserved { .. }
            | ContractOp::CtReserved { .. } => INSTR_RGB_CNT,

            ContractOp::LdG { .. }
            | ContractOp::LdI { .. }
            | ContractOp::LdO { .. }
            | ContractOp::LdC { .. } => INSTR_RGB_LD,

            ContractOp::LdM { .. } => INSTR_RGB_LDM,
        }
    }

    fn encode_args<W>(&self, writer: &mut W) -> Result<(), BytecodeError>
    where W: Write {
        match *self {
            ContractOp::CnC { dst, ty }
            | ContractOp::CnG { dst, ty }
            | ContractOp::CnI { dst, ty }
            | ContractOp::CnO { dst, ty }
            | ContractOp::CnReserved { dst, ty, .. } => {
                writer.write_u3(INSTR_RGB_CNT_EXT)?;
                match *self {
                    ContractOp::CnC { .. } => writer.write_u3(INSTR_RGB_CNT_C)?,
                    ContractOp::CnG { .. } => writer.write_u3(INSTR_RGB_CNT_G)?,
                    ContractOp::CnI { .. } => writer.write_u3(INSTR_RGB_CNT_I)?,
                    ContractOp::CnO { .. } => writer.write_u3(INSTR_RGB_CNT_O)?,
                    ContractOp::CnReserved { instr, .. } => {
                        writer.write_u1(u1::ONE)?;
                        writer.write_u2(instr)?;
                    }
                    _ => unreachable!(),
                }
                writer.write_u5(dst)?;
                writer.write_u5(ty)?;
            }

            ContractOp::CtReserved { instr, dst } => {
                writer.write_u3(instr)?;
                writer.write_u5(dst)?;
            }

            ContractOp::LdC { dst, ty, pos }
            | ContractOp::LdG { dst, ty, pos }
            | ContractOp::LdI { dst, ty, pos }
            | ContractOp::LdO { dst, ty, pos } => {
                writer.write_u2(match self {
                    ContractOp::LdC { .. } => INSTR_RGB_LD_C,
                    ContractOp::LdG { .. } => INSTR_RGB_LD_G,
                    ContractOp::LdI { .. } => INSTR_RGB_LD_I,
                    ContractOp::LdO { .. } => INSTR_RGB_LD_O,
                    _ => unreachable!(),
                })?;
                writer.write_u4(dst)?;
                writer.write_u5(ty)?;
                writer.write_u5(pos)?;
            }

            ContractOp::LdM { dst, ty } => {
                writer.write_u4(dst)?;
                writer.write_u4(ty)?;
            }
        }
        Ok(())
    }

    fn decode<R>(reader: &mut R) -> Result<Self, CodeEofError>
    where
        Self: Sized,
        R: Read,
    {
        Ok(match reader.read_u8()? {
            INSTR_RGB_CNT => {
                let instr = reader.read_u3()?;
                if instr == INSTR_RGB_CNT_EXT {
                    let instr2 = reader.read_u3()?;
                    let dst = Reg32::from(reader.read_u5()?);
                    let ty = Reg32::from(reader.read_u5()?);
                    match instr2 {
                        INSTR_RGB_CNT_C => Self::CnC { dst, ty },
                        INSTR_RGB_CNT_G => Self::CnG { dst, ty },
                        INSTR_RGB_CNT_I => Self::CnI { dst, ty },
                        INSTR_RGB_CNT_O => Self::CnO { dst, ty },
                        INSTR_RGB_CNT_R => Self::CnReserved {
                            instr: u2::with(0),
                            dst,
                            ty,
                            _phantom: PhantomData,
                        },
                        INSTR_RGB_CNT_V => Self::CnReserved {
                            instr: u2::with(1),
                            dst,
                            ty,
                            _phantom: PhantomData,
                        },
                        INSTR_RGB_CNT_M => Self::CnReserved {
                            instr: u2::with(2),
                            dst,
                            ty,
                            _phantom: PhantomData,
                        },
                        INSTR_RGB_CNT_EXT => Self::CnReserved {
                            instr: u2::with(3),
                            dst,
                            ty,
                            _phantom: PhantomData,
                        },
                        _ => unreachable!(),
                    }
                } else {
                    let dst = Reg32::from(reader.read_u5()?);
                    Self::CtReserved { instr, dst }
                    /*match instr {
                        INSTR_RGB_CNT_C => Self::CtC { dst, ty },
                        INSTR_RGB_CNT_G => Self::CtG { dst, ty },
                        INSTR_RGB_CNT_I => Self::CtI { dst, ty },
                        INSTR_RGB_CNT_O => Self::CtO { dst, ty },
                        INSTR_RGB_CNT_R => Self::CtR { dst, ty },
                        INSTR_RGB_CNT_V => Self::CtV { dst, ty },
                        INSTR_RGB_CNT_M => Self::CtV { dst, ty },
                        INSTR_RGB_CNT_RESERVED1 => Self::Reserved1 { dst, ty },
                    }*/
                }
            }

            INSTR_RGB_LD => {
                let instr = reader.read_u2()?;
                let dst = RegS::from(reader.read_u4()?);
                let ty = Reg32::from(reader.read_u5()?);
                let pos = Reg32::from(reader.read_u5()?);
                match instr {
                    INSTR_RGB_LD_C => Self::LdC { dst, ty, pos },
                    INSTR_RGB_LD_G => Self::LdG { dst, ty, pos },
                    INSTR_RGB_LD_I => Self::LdI { dst, ty, pos },
                    INSTR_RGB_LD_O => Self::LdO { dst, ty, pos },
                    _ => unreachable!(),
                }
            }

            INSTR_RGB_LDM => {
                let dst = RegS::from(reader.read_u4()?);
                let ty = Reg16::from(reader.read_u4()?);
                Self::LdM { dst, ty }
            }

            _ => unreachable!("error in constants definition"),
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

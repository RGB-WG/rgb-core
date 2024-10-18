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

use std::marker::PhantomData;
use std::ops::RangeInclusive;

use aluvm::isa::{Bytecode, BytecodeError};
use aluvm::library::{CodeEofError, Read, Write};
use aluvm::reg::{Reg16, Reg32, RegS};
use amplify::num::{u1, u2};

use super::instr::*;
use super::{ContractOp, ContractStateAccess, RgbIsa};

impl<S: ContractStateAccess> Bytecode for RgbIsa<S> {
    fn instr_range() -> RangeInclusive<u8> { INSTR_RGBISA_FROM..=INSTR_RGBISA_TO }

    fn instr_byte(&self) -> u8 {
        match self {
            RgbIsa::Contract(op) => op.instr_byte(),
            RgbIsa::Fail(code) => *code,
        }
    }

    fn encode_args<W>(&self, writer: &mut W) -> Result<(), BytecodeError>
    where W: Write {
        match self {
            RgbIsa::Contract(op) => op.encode_args(writer),
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
            instr if ContractOp::<S>::instr_range().contains(&instr) => {
                RgbIsa::Contract(ContractOp::decode(reader)?)
            }
            INSTR_CONTRACT_TO..=INSTR_RGBISA_TO => RgbIsa::Fail(instr),
            _ => unreachable!(),
        })
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

// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2019-2024 Dr Maxim Orlovsky. All rights reserved.

use std::collections::BTreeSet;
use std::ops::RangeInclusive;

use aluvm::isa::{Bytecode, BytecodeRead, BytecodeWrite, CodeEofError, ExecStep, Instruction, InstructionSet};
use aluvm::regs::Reg;
use aluvm::{Core, LibId, Site, ISA_ALU128};

use crate::VmContext;

pub const ISA_RGB1: &str = "RGB1";

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Display)]
#[display(inner)]
#[non_exhaustive]
pub enum RgbInstr {
    #[display("halt    {0:#02X}:h")]
    Reserved(u8),
}

impl InstructionSet<LibId> for RgbInstr {
    const ISA: &'static str = ISA_ALU128;
    const ISA_EXT: &'static [&'static str] = &[ISA_RGB1];
    const HAS_EXT: bool = false;
    type Ext = Self;
    type Instr = Self;
}

impl Bytecode<LibId> for RgbInstr {
    fn op_range() -> RangeInclusive<u8> { todo!() }

    fn opcode_byte(&self) -> u8 { todo!() }

    fn encode_operands<W>(&self, writer: &mut W) -> Result<(), W::Error>
    where W: BytecodeWrite<LibId> {
        todo!()
    }

    fn decode_operands<R>(reader: &mut R, opcode: u8) -> Result<Self, CodeEofError>
    where
        Self: Sized,
        R: BytecodeRead<LibId>,
    {
        todo!()
    }
}

impl Instruction<LibId> for RgbInstr {
    type Context<'ctx> = VmContext<'ctx>;

    fn src_regs(&self) -> BTreeSet<Reg> { todo!() }

    fn dst_regs(&self) -> BTreeSet<Reg> { todo!() }

    fn op_data_bytes(&self) -> u16 { todo!() }

    fn ext_data_bytes(&self) -> u16 { todo!() }

    fn exec(&self, core: &mut Core<LibId>, site: Site<LibId>, context: &Self::Context<'_>) -> ExecStep<Site<LibId>> {
        todo!()
    }
}

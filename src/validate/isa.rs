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
use aluvm::regs::{IdxA, Reg, RegA};
use aluvm::{Core, LibId, Site, ISA_ALU128};
use amplify::num::u3;

use super::microcode::Microcode;
use crate::{AssignmentType, GlobalStateType, MetaType, VmContext};

pub const ISA_RGB1: &str = "RGB1";

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Display)]
#[display(inner)]
#[non_exhaustive]
pub enum RgbInstr {
    /// Count contract's global state items of a type.
    ///
    /// The global state type is taken from the constant operand `ty`; the resulting count is put
    /// into `a16` register with an index from operand `dst`.
    ///
    /// # Control registers
    ///
    /// - If the contract doesn't define any state of the given type, or it contains zero entries:
    ///   sets destination to `0`.
    /// - Doesn't change the value of check and fail registers `CK`, `CO`, `CF`.
    #[display("cn.c    A16{dst}, {ty}")]
    CnC {
        /// Index of a destination `A16` register to have the number of the state entries.
        dst: IdxA,
        /// Global state type to count.
        ty: GlobalStateType,
    },

    /// Count operation's global state items of a type.
    ///
    /// The global state type is taken from the constant operand `ty`; the resulting count is put
    /// into `a16` register with an index from operand `dst`.
    ///
    /// # Control registers
    ///
    /// - If the operation doesn't define any state of the given type: sets destination to `None`
    ///   and sets `CK` to a failed state.
    #[display("cn.g    A16{dst}, {ty}")]
    CnG {
        /// Index of a destination `A16` register to have the number of the state entries.
        dst: IdxA,
        /// Global state type to count.
        ty: GlobalStateType,
    },

    /// Count operation's input owned state items of a type.
    ///
    /// Operation input owned state is a state assigned to a seal defined in a previous operation,
    /// which is closed with the current operation.
    ///
    /// The assignment type is taken from the constant operand `ty`; the resulting count is put
    /// into `a16` register with an index from operand `dst`.
    ///
    /// # Control registers
    ///
    /// - If the operation doesn't define any state of the given type: sets destination to `None`
    ///   and sets `CK` to a failed state.
    #[display("cn.i    A16{dst}, {ty}")]
    CnI {
        /// Index of a destination `A16` register to have the number of the state entries.
        dst: IdxA,
        /// Assignment type to count owned state entries.
        ty: AssignmentType,
    },

    /// Count operation's output owned state items of a type.
    ///
    /// Operation output owned state is a state assigned to a single-use seals defined in this
    /// operation.
    ///
    /// The assignment type is taken from the constant operand `ty`; the resulting count is put
    /// into `a16` register with an index from operand `dst`.
    ///
    /// # Control registers
    ///
    /// - If the operation doesn't define any state of the given type: sets destination to `None`
    ///   and sets `CK` to a failed state.
    #[display("cn.o    A16{dst}, {ty}")]
    CnO {
        /// Index of a destination `A16` register to have the number of the state entries.
        dst: IdxA,
        /// Assignment type to count owned state entries.
        ty: AssignmentType,
    },

    /// Load a field element from the contract's global state of a given type.
    ///
    /// Contract global state is kept as stacks of entries, one stacks per each [`GlobalStateType`].
    /// The maximum size of the stack is fixed basing on the global state schema information, but it
    /// never exceeds `u16::MAX` items. Each completed operation pushes its global stack entries
    /// to the stack(s) of the corresponding type(s), and, in case of stack overflow, removes the
    /// overflowing elements from the bottom of the stack ("forgetting" old stack values).
    ///
    /// The `pos` operand defines the "depth" of the element loaded from the stack of type provided
    /// by the `ty` operand.
    ///
    /// Each global state item is represented by a number of elements of a finite field, from zero
    /// to 4 (at RGBv1.0). Operant `el` provides position for the element to load.
    ///
    /// # Control registers
    ///
    /// In all the following cases `CK` is set to a failed state and `dst` is set to `None`:
    /// - if `A16` `pos` register is set to `None`;
    /// - if a contract global state stack of type `ty` is not defined, an empty or has less than
    ///   `pos` elements;
    /// - if a global state item of type `ty` at position `pos` has less than `el` elements;
    /// - if the bit size of the field element used by the global state doesn't match the bit size
    ///   of the destination `A` register (either lower or bigger).
    ///
    /// In the last case (bit size mismatch between the state element and destination register)
    /// `CO` register is set to `true` (overflow/underflow).
    #[display("ld.c    {dst}, {ty}, A16{pos}, {el}")]
    LdC {
        /// Index of a destination `A` register to receive the finite field element value from the
        /// state.
        dst: RegA,
        /// Global state type to choose the element from.
        ty: GlobalStateType,
        /// `A16` register with the position of the global state (from the most recent one) to load.
        pos: IdxA,
        /// Element of a state within the verifiable state ([`VerifiableState`]) to load.
        el: u8,
    },

    /// Load a field element from the operation's global state of a given type.
    ///
    /// Operation global state is structured as a set of global state lists, one per
    /// [`GlobalStateType`]. Each of the lists may have up to `u16::MAX` items.
    ///
    /// NB: This is very different from the way the contract's global state is structured:
    /// operation's global state is not a stack but list, and the list size is not additionally
    /// limited in the maximal number of items by the global state schema.
    ///
    /// Operand `pos` defines a position within the global state list of a `ty` type.
    ///
    /// Each global state item is represented by a number of elements of a finite field, from zero
    /// to 4 (at RGBv1.0). Operant `el` provides position for the element to load.
    ///
    /// # Control registers
    ///
    /// In all the following cases `CK` is set to a failed state and `dst` is set to `None`:
    /// - if `A16` `pos` register is set to `None`;
    /// - if an operation's global state list of type `ty` is not defined, an empty or has less than
    ///   `pos` elements;
    /// - if a global state item of type `ty` at position `pos` has less than `el` elements;
    /// - if the bit size of the field element used by the global state doesn't match the bit size
    ///   of the destination `A` register (either lower or bigger).
    ///
    /// In the last case (bit size mismatch between the state element and destination register)
    /// `CO` register is set to `true` (overflow/underflow).
    #[display("ld.g    {dst}, {ty}, A16{pos}, {el}")]
    LdG {
        /// Index of a destination `A` register to receive the finite field element value from the
        /// state.
        dst: RegA,
        /// Global state type to choose the element from.
        ty: GlobalStateType,
        /// `A16` register with the position of the global state (from the most recent one) to load.
        pos: IdxA,
        /// Element of a state within the verifiable state ([`VerifiableState`]) to load.
        el: u8,
    },

    /// Load a field element from the operation's input owned state of a given type.
    ///
    /// Operation input owned state is a state assigned to a seal defined in a previous operation,
    /// which is closed with the current operation.
    ///
    /// Operation input owned state is structured as a set lists, one per [`AssignmentType`]. Each
    /// of the lists may have up to `u16::MAX` items. Operand `pos` defines a position within the
    /// input owned state list of a `ty` type. Each owned state item is represented by a number of
    /// elements of a finite field, from zero to 4 (at RGBv1.0). Operant `el` provides position
    /// for the element to load.
    ///
    /// # Control registers
    ///
    /// In all the following cases `CK` is set to a failed state and `dst` is set to `None`:
    /// - if `A16` `pos` register is set to `None`;
    /// - if an operation's input owned state list of type `ty` is not defined, an empty or has less
    ///   than `pos` elements;
    /// - if an input owned state item of type `ty` at position `pos` has less than `el` elements;
    /// - if the bit size of the field element used by the input owned state doesn't match the bit
    ///   size of the destination `A` register (either lower or bigger).
    ///
    /// In the last case (bit size mismatch between the state element and destination register)
    /// `CO` register is set to `true` (overflow/underflow).
    #[display("ld.i    {dst}, {ty}, A16{pos}, {el}")]
    LdI {
        /// Index of a destination `A` register to receive the finite field element value from the
        /// state.
        dst: RegA,
        /// Assignment state type to choose the element from.
        ty: AssignmentType,
        /// `A16` register with the position of the global state (from the most recent one) to load.
        pos: IdxA,
        /// Element of a state within the verifiable state ([`VerifiableState`]) to load.
        el: u8,
    },

    /// Load a field element from the operation's output owned state of a given type.
    ///
    /// Operation output owned state is a state assigned to a single-use seals defined in this
    /// operation.
    ///
    /// Operation output owned state is structured as a set lists, one per [`AssignmentType`]. Each
    /// of the lists may have up to `u16::MAX` items. Operand `pos` defines a position within the
    /// output owned state list of a `ty` type. Each owned state item is represented by a number of
    /// elements of a finite field, from zero to 4 (at RGBv1.0). Operant `el` provides position
    /// for the element to load.
    ///
    /// # Control registers
    ///
    /// In all the following cases `CK` is set to a failed state and `dst` is set to `None`:
    /// - if `A16` `pos` register is set to `None`;
    /// - if an operation's output owned state list of type `ty` is not defined, an empty or has
    ///   less than `pos` elements;
    /// - if an output owned state item of type `ty` at position `pos` has less than `el` elements;
    /// - if the bit size of the field element used by the output owned state doesn't match the bit
    ///   size of the destination `A` register (either lower or bigger).
    ///
    /// In the last case (bit size mismatch between the state element and destination register)
    /// `CO` register is set to `true` (overflow/underflow).
    #[display("ld.o    {dst}, {ty}, A16{pos}, {el}")]
    LdO {
        /// Index of a destination `A` register to receive the finite field element value from the
        /// state.
        dst: RegA,
        /// Assignment state type to choose the element from.
        ty: AssignmentType,
        /// `A16` register with the position of the global state (from the most recent one) to load.
        pos: IdxA,
        /// Element of a state within the verifiable state ([`VerifiableState`]) to load.
        el: u8,
    },

    /// Load a field element from the operation's metadata of a given type.
    ///
    /// Operation metadata are structured as a set of [`VerifiableState`], one per [`MetaType`].
    /// Each individual metadatum is represented by a number of elements of a finite field, from
    /// zero to 4 (at RGBv1.0). Operant `el` provides position for the element to load.
    ///
    /// # Control registers
    ///
    /// In all the following cases `CK` is set to a failed state and `dst` is set to `None`:
    /// - if `A16` `pos` register is set to `None`;
    /// - if an operation's metadatum of type `ty` is not defined;
    /// - if the metadatum of type `ty` has less than `el` elements;
    /// - if the bit size of the field element used by the metadatum doesn't match the bit size of
    ///   the destination `A` register (either lower or bigger).
    ///
    /// In the last case (bit size mismatch between the state element and destination register)
    /// `CO` register is set to `true` (overflow/underflow).
    #[display("ld.m    {dst}, {ty}, {el}")]
    LdM {
        /// Index of a destination `A` register to receive the finite field element value from the
        /// state.
        dst: RegA,
        /// Metadata type to choose the element from.
        ty: MetaType,
        /// Element of a state within the verifiable state ([`VerifiableState`]) to load.
        el: u8,
    },

    /// Operation reserved for future RGB instruction set architecture extensions (like `RGB2` etc).
    ///
    /// Halts execution and sets `CK` to a failed state.
    #[display("halt    {0:#02X}:h")]
    Reserved(u8),
}

impl RgbInstr {
    const START: u8 = 128;
    const END: u8 = Self::START + 16;
    const RGB1: u8 = 0;
    const META: u8 = 1;

    const SUBOP_CNC: u3 = u3::with(0);
    const SUBOP_CNG: u3 = u3::with(1);
    const SUBOP_CNI: u3 = u3::with(2);
    const SUBOP_CNO: u3 = u3::with(3);
    const SUBOP_LDC: u3 = u3::with(4);
    const SUBOP_LDG: u3 = u3::with(5);
    const SUBOP_LDI: u3 = u3::with(6);
    const SUBOP_LDO: u3 = u3::with(7);
}

impl InstructionSet<LibId> for RgbInstr {
    const ISA: &'static str = ISA_ALU128;
    const ISA_EXT: &'static [&'static str] = &[ISA_RGB1];
    const HAS_EXT: bool = false;
    type Ext = Self;
    type Instr = Self;
}

impl Instruction<LibId> for RgbInstr {
    type Context<'ctx> = VmContext<'ctx>;

    fn src_regs(&self) -> BTreeSet<Reg> {
        match *self {
            RgbInstr::CnC { dst: _, ty: _ }
            | RgbInstr::CnG { dst: _, ty: _ }
            | RgbInstr::CnI { dst: _, ty: _ }
            | RgbInstr::CnO { dst: _, ty: _ } => none!(),
            RgbInstr::LdC { dst: _, ty: _, pos, el: _ }
            | RgbInstr::LdG { dst: _, ty: _, pos, el: _ }
            | RgbInstr::LdI { dst: _, ty: _, pos, el: _ }
            | RgbInstr::LdO { dst: _, ty: _, pos, el: _ } => bset![RegA::A16(pos).into()],
            RgbInstr::LdM { dst: _, ty: _, el: _ } => none!(),
            RgbInstr::Reserved(_) => none!(),
        }
    }

    fn dst_regs(&self) -> BTreeSet<Reg> {
        match *self {
            RgbInstr::CnC { dst, ty: _ }
            | RgbInstr::CnG { dst, ty: _ }
            | RgbInstr::CnI { dst, ty: _ }
            | RgbInstr::CnO { dst, ty: _ } => bset![RegA::A16(dst).into()],
            RgbInstr::LdC { dst, ty: _, pos: _, el: _ }
            | RgbInstr::LdG { dst, ty: _, pos: _, el: _ }
            | RgbInstr::LdI { dst, ty: _, pos: _, el: _ }
            | RgbInstr::LdO { dst, ty: _, pos: _, el: _ } => bset![dst.into()],
            RgbInstr::LdM { dst: _, ty: _, el: _ } => none!(),
            RgbInstr::Reserved(_) => none!(),
        }
    }

    fn op_data_bytes(&self) -> u16 {
        match *self {
            RgbInstr::CnC { dst: _, ty: _ }
            | RgbInstr::CnG { dst: _, ty: _ }
            | RgbInstr::CnI { dst: _, ty: _ }
            | RgbInstr::CnO { dst: _, ty: _ } => 1,
            RgbInstr::LdC { dst: _, ty: _, pos: _, el: _ }
            | RgbInstr::LdG { dst: _, ty: _, pos: _, el: _ }
            | RgbInstr::LdI { dst: _, ty: _, pos: _, el: _ }
            | RgbInstr::LdO { dst: _, ty: _, pos: _, el: _ } => 2,
            RgbInstr::LdM { dst: _, ty: _, el: _ } => 2,
            RgbInstr::Reserved(_) => none!(),
        }
    }

    fn ext_data_bytes(&self) -> u16 { 0 }

    fn exec(&self, core: &mut Core<LibId>, _site: Site<LibId>, context: &Self::Context<'_>) -> ExecStep<Site<LibId>> {
        match *self {
            RgbInstr::CnC { dst, ty } => core.cnt(|| context.cnc(ty), dst),
            RgbInstr::CnG { dst, ty } => core.cn(|| context.cng(ty), dst),
            RgbInstr::CnI { dst, ty } => core.cn(|| context.cni(ty), dst),
            RgbInstr::CnO { dst, ty } => core.cn(|| context.cno(ty), dst),
            RgbInstr::LdC { dst, ty, pos, el } => core.rdild(|i| context.rdc(ty, i), dst, pos, el),
            RgbInstr::LdG { dst, ty, pos, el } => core.rdild(|i| context.rdg(ty, i), dst, pos, el),
            RgbInstr::LdI { dst, ty, pos, el } => core.rdild(|i| context.rdi(ty, i), dst, pos, el),
            RgbInstr::LdO { dst, ty, pos, el } => core.rdild(|i| context.rdo(ty, i), dst, pos, el),
            RgbInstr::LdM { dst, ty, el } => core.rdld(|| context.rdm(ty), dst, el),
            RgbInstr::Reserved(_) => ExecStep::FailHalt,
        }
    }
}

impl Bytecode<LibId> for RgbInstr {
    fn op_range() -> RangeInclusive<u8> { Self::START..=Self::END }

    fn opcode_byte(&self) -> u8 {
        match *self {
            RgbInstr::CnC { .. }
            | RgbInstr::CnG { .. }
            | RgbInstr::CnI { .. }
            | RgbInstr::CnO { .. }
            | RgbInstr::LdC { .. }
            | RgbInstr::LdG { .. }
            | RgbInstr::LdI { .. }
            | RgbInstr::LdO { .. } => Self::START + Self::RGB1,
            RgbInstr::LdM { .. } => Self::START + Self::META,
            RgbInstr::Reserved(op) => op,
        }
    }

    fn encode_operands<W>(&self, writer: &mut W) -> Result<(), W::Error>
    where W: BytecodeWrite<LibId> {
        match self {
            RgbInstr::CnC { .. } => writer.write_3bits(Self::SUBOP_CNC)?,
            RgbInstr::CnG { .. } => writer.write_3bits(Self::SUBOP_CNG)?,
            RgbInstr::CnI { .. } => writer.write_3bits(Self::SUBOP_CNI)?,
            RgbInstr::CnO { .. } => writer.write_3bits(Self::SUBOP_CNO)?,
            RgbInstr::LdC { .. } => writer.write_3bits(Self::SUBOP_LDC)?,
            RgbInstr::LdG { .. } => writer.write_3bits(Self::SUBOP_LDG)?,
            RgbInstr::LdI { .. } => writer.write_3bits(Self::SUBOP_LDI)?,
            RgbInstr::LdO { .. } => writer.write_3bits(Self::SUBOP_LDO)?,
            RgbInstr::LdM { .. } => {}
            RgbInstr::Reserved(_) => {}
        }

        match *self {
            RgbInstr::CnC { dst, ty } | RgbInstr::CnG { dst, ty } => {
                writer.write_5bits(dst.to_u5())?;
                writer.write_byte(ty.to_u8())?;
            }
            RgbInstr::CnI { dst, ty } | RgbInstr::CnO { dst, ty } => {
                writer.write_5bits(dst.to_u5())?;
                writer.write_byte(ty.to_u8())?;
            }
            RgbInstr::LdC { dst, ty, pos, el } | RgbInstr::LdG { dst, ty, pos, el } => {
                writer.write_byte(dst.to_u8())?;
                writer.write_byte(ty.to_u8())?;
                writer.write_5bits(pos.to_u5())?;
                writer.write_byte(el)?;
            }
            RgbInstr::LdI { dst, ty, pos, el } | RgbInstr::LdO { dst, ty, pos, el } => {
                writer.write_byte(dst.to_u8())?;
                writer.write_byte(ty.to_u8())?;
                writer.write_5bits(pos.to_u5())?;
                writer.write_byte(el)?;
            }
            RgbInstr::LdM { dst, ty, el } => {
                writer.write_byte(dst.to_u8())?;
                writer.write_byte(ty.to_u8())?;
                writer.write_byte(el)?;
            }
            RgbInstr::Reserved(_) => {}
        }

        Ok(())
    }

    fn decode_operands<R>(reader: &mut R, opcode: u8) -> Result<Self, CodeEofError>
    where
        Self: Sized,
        R: BytecodeRead<LibId>,
    {
        Ok(match opcode.overflowing_sub(Self::START) {
            (Self::RGB1, false) => {
                let subop = reader.read_3bits()?;
                match subop {
                    Self::SUBOP_CNC => {
                        let dst = IdxA::from(reader.read_5bits()?);
                        let ty = GlobalStateType::from(reader.read_byte()?);
                        Self::CnC { dst, ty }
                    }
                    Self::SUBOP_CNG => {
                        let dst = IdxA::from(reader.read_5bits()?);
                        let ty = GlobalStateType::from(reader.read_byte()?);
                        Self::CnG { dst, ty }
                    }
                    Self::SUBOP_CNI => {
                        let dst = IdxA::from(reader.read_5bits()?);
                        let ty = AssignmentType::from(reader.read_byte()?);
                        Self::CnI { dst, ty }
                    }
                    Self::SUBOP_CNO => {
                        let dst = IdxA::from(reader.read_5bits()?);
                        let ty = AssignmentType::from(reader.read_byte()?);
                        Self::CnO { dst, ty }
                    }

                    Self::SUBOP_LDC => {
                        let dst = RegA::from(reader.read_byte()?);
                        let ty = GlobalStateType::from(reader.read_byte()?);
                        let pos = IdxA::from(reader.read_5bits()?);
                        let el = reader.read_byte()?;
                        Self::LdC { dst, ty, pos, el }
                    }
                    Self::SUBOP_LDG => {
                        let dst = RegA::from(reader.read_byte()?);
                        let ty = GlobalStateType::from(reader.read_byte()?);
                        let pos = IdxA::from(reader.read_5bits()?);
                        let el = reader.read_byte()?;
                        Self::LdG { dst, ty, pos, el }
                    }
                    Self::SUBOP_LDI => {
                        let dst = RegA::from(reader.read_byte()?);
                        let ty = AssignmentType::from(reader.read_byte()?);
                        let pos = IdxA::from(reader.read_5bits()?);
                        let el = reader.read_byte()?;
                        Self::LdI { dst, ty, pos, el }
                    }
                    Self::SUBOP_LDO => {
                        let dst = RegA::from(reader.read_byte()?);
                        let ty = AssignmentType::from(reader.read_byte()?);
                        let pos = IdxA::from(reader.read_5bits()?);
                        let el = reader.read_byte()?;
                        Self::LdO { dst, ty, pos, el }
                    }
                    _ => unreachable!(),
                }
            }
            (Self::META, false) => {
                let dst = RegA::from(reader.read_byte()?);
                let ty = MetaType::from(reader.read_byte()?);
                let el = reader.read_byte()?;
                Self::LdM { dst, ty, el }
            }
            _ => Self::Reserved(opcode),
        })
    }
}

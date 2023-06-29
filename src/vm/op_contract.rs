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
use aluvm::reg::{CoreRegs, Reg16, RegA, RegS};
use amplify::num::u4;
use amplify::Wrapper;
use commit_verify::{Digest, Sha256};
use secp256k1_zkp::Tweak;
use strict_encoding::StrictSerialize;

use super::opcodes::*;
use crate::validation::OpInfo;
use crate::{Assign, TypedAssigns};

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
pub enum ContractOp {
    /// Counts number of inputs (previous state entries) of the provided type
    /// and assigns the number to the destination `a16` register.
    #[display("cnp      {0},a16{1}")]
    CnP(u16, Reg16),

    /// Counts number of outputs (owned state entries) of the provided type
    /// and assigns the number to the destination `a16` register.
    #[display("cns      {0},a16{1}")]
    CnS(u16, Reg16),

    /// Counts number of inputs (previous state entries) of the provided type
    /// and assigns the number to the destination `a8` register.
    #[display("cng      {0},a8{1}")]
    CnG(u16, Reg16),

    /// Counts number of inputs (previous state entries) of the provided type
    /// and assigns the number to the destination `a16` register.
    #[display("cnc      {0},a16{1}")]
    CnC(u16, Reg16),

    /// Loads input (previous) state with type id from the first argument and
    /// index from the second argument into a register provided in the third
    /// argument.
    ///
    /// If the state is absent or is not a structured state sets `st0` to
    /// `false` and terminates the program.
    ///
    /// If the state at the index is concealed, sets destination to `None`.
    #[display("ldp      {0},{1},{2}")]
    LdP(u16, u16, RegS),

    /// Loads owned structured state with type id from the first argument and
    /// index from the second argument into a register provided in the third
    /// argument.
    ///
    /// If the state is absent or is not a structured state sets `st0` to
    /// `false` and terminates the program.
    ///
    /// If the state at the index is concealed, sets destination to `None`.
    #[display("lds      {0},{1},{2}")]
    LdS(u16, u16, RegS),

    /// Loads owned fungible state with type id from the first argument and
    /// index from the second argument into `a64` register provided in the third
    /// argument.
    ///
    /// If the state is absent or is not a fungible state sets `st0` to
    /// `false` and terminates the program.
    ///
    /// If the state at the index is concealed, sets destination to `None`.
    #[display("ldf      {0},{1},a64{2}")]
    LdF(u16, u16, Reg16),

    /// Loads global state from the current operation with type id from the
    /// first argument and index from the second argument into a register
    /// provided in the third argument.
    ///
    /// If the state is absent sets `st0` to `false` and terminates the program.
    #[display("ldg      {0},{1},{2}")]
    LdG(u16, u8, RegS),

    /// Loads part of the contract global state with type id from the first
    /// argument at the depth from the second argument into a register
    /// provided in the third argument.
    ///
    /// If the state is absent or concealed sets destination to `None`.
    /// Does not modify content of `st0` register.
    #[display("ldc      {0},{1},{2}")]
    LdC(u16, u16, RegS),

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

    /// Verifies equivalence of a sum of pedersen commitments for the list of
    /// outputs with a given owned state type against a value taken from a
    /// global state.
    ///
    /// The first argument specifies owned state type for the sum operation. If
    /// this state does not exists, either inputs or outputs does not have
    /// any data for the state, or the state is not
    /// of `FungibleState::Bits64` fails the verification.
    ///
    /// The second argument specifies global state type. If the state does not
    /// exist, there is more than one value, or it is not a u64 value, the
    /// verification fails.
    ///
    /// If verification succeeds, doesn't changes `st0` value; otherwise sets it
    /// to `false`.
    #[display("pccs     {0},{1}")]
    PcCs(/** owned state type */ u16, /** global state type */ u16),

    /// All other future unsupported operations, which must set `st0` to
    /// `false`.
    #[display("fail     {0}")]
    Fail(u8),
}

impl InstructionSet for ContractOp {
    type Context<'ctx> = OpInfo<'ctx>;

    fn isa_ids() -> BTreeSet<&'static str> { none!() }

    fn exec(&self, regs: &mut CoreRegs, site: LibSite, context: &Self::Context<'_>) -> ExecStep {
        macro_rules! fail {
            () => {{
                isa::ControlFlowOp::Fail.exec(regs, site, &());
                return ExecStep::Stop;
            }};
        }
        macro_rules! load_inputs {
            ($state_type:ident) => {{
                if !context.prev_state.contains_key($state_type) {
                    return ExecStep::Next;
                }
                let Some(prev_state) = context.prev_state.get($state_type) else {
                    fail!()
                };
                match prev_state {
                    TypedAssigns::Fungible(state) => state
                        .iter()
                        .map(Assign::to_confidential_state)
                        .map(|s| s.commitment.into_inner())
                        .collect::<Vec<_>>(),
                    _ => fail!(),
                }
            }};
        }
        macro_rules! load_outputs {
            ($state_type:ident) => {{
                if !context.owned_state.has_type(*$state_type) {
                    return ExecStep::Next;
                }
                let Some(new_state) = context.owned_state.get(*$state_type) else {
                    fail!()
                };
                match new_state {
                    TypedAssigns::Fungible(state) => state
                        .iter()
                        .map(Assign::to_confidential_state)
                        .map(|s| s.commitment.into_inner())
                        .collect::<Vec<_>>(),
                    _ => fail!(),
                }
            }};
        }

        match self {
            ContractOp::CnP(state_type, reg) => {
                regs.set(RegA::A16, *reg, context.prev_state.get(state_type).map(|a| a.len_u16()));
            }
            ContractOp::CnS(state_type, reg) => {
                regs.set(
                    RegA::A16,
                    *reg,
                    context.owned_state.get(*state_type).map(|a| a.len_u16()),
                );
            }
            ContractOp::CnG(state_type, reg) => {
                regs.set(RegA::A16, *reg, context.global.get(state_type).map(|a| a.len_u16()));
            }
            ContractOp::CnC(_state_type, _reg) => {
                // TODO: implement global contract state
                fail!()
            }
            ContractOp::LdP(state_type, index, reg) => {
                let Some(Ok(state)) = context
                    .prev_state
                    .get(state_type)
                    .map(|a| a.as_structured_state_at(*index))
                else {
                    fail!()
                };
                let state = state.map(|s| {
                    s.to_strict_serialized::<{ u16::MAX as usize }>()
                        .expect("type guarantees")
                });
                regs.set_s(*reg, state);
            }
            ContractOp::LdS(state_type, index, reg) => {
                let Some(Ok(state)) = context
                    .owned_state
                    .get(*state_type)
                    .map(|a| a.into_structured_state_at(*index))
                else {
                    fail!()
                };
                let state = state.map(|s| {
                    s.to_strict_serialized::<{ u16::MAX as usize }>()
                        .expect("type guarantees")
                });
                regs.set_s(*reg, state);
            }
            ContractOp::LdF(state_type, index, reg) => {
                let Some(Ok(state)) = context
                    .owned_state
                    .get(*state_type)
                    .map(|a| a.into_fungible_state_at(*index))
                else {
                    fail!()
                };
                regs.set(RegA::A64, *reg, state.map(|s| s.value.as_u64()));
            }
            ContractOp::LdG(state_type, index, reg) => {
                let Some(state) = context
                    .global
                    .get(state_type)
                    .and_then(|a| a.get(*index as usize))
                else {
                    fail!()
                };
                regs.set_s(*reg, Some(state.as_inner()));
            }
            ContractOp::LdC(_state_type, _index, _reg) => {
                // TODO: implement global contract state
                fail!()
            }
            ContractOp::LdM(reg) => {
                regs.set_s(*reg, Some(context.metadata));
            }

            ContractOp::PcVs(state_type) => {
                let inputs = load_inputs!(state_type);
                let outputs = load_outputs!(state_type);
                if !secp256k1_zkp::verify_commitments_sum_to_equal(
                    secp256k1_zkp::SECP256K1,
                    &inputs,
                    &outputs,
                ) {
                    fail!()
                }
            }

            ContractOp::PcCs(owned_state, global_state) => {
                let Some(sum) = context.global.get(global_state) else {
                    fail!()
                };
                if sum.len() != 1 {
                    fail!()
                }
                if sum[0].as_inner().len() != 8 {
                    fail!()
                }
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(sum[0].as_inner());
                let sum = u64::from_le_bytes(bytes);

                // TODO: Check that we create correct generator value.
                let one_key = secp256k1_zkp::SecretKey::from_slice(&secp256k1_zkp::constants::ONE)
                    .expect("secret key from a constant");
                let g =
                    secp256k1_zkp::PublicKey::from_secret_key(secp256k1_zkp::SECP256K1, &one_key);
                let h: [u8; 32] = Sha256::digest(&g.serialize_uncompressed()).into();
                let tag = secp256k1_zkp::Tag::from(h);
                let generator =
                    secp256k1_zkp::Generator::new_unblinded(secp256k1_zkp::SECP256K1, tag);
                let inputs = vec![secp256k1_zkp::PedersenCommitment::new(
                    secp256k1_zkp::SECP256K1,
                    sum,
                    Tweak::default(),
                    generator,
                )];

                let outputs = load_outputs!(owned_state);
                if !secp256k1_zkp::verify_commitments_sum_to_equal(
                    secp256k1_zkp::SECP256K1,
                    &inputs,
                    &outputs,
                ) {
                    fail!()
                }
            }

            // All other future unsupported operations, which must set `st0` to `false`.
            _ => fail!(),
        }
        ExecStep::Next
    }
}

impl Bytecode for ContractOp {
    fn byte_count(&self) -> u16 {
        match self {
            ContractOp::CnP(_, _) |
            ContractOp::CnS(_, _) |
            ContractOp::CnG(_, _) |
            ContractOp::CnC(_, _) => 3,

            ContractOp::LdP(_, _, _) |
            ContractOp::LdS(_, _, _) |
            ContractOp::LdF(_, _, _) |
            ContractOp::LdC(_, _, _) => 5,
            ContractOp::LdG(_, _, _) => 4,
            ContractOp::LdM(_) => 1,

            ContractOp::PcVs(_) => 2,
            ContractOp::PcCs(_, _) => 4,

            ContractOp::Fail(_) => 0,
        }
    }

    fn instr_range() -> RangeInclusive<u8> { INSTR_CNP..=0b11_001_111 }

    fn instr_byte(&self) -> u8 {
        match self {
            ContractOp::CnP(_, _) => INSTR_CNP,
            ContractOp::CnS(_, _) => INSTR_CNS,
            ContractOp::CnG(_, _) => INSTR_CNG,
            ContractOp::CnC(_, _) => INSTR_CNC,

            ContractOp::LdP(_, _, _) => INSTR_LDP,
            ContractOp::LdS(_, _, _) => INSTR_LDS,
            ContractOp::LdF(_, _, _) => INSTR_LDF,
            ContractOp::LdG(_, _, _) => INSTR_LDG,
            ContractOp::LdC(_, _, _) => INSTR_LDC,
            ContractOp::LdM(_) => INSTR_LDM,

            ContractOp::PcVs(_) => INSTR_PCVS,
            ContractOp::PcCs(_, _) => INSTR_PCCS,

            ContractOp::Fail(other) => *other,
        }
    }

    fn encode_args<W>(&self, writer: &mut W) -> Result<(), BytecodeError>
    where W: Write {
        match self {
            ContractOp::CnP(state_type, reg) => {
                writer.write_u16(*state_type)?;
                writer.write_u4(reg)?;
                writer.write_u4(u4::ZERO)?;
            }
            ContractOp::CnS(state_type, reg) => {
                writer.write_u16(*state_type)?;
                writer.write_u4(reg)?;
                writer.write_u4(u4::ZERO)?;
            }
            ContractOp::CnG(state_type, reg) => {
                writer.write_u16(*state_type)?;
                writer.write_u4(reg)?;
                writer.write_u4(u4::ZERO)?;
            }
            ContractOp::CnC(state_type, reg) => {
                writer.write_u16(*state_type)?;
                writer.write_u4(reg)?;
                writer.write_u4(u4::ZERO)?;
            }
            ContractOp::LdP(state_type, index, reg) => {
                writer.write_u16(*state_type)?;
                writer.write_u16(*index)?;
                writer.write_u4(reg)?;
                writer.write_u4(u4::ZERO)?;
            }
            ContractOp::LdS(state_type, index, reg) => {
                writer.write_u16(*state_type)?;
                writer.write_u16(*index)?;
                writer.write_u4(reg)?;
                writer.write_u4(u4::ZERO)?;
            }
            ContractOp::LdF(state_type, index, reg) => {
                writer.write_u16(*state_type)?;
                writer.write_u16(*index)?;
                writer.write_u4(reg)?;
                writer.write_u4(u4::ZERO)?;
            }
            ContractOp::LdG(state_type, index, reg) => {
                writer.write_u16(*state_type)?;
                writer.write_u8(*index)?;
                writer.write_u4(reg)?;
                writer.write_u4(u4::ZERO)?;
            }
            ContractOp::LdC(state_type, index, reg) => {
                writer.write_u16(*state_type)?;
                writer.write_u16(*index)?;
                writer.write_u4(reg)?;
                writer.write_u4(u4::ZERO)?;
            }
            ContractOp::LdM(reg) => {
                writer.write_u4(reg)?;
                writer.write_u4(u4::ZERO)?;
            }

            ContractOp::PcVs(state_type) => writer.write_u16(*state_type)?,
            ContractOp::PcCs(owned_type, global_type) => {
                writer.write_u16(*owned_type)?;
                writer.write_u16(*global_type)?;
            }

            ContractOp::Fail(_) => {}
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
                let i = Self::LdP(reader.read_u16()?, reader.read_u16()?, reader.read_u4()?.into());
                reader.read_u4()?; // Discard garbage bits
                i
            }
            INSTR_LDS => {
                let i = Self::LdS(reader.read_u16()?, reader.read_u16()?, reader.read_u4()?.into());
                reader.read_u4()?; // Discard garbage bits
                i
            }
            INSTR_LDF => {
                let i = Self::LdF(reader.read_u16()?, reader.read_u16()?, reader.read_u4()?.into());
                reader.read_u4()?; // Discard garbage bits
                i
            }
            INSTR_LDG => {
                let i = Self::LdG(reader.read_u16()?, reader.read_u8()?, reader.read_u4()?.into());
                reader.read_u4()?; // Discard garbage bits
                i
            }
            INSTR_LDC => {
                let i = Self::LdC(reader.read_u16()?, reader.read_u16()?, reader.read_u4()?.into());
                reader.read_u4()?; // Discard garbage bits
                i
            }
            INSTR_LDM => {
                let i = Self::LdM(reader.read_u4()?.into());
                reader.read_u4()?; // Discard garbage bits
                i
            }

            INSTR_PCVS => Self::PcVs(reader.read_u16()?),
            INSTR_PCCS => Self::PcCs(reader.read_u16()?, reader.read_u16()?),

            x => Self::Fail(x),
        })
    }
}

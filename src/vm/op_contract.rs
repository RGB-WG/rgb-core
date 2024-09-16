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
use commit_verify::CommitVerify;

use super::opcodes::*;
use super::{ContractStateAccess, VmContext};
use crate::{
    Assign, AssignmentType, BlindingFactor, GlobalStateType, MetaType, PedersenCommitment,
    RevealedValue, TypedAssigns,
};

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
pub enum ContractOp<S: ContractStateAccess> {
    /// Counts number of inputs (previous state entries) of the provided type
    /// and puts the number to the destination `a16` register.
    ///
    /// If the operation doesn't contain inputs with a given assignment type,
    /// sets destination index to zero. Does not change `st0` register.
    #[display("cnp     {0},a16{1}")]
    CnP(AssignmentType, Reg32),

    /// Counts number of outputs (owned state entries) of the provided type
    /// and puts the number to the destination `a16` register.
    ///
    /// If the operation doesn't contain inputs with a given assignment type,
    /// sets destination index to zero. Does not change `st0` register.
    #[display("cns     {0},a16{1}")]
    CnS(AssignmentType, Reg32),

    /// Counts number of global state items of the provided type affected by the
    /// current operation and puts the number to the destination `a8` register.
    ///
    /// If the operation doesn't contain inputs with a given assignment type,
    /// sets destination index to zero. Does not change `st0` register.
    #[display("cng     {0},a8{1}")]
    CnG(GlobalStateType, Reg32),

    /// Counts number of global state items of the provided type in the contract
    /// state and puts the number to the destination `a32` register.
    ///
    /// If the operation doesn't contain inputs with a given assignment type,
    /// sets destination index to zero. Does not change `st0` register.
    #[display("cnc     {0},a32{1}")]
    CnC(GlobalStateType, Reg32),

    /// Loads input (previous) structured state with type id from the first
    /// argument and index from the second argument `a16` register into a
    /// register provided in the third argument.
    ///
    /// If the state is absent or is not a structured state sets `st0` to
    /// `false` and terminates the program.
    ///
    /// If the state at the index is concealed, sets destination to `None`.
    #[display("ldp     {0},a16{1},{2}")]
    LdP(AssignmentType, Reg16, RegS),

    /// Loads owned structured state with type id from the first argument and
    /// index from the second argument `a16` register into a register provided
    /// in the third argument.
    ///
    /// If the state is absent or is not a structured state sets `st0` to
    /// `false` and terminates the program.
    ///
    /// If the state at the index is concealed, sets destination to `None`.
    #[display("lds     {0},a16{1},{2}")]
    LdS(AssignmentType, Reg16, RegS),

    /// Loads owned fungible state with type id from the first argument and
    /// index from the second argument `a16` register into `a64` register
    /// provided in the third argument.
    ///
    /// If the state is absent or is not a fungible state sets `st0` to
    /// `false` and terminates the program.
    ///
    /// If the state at the index is concealed, sets destination to `None`.
    #[display("ldf     {0},a16{1},a64{2}")]
    LdF(AssignmentType, Reg16, Reg16),

    /// Loads global state from the current operation with type id from the
    /// first argument and index from the second argument `a8` register into a
    /// register provided in the third argument.
    ///
    /// If the state is absent sets `st0` to `false` and terminates the program.
    #[display("ldg     {0},a8{1},{2}")]
    LdG(GlobalStateType, Reg16, RegS),

    /// Loads part of the contract global state with type id from the first
    /// argument at the depth from the second argument `a32` register into a
    /// register provided in the third argument.
    ///
    /// If the contract doesn't have the provided global state type, or it
    /// doesn't contain a value at the requested index, sets `st0`
    /// to fail state and terminates the program. The value of the
    /// destination register is not changed.
    #[display("ldc     {0},a32{1},{2}")]
    LdC(GlobalStateType, Reg16, RegS),

    /// Loads operation metadata with a type id from the first argument into a
    /// register provided in the second argument.
    ///
    /// If the operation doesn't have metadata, sets `st0` to fail state and
    /// terminates the program. The value of the destination register is not
    /// changed.
    #[display("ldm     {0},{1}")]
    LdM(MetaType, RegS),

    /// Verify sum of inputs and outputs are equal.
    ///
    /// The only argument specifies owned state type for the sum operation. If
    /// this state does not exist, or either inputs or outputs does not have
    /// any data for the state, the verification fails.
    ///
    /// If verification succeeds, doesn't change `st0` value; otherwise sets it
    /// to `false` and stops execution.
    #[display("svs    {0}")]
    Svs(AssignmentType),

    /// Verify sum of outputs and value in `a64[0]` register are equal.
    ///
    /// The first argument specifies owned state type for the sum operation. If
    /// this state does not exist, or either inputs or outputs does not have
    /// any data for the state, the verification fails.
    ///
    /// If `a64[0]` register does not contain value, the verification fails.
    ///
    /// If verification succeeds, doesn't change `st0` value; otherwise sets it
    /// to `false` and stops execution.
    #[display("sas    {0}")]
    Sas(/** owned state type */ AssignmentType),

    /// Verify sum of inputs and value in `a64[0]` register are equal.
    ///
    /// The first argument specifies owned state type for the sum operation. If
    /// this state does not exist, or either inputs or outputs does not have
    /// any data for the state, the verification fails.
    ///
    /// If `a64[0]` register does not contain value, the verification fails.
    ///
    /// If verification succeeds, doesn't change `st0` value; otherwise sets it
    /// to `false` and stops execution.
    #[display("sps    {0}")]
    Sps(/** owned state type */ AssignmentType),

    /// Verify sum of pedersen commitments from inputs and outputs.
    ///
    /// The only argument specifies owned state type for the sum operation. If
    /// this state does not exist, or either inputs or outputs does not have
    /// any data for the state, the verification fails.
    ///
    /// If verification succeeds, doesn't change `st0` value; otherwise sets it
    /// to `false` and stops execution.
    #[display("pcvs    {0}")]
    Pcvs(AssignmentType),

    /// Verifies equivalence of a sum of pedersen commitments for the list of
    /// assignment outputs to a value from `a64[0]` register.
    ///
    /// The first argument specifies owned state type for the sum operation. If
    /// this state does not exist, or either inputs or outputs does not have
    /// any data for the state, the verification fails.
    ///
    /// If `a64[0]` register does not contain value, the verification fails.
    ///
    /// If verification succeeds, doesn't change `st0` value; otherwise sets it
    /// to `false` and stops execution.
    #[display("pcas    {0}")]
    Pcas(/** owned state type */ AssignmentType),

    /// Verifies equivalence of a sum of pedersen commitments for the list of
    /// inputs to a value from `a64[0]` register.
    ///
    /// The first argument specifies owned state type for the sum operation. If
    /// this state does not exist, or either inputs or outputs does not have
    /// any data for the state, the verification fails.
    ///
    /// If `a64[0]` register does not contain value, the verification fails.
    ///
    /// If verification succeeds, doesn't change `st0` value; otherwise sets it
    /// to `false` and stops execution.
    #[display("pcps    {0}")]
    Pcps(/** owned state type */ AssignmentType),

    /// All other future unsupported operations, which must set `st0` to
    /// `false` and stop the execution.
    #[display("fail    {0}")]
    Fail(u8, PhantomData<S>),
}

impl<S: ContractStateAccess> InstructionSet for ContractOp<S> {
    type Context<'ctx> = VmContext<'ctx, S>;

    fn isa_ids() -> IsaSeg { IsaSeg::with("RGB") }

    fn src_regs(&self) -> BTreeSet<Reg> {
        match self {
            ContractOp::LdP(_, reg, _)
            | ContractOp::LdF(_, reg, _)
            | ContractOp::LdS(_, reg, _) => bset![Reg::A(RegA::A16, (*reg).into())],
            ContractOp::LdG(_, reg, _) => bset![Reg::A(RegA::A8, (*reg).into())],
            ContractOp::LdC(_, reg, _) => bset![Reg::A(RegA::A32, (*reg).into())],

            ContractOp::CnP(_, _)
            | ContractOp::CnS(_, _)
            | ContractOp::CnG(_, _)
            | ContractOp::CnC(_, _)
            | ContractOp::LdM(_, _) => bset![],
            ContractOp::Pcvs(_) => bset![],
            ContractOp::Pcas(_) | ContractOp::Pcps(_) => bset![Reg::A(RegA::A64, Reg32::Reg0)],
            ContractOp::Svs(_) => bset![],
            ContractOp::Sas(_) | ContractOp::Sps(_) => bset![Reg::A(RegA::A64, Reg32::Reg0)],
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
            ContractOp::LdF(_, _, reg) => {
                bset![Reg::A(RegA::A64, (*reg).into())]
            }
            ContractOp::LdG(_, _, reg)
            | ContractOp::LdS(_, _, reg)
            | ContractOp::LdP(_, _, reg)
            | ContractOp::LdC(_, _, reg)
            | ContractOp::LdM(_, reg) => {
                bset![Reg::S(*reg)]
            }
            ContractOp::Pcvs(_) | ContractOp::Pcas(_) | ContractOp::Pcps(_) => {
                bset![]
            }
            ContractOp::Svs(_) | ContractOp::Sas(_) | ContractOp::Sps(_) => {
                bset![]
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
            | ContractOp::LdF(_, _, _)
            | ContractOp::LdG(_, _, _)
            | ContractOp::LdC(_, _, _) => 8,
            ContractOp::LdM(_, _) => 6,
            // TODO: what are the proper values for complexity?
            ContractOp::Svs(_)
            | ContractOp::Sas(_)
            | ContractOp::Sps(_) => 20,
            ContractOp::Pcvs(_) => 1024,
            ContractOp::Pcas(_) | ContractOp::Pcps(_) => 512,
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
        macro_rules! load_inputs {
            ($state_type:ident) => {{
                let Some(prev_state) = context.op_info.prev_state.get($state_type) else {
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
                let Some(new_state) = context.op_info.owned_state.get(*$state_type) else {
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
        macro_rules! load_revealed_inputs {
            ($state_type:ident) => {{
                let Some(prev_state) = context.op_info.prev_state.get($state_type) else {
                    fail!()
                };
                match prev_state {
                    TypedAssigns::Fungible(state) => state
                        .iter()
                        .map(Assign::as_revealed_state)
                        // TODO: properly fail if we can't read revealed state
                        .map(|s| s.unwrap().value.as_u64())
                        .collect::<Vec<_>>(),
                    _ => fail!(),
                }
            }};
        }
        macro_rules! load_revealed_outputs {
            ($state_type:ident) => {{
                let Some(new_state) = context.op_info.owned_state.get(*$state_type) else {
                    fail!()
                };
                match new_state {
                    TypedAssigns::Fungible(state) => state
                        .iter()
                        .map(Assign::as_revealed_state)
                        // TODO: properly fail if we can't read revealed state
                        .map(|s| s.unwrap().value.as_u64())
                        .collect::<Vec<_>>(),
                    _ => fail!(),
                }
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

                let Some(Ok(state)) = context
                    .op_info
                    .prev_state
                    .get(state_type)
                    .map(|a| a.as_structured_state_at(index))
                else {
                    fail!()
                };
                let state = state.map(|s| s.value.as_inner());
                regs.set_s(*reg, state);
            }
            ContractOp::LdS(state_type, reg_32, reg) => {
                let Some(reg_32) = *regs.get_n(RegA::A16, *reg_32) else {
                    fail!()
                };
                let index: u16 = reg_32.into();

                let Some(Ok(state)) = context
                    .op_info
                    .owned_state
                    .get(*state_type)
                    .map(|a| a.into_structured_state_at(index))
                else {
                    fail!()
                };
                let state = state.map(|s| s.value.into_inner());
                regs.set_s(*reg, state);
            }
            ContractOp::LdF(state_type, reg_32, reg) => {
                let Some(reg_32) = *regs.get_n(RegA::A16, *reg_32) else {
                    fail!()
                };
                let index: u16 = reg_32.into();

                let Some(Ok(state)) = context
                    .op_info
                    .owned_state
                    .get(*state_type)
                    .map(|a| a.into_fungible_state_at(index))
                else {
                    fail!()
                };
                regs.set_n(RegA::A64, *reg, state.map(|s| s.value.as_u64()));
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
                regs.set_s(*reg_s, Some(state.as_inner()));
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
                regs.set_s(*reg_s, Some(state.borrow().as_inner()));
            }
            ContractOp::LdM(type_id, reg) => {
                let Some(meta) = context.op_info.metadata.get(type_id) else {
                    fail!()
                };
                regs.set_s(*reg, Some(meta.to_inner()));
            }

            ContractOp::Pcvs(state_type) => {
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

            ContractOp::Pcas(owned_state) => {
                let Some(sum) = *regs.get_n(RegA::A64, Reg32::Reg0) else {
                    fail!()
                };
                let sum = u64::from(sum);

                let Some(tag) = context.asset_tags.get(owned_state) else {
                    fail!()
                };
                let sum = RevealedValue::with_blinding(sum, BlindingFactor::EMPTY, *tag);

                let inputs = [PedersenCommitment::commit(&sum).into_inner()];
                let outputs = load_outputs!(owned_state);

                if !secp256k1_zkp::verify_commitments_sum_to_equal(
                    secp256k1_zkp::SECP256K1,
                    &inputs,
                    &outputs,
                ) {
                    fail!()
                }
            }

            ContractOp::Pcps(owned_state) => {
                let Some(sum) = *regs.get_n(RegA::A64, Reg32::Reg0) else {
                    fail!()
                };
                let sum = u64::from(sum);

                let Some(tag) = context.asset_tags.get(owned_state) else {
                    fail!()
                };
                let sum = RevealedValue::with_blinding(sum, BlindingFactor::EMPTY, *tag);

                let inputs = [PedersenCommitment::commit(&sum).into_inner()];
                let outputs = load_inputs!(owned_state);

                if !secp256k1_zkp::verify_commitments_sum_to_equal(
                    secp256k1_zkp::SECP256K1,
                    &inputs,
                    &outputs,
                ) {
                    fail!()
                }
            }
            ContractOp::Svs(state_type) => {
                let Some(input_amt) = load_revealed_inputs!(state_type)
                    .iter()
                    .try_fold(0u64, |acc, &x| acc.checked_add(x))
                else {
                    fail!()
                };
                let Some(output_amt) = load_revealed_outputs!(state_type)
                    .iter()
                    .try_fold(0u64, |acc, &x| acc.checked_add(x))
                else {
                    fail!()
                };
                if input_amt != output_amt {
                    fail!()
                }
            }

            ContractOp::Sas(owned_state) => {
                let Some(sum) = *regs.get_n(RegA::A64, Reg32::Reg0) else {
                    fail!()
                };
                let sum = u64::from(sum);

                let Some(output_amt) = load_revealed_outputs!(owned_state)
                    .iter()
                    .try_fold(0u64, |acc, &x| acc.checked_add(x))
                else {
                    fail!()
                };

                if sum != output_amt {
                    fail!()
                }
            }

            ContractOp::Sps(owned_state) => {
                let Some(sum) = *regs.get_n(RegA::A64, Reg32::Reg0) else {
                    fail!()
                };
                let sum = u64::from(sum);

                let Some(input_amt) = load_revealed_inputs!(owned_state)
                    .iter()
                    .try_fold(0u64, |acc, &x| acc.checked_add(x))
                else {
                    fail!()
                };

                if sum != input_amt {
                    fail!()
                }
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
            ContractOp::LdF(_, _, _) => INSTR_LDF,
            ContractOp::LdC(_, _, _) => INSTR_LDC,
            ContractOp::LdM(_, _) => INSTR_LDM,

            ContractOp::Pcvs(_) => INSTR_PCVS,
            ContractOp::Pcas(_) => INSTR_PCAS,
            ContractOp::Pcps(_) => INSTR_PCPS,

            ContractOp::Svs(_) => INSTR_SVS,
            ContractOp::Sas(_) => INSTR_SAS,
            ContractOp::Sps(_) => INSTR_SPS,

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
            ContractOp::LdF(state_type, reg_a, reg_dst) => {
                writer.write_u16(*state_type)?;
                writer.write_u4(reg_a)?;
                writer.write_u4(reg_dst)?;
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

            ContractOp::Pcvs(state_type)
            | ContractOp::Svs(state_type) => writer.write_u16(*state_type)?,
            ContractOp::Pcas(owned_type)
            | ContractOp::Sas(owned_type)  => writer.write_u16(*owned_type)?,
            ContractOp::Pcps(owned_type)
            | ContractOp::Sps(owned_type)  => writer.write_u16(*owned_type)?,

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
            INSTR_LDF => Self::LdF(
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

            INSTR_PCVS => Self::Pcvs(reader.read_u16()?.into()),
            INSTR_PCAS => Self::Pcas(reader.read_u16()?.into()),
            INSTR_PCPS => Self::Pcps(reader.read_u16()?.into()),

            INSTR_SVS => Self::Svs(reader.read_u16()?.into()),
            INSTR_SAS => Self::Sas(reader.read_u16()?.into()),
            INSTR_SPS => Self::Sps(reader.read_u16()?.into()),

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

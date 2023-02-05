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

/*
use std::collections::BTreeSet;
use std::ops::RangeInclusive;

use aluvm::isa::{Bytecode, BytecodeError, ExecStep, InstructionSet};
use aluvm::program::{CodeEofError, LibSite, Read, Write};
use aluvm::reg::CoreRegs;
use aluvm::Vm;
 */

use crate::validation::Failure;
use crate::{Metadata, NodeId, NodeSubtype, OwnedRights, PublicRights, Validate};

/*
pub const INSTR_NOOP: u8 = 0b11_000_000;
pub const INSTR_ISAE_FROM: u8 = 0b11_000_000;
pub const INSTR_ISAE_TO: u8 = 0b11_000_000;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
pub enum RgbIsa {
    #[display("noop")]
    Noop,
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
            RgbIsa::Noop => 0,
        }
    }

    fn instr_range() -> RangeInclusive<u8> { INSTR_ISAE_FROM..=INSTR_ISAE_TO }

    fn instr_byte(&self) -> u8 {
        match self {
            Self::Noop => INSTR_NOOP,
        }
    }

    fn encode_args<W>(&self, _writer: &mut W) -> Result<(), BytecodeError>
    where W: Write {
        match self {
            RgbIsa::Noop => {}
        }
        Ok(())
    }

    fn decode<R>(reader: &mut R) -> Result<Self, CodeEofError>
    where
        Self: Sized,
        R: Read,
    {
        Ok(match reader.read_u8()? {
            INSTR_NOOP => Self::Noop,
            _ => Self::Noop,
        })
    }
}
*/

pub type ValidationScript = Vec<u8>; // aluvm::Program<RgbIsa>;

pub struct Runtime<'script> {
    #[allow(dead_code)]
    script: &'script ValidationScript,
}

impl<'script> Runtime<'script> {
    pub fn new(script: &'script ValidationScript) -> Self { Runtime { script } }
}

impl<'script> Validate for Runtime<'script> {
    #[allow(unused_variables)]
    fn validate(
        &self,
        node_id: NodeId,
        node_subtype: NodeSubtype,
        previous_owned_rights: &OwnedRights,
        current_owned_rights: &OwnedRights,
        previous_public_rights: &PublicRights,
        current_public_rights: &PublicRights,
        current_meta: &Metadata,
    ) -> Result<(), Failure> {
        // TODO: Implement validation with AluVM
        /*
        let mut vm = Vm::<RgbIsa>::new();
        if vm.run(self.script) {
            Ok(())
        } else {
            Err(Failure::ScriptFailure(node_id))
        }
         */
        Ok(())
    }
}

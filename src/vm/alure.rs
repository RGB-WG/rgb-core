// RGB Core Library: a reference implementation of RGB smart contract standards.
// Written in 2019-2022 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the MIT License along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

use std::collections::BTreeSet;
use std::ops::RangeInclusive;

use aluvm::isa::{Bytecode, BytecodeError, ExecStep, InstructionSet};
use aluvm::program::{CodeEofError, LibSite, Read, Write};
use aluvm::reg::CoreRegs;
use aluvm::Vm;

use crate::validation::Failure;
use crate::{Metadata, NodeId, NodeSubtype, OwnedRights, PublicRights, Validate};

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

    fn write_args<W>(&self, writer: &mut W) -> Result<(), BytecodeError>
    where W: Write {
        match self {
            RgbIsa::Noop => {}
        }
        Ok(())
    }

    fn read<R>(reader: &mut R) -> Result<Self, CodeEofError>
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

pub type ValidationScript = aluvm::Program<RgbIsa>;

pub struct Runtime<'script> {
    script: &'script ValidationScript,
}

impl<'script> Runtime<'script> {
    pub fn new(script: &'script ValidationScript) -> Self { Runtime { script } }
}

impl<'script> Validate for Runtime<'script> {
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
        let mut vm = Vm::<RgbIsa>::new();
        if vm.run(self.script) {
            Ok(())
        } else {
            Err(Failure::ScriptFailure(node_id))
        }
    }
}

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

//! API for interfacing different virtual machines
//!
//! Concrete virtual machine implementations must be wrapped into this API

#[macro_use]
mod macroasm;
pub mod instr;
mod isa;
mod opcodes;
mod contract;
mod bytecode;
mod exec;
#[cfg(test)]
mod tests;

pub use aluvm::aluasm_isa;
pub use contract::{
    ContractStateAccess, ContractStateEvolve, GlobalContractState, GlobalOrd, GlobalStateIter,
    ImpossibleIter, OpOrd, OrdOpRef, UnknownGlobalStateType, WitnessOrd, WitnessPos, XWitnessId,
    XWitnessTx,
};
pub(crate) use contract::{OpInfo, VmContext};
pub use isa::{assemble, disassemble, CompileOnly, RgbIsa};
pub use opcodes::ContractOp;

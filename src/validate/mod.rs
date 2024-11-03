// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2019-2024 Dr Maxim Orlovsky. All rights reserved.

#[macro_use]
mod vm;
mod isa;
mod contract;

pub use contract::{ContractRepository, GlobalRef, RgbWitness, ValidationError, VerifiedContractState};
pub use isa::{RgbInstr, ISA_RGB1};
pub use vm::{RgbVm, VmContext, VmError};

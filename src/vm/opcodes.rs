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

use aluvm::isa::opcodes::INSTR_ISAE_TO;

pub const INSTR_RGBISA_FROM: u8 = 0b10_010_000;
pub const INSTR_RGBISA_TO: u8 = INSTR_ISAE_TO;

// CONTRACTS:
pub const INSTR_CNP: u8 = 0b11_000_000;
pub const INSTR_CNS: u8 = 0b11_000_001;
pub const INSTR_CNG: u8 = 0b11_000_010;
pub const INSTR_CNC: u8 = 0b11_000_011;

pub const INSTR_LDP: u8 = 0b11_000_100;
pub const INSTR_LDS: u8 = 0b11_000_101;
// Reserved 0b11_000_111

pub const INSTR_LDG: u8 = 0b11_001_000;
pub const INSTR_LDC: u8 = 0b11_001_001;
pub const INSTR_LDM: u8 = 0b11_001_010;
// Reserved 0b11_001_111

// Reserved 0b11_010_011
pub const INSTR_CONTRACT_FROM: u8 = 0b11_000_000;
pub const INSTR_CONTRACT_TO: u8 = 0b11_001_111;

// TIMECHAIN:
pub const INSTR_TIMECHAIN_FROM: u8 = 0b11_011_100;
pub const INSTR_TIMECHAIN_TO: u8 = 0b11_011_111;

// Reserved 0b11_011_100
// Reserved 0b11_011_101
// Reserved 0b11_011_110
// Reserved 0b11_011_111

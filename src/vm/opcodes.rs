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

use aluvm::isa::opcodes::INSTR_ISAE_TO;

// 110 instructions in total
pub const INSTR_RGBISA_FROM: u8 = 0b10_010_000;
pub const INSTR_RGBISA_TO: u8 = INSTR_ISAE_TO;

// 0b10_010_000 .. 0b10_111_111 reserved (47 instructions)

// CONTRACTS:
pub const INSTR_COUNT: u8 = 0b11_000_000;
pub const INSTR_LOAD: u8 = 0b11_000_001;
pub const INSTR_VAL: u8 = 0b11_000_010;
pub const INSTR_TAKE: u8 = 0b11_000_011;

pub const INSTR_LOAD_META: u8 = 0b11_000_100;
pub const INSTR_TAKE_META: u8 = 0b11_000_101;
pub const INSTR_PCVS: u8 = 0b11_000_110;
pub const INSTR_PCCS: u8 = 0b11_000_111;

pub const INSTR_CONTRACT_FROM: u8 = 0b11_000_000;
pub const INSTR_CONTRACT_TO: u8 = 0b11_000_111;

// TIMECHAIN:
pub const INSTR_TIMECHAIN_FROM: u8 = 0b11_001_000;
pub const INSTR_TIMECHAIN_TO: u8 = 0b11_001_111;

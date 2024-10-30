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

use amplify::num::{u2, u3};

#[allow(unused_imports)] // Needed for docs
use super::ContractOp;

// 64 instructions in total: 4 blocks by 16 instructions minus 0xFFFF instruction
pub const INSTR_RGBISA_FROM: u8 = 0b1100_0000;
pub const INSTR_RGBISA_TO: u8 = INSTR_ISAE_TO;

// ================================================================================================
// Block 1: Contracts (RGB and RGBIC)
pub const INSTR_CONTRACT_FROM: u8 = INSTR_RGB_CNT;
pub const INSTR_CONTRACT_TO: u8 = INSTR_RGB_RESERVED_TO;

// ------------------------------------------------------------------------------------------------
// RGB ISA extension (single-contract instructions)

/// Instructions counting state items.
///
/// # Mnemonics
/// `cn.i`, `cn.o`, `cn.g`, `cn.c`
///
/// # Operations
/// - [`ContractOp::CnI`]
/// - [`ContractOp::CnO`]
/// - [`ContractOp::CnG`]
/// - [`ContractOp::CnC`]
pub const INSTR_RGB_CNT: u8 = 0b1100_0000;
pub const INSTR_RGB_CNT_C: u3 = u3::with(0b_000);
pub const INSTR_RGB_CNT_G: u3 = u3::with(0b_001);
pub const INSTR_RGB_CNT_I: u3 = u3::with(0b_010);
pub const INSTR_RGB_CNT_O: u3 = u3::with(0b_011);
pub const INSTR_RGB_CNT_R: u3 = u3::with(0b_100);
pub const INSTR_RGB_CNT_V: u3 = u3::with(0b_101);
pub const INSTR_RGB_CNT_M: u3 = u3::with(0b_110);
pub const INSTR_RGB_CNT_EXT: u3 = u3::with(0b_111);

/// Instructions loading state.
///
/// # Mnemonics
/// `ld.i`, `ld.o`, `ld.g`, `ld.c`
///
/// # Operations
/// - [`ContractOp::LdI`]
/// - [`ContractOp::LdO`]
/// - [`ContractOp::LdG`]
/// - [`ContractOp::LdC`]

pub const INSTR_RGB_LD: u8 = 0b1100_0001;
pub const INSTR_RGB_LD_C: u2 = u2::with(0b_00);
pub const INSTR_RGB_LD_G: u2 = u2::with(0b_01);
pub const INSTR_RGB_LD_I: u2 = u2::with(0b_10);
pub const INSTR_RGB_LD_O: u2 = u2::with(0b_11);

/// Instruction loading metadata.
///
/// Mnemonic: `ld.m`
///
/// Operation: [`ContractOp::LdM`].
pub const INSTR_RGB_LDM: u8 = 0b1100_0010;

// ------------------------------------------------------------------------------------------------
// RGBIC ISA extension (inter-contract operations)
pub const INSTR_RGB_RESERVED_FROM: u8 = INSTR_RGBIC_RESERVED1;
pub const INSTR_RGB_RESERVED_TO: u8 = INSTR_RGBIC_RESERVED13;
pub const INSTR_RGBIC_RESERVED1: u8 = 0b1100_0011;
pub const INSTR_RGBIC_RESERVED2: u8 = 0b1100_0100;
pub const INSTR_RGBIC_RESERVED3: u8 = 0b1100_0101;
pub const INSTR_RGBIC_RESERVED4: u8 = 0b1100_0110;
pub const INSTR_RGBIC_RESERVED5: u8 = 0b1100_0111;
pub const INSTR_RGBIC_RESERVED6: u8 = 0b1100_1000;
pub const INSTR_RGBIC_RESERVED7: u8 = 0b1100_1001;
pub const INSTR_RGBIC_RESERVED8: u8 = 0b1100_1010;
pub const INSTR_RGBIC_RESERVED9: u8 = 0b1100_1011;
pub const INSTR_RGBIC_RESERVED10: u8 = 0b1100_1100;
pub const INSTR_RGBIC_RESERVED11: u8 = 0b1100_1101;
pub const INSTR_RGBIC_RESERVED12: u8 = 0b1100_1110;
pub const INSTR_RGBIC_RESERVED13: u8 = 0b1100_1111;

// ================================================================================================
// Block 2: Timechain (BP)
pub const INSTR_BP_FROM: u8 = 0b1101_0000;
pub const INSTR_BP_TO: u8 = 0b1101_1111;

// ================================================================================================
// Block 3: Lightning (LNP)
pub const INSTR_LNP_FROM: u8 = 0b1110_0000;
pub const INSTR_LNP_TO: u8 = 0b1110_1111;

// ================================================================================================
// Block 4: Data availability (RGBDA / STORM)
pub const INSTR_STORM_FROM: u8 = 0b1111_0000;
pub const INSTR_STORM_TO: u8 = 0b1111_1110;

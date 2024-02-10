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

#[macro_export]
macro_rules! rgbasm {
    ($( $tt:tt )+) => {{ #[allow(unused_imports)] {
        use $crate::vm::{RgbIsa, ContractOp, TimechainOp};
        use $crate::vm::aluasm_isa;
        use $crate::isa_instr;
        aluasm_isa! { RgbIsa => $( $tt )+ }
    } }};
}

#[macro_export]
macro_rules! isa_instr {
    (pcvs $no:literal) => {{ RgbIsa::Contract(ContractOp::PcVs($no.into())) }};
    (pccs $no1:literal, $no2:literal) => {{ RgbIsa::Contract(ContractOp::PcCs($no1.into(), $no2.into())) }};
    (ldg $t:literal, $no:literal,s16[$s_idx:literal]) => {{ RgbIsa::Contract(ContractOp::LdG($t.into(), $no, RegS::from($s_idx))) }};
    (lds $t:literal, $no:literal,s16[$s_idx:literal]) => {{ RgbIsa::Contract(ContractOp::LdS($t.into(), $no, RegS::from($s_idx))) }};
    (ldp $t:literal, $no:literal,s16[$s_idx:literal]) => {{ RgbIsa::Contract(ContractOp::LdP($t.into(), $no, RegS::from($s_idx))) }};
    ($op:ident $($tt:tt)+) => {{ compile_error!(concat!("unknown RGB assembly opcode `", stringify!($op), "`")) }};
}

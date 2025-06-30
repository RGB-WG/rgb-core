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
        use amplify::num::{u4, u5};
        use $crate::vm::{RgbIsa, ContractOp};
        use $crate::vm::aluasm_isa;
        use $crate::isa_instr;
        aluasm_isa! { RgbIsa<_> => $( $tt )+ }
    } }};
}

#[macro_export]
macro_rules! isa_instr {
    (svs $no:ident) => {{
        RgbIsa::Contract(ContractOp::Svs($no))
    }};
    (sas $no:ident) => {{
        RgbIsa::Contract(ContractOp::Sas($no))
    }};
    (sps $no:ident) => {{
        RgbIsa::Contract(ContractOp::Sps($no))
    }};
    (cnp $t:ident,a16[$a_idx:literal]) => {{
        RgbIsa::Contract(ContractOp::CnP($t, Reg32::from(u5::with($a_idx))))
    }};
    (cns $t:ident,a16[$a_idx:literal]) => {{
        RgbIsa::Contract(ContractOp::CnS($t, Reg32::from(u5::with($a_idx))))
    }};
    (cng $t:ident,a8[$a_idx:literal]) => {{
        RgbIsa::Contract(ContractOp::CnG($t, Reg32::from(u5::with($a_idx))))
    }};
    (cnc $t:ident,a16[$a_idx:literal]) => {{
        RgbIsa::Contract(ContractOp::CnC($t, Reg32::from(u5::with($a_idx))))
    }};
    (ldc $t:ident,a32[$a_idx:literal],s16[$s_idx:literal]) => {{
        RgbIsa::Contract(ContractOp::LdC($t, Reg16::from(u4::with($a_idx)), RegS::from($s_idx)))
    }};
    (ldm $t:ident,s16[$s_idx:literal]) => {{
        RgbIsa::Contract(ContractOp::LdM($t, RegS::from($s_idx)))
    }};
    (ldg $t:ident,a8[$a_idx:literal],s16[$s_idx:literal]) => {{
        RgbIsa::Contract(ContractOp::LdG($t, Reg16::from(u4::with($a_idx)), RegS::from($s_idx)))
    }};
    (ldp $t:ident,a16[$a_idx:literal],s16[$s_idx:literal]) => {{
        RgbIsa::Contract(ContractOp::LdP($t, Reg16::from(u4::with($a_idx)), RegS::from($s_idx)))
    }};
    (lds $t:ident,a16[$a_idx:literal],s16[$s_idx:literal]) => {{
        RgbIsa::Contract(ContractOp::LdS($t, Reg16::from(u4::with($a_idx)), RegS::from($s_idx)))
    }};
    (vts s16[$s_idx:literal]) => {{
        RgbIsa::Contract(ContractOp::Vts(RegS::from($s_idx)))
    }};
    ($op:ident $($tt:tt)+) => {{
        compile_error!(concat!("unknown RGB assembly opcode `", stringify!($op), "`"))
    }};
}

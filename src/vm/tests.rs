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

use amplify::hex::ToHex;

use crate::vm::instr::{INSTR_RGB_CNT, INSTR_RGB_LD, INSTR_RGB_LDM};
use crate::{disassemble, rgbasm};

#[test]
fn bytecode_roundtrip() {
    let lib = rgbasm! {
         ld.c       s16[0],a16[0],a32[15];
         ld.g       s16[1],a16[1],a16[14];
         ld.i       s16[2],a16[2],a16[13];
         ld.o       s16[3],a16[3],a16[12];
         ld.m       s16[4],a16[11];

         cn.c       a32[9],a16[5];
         cn.g       a16[10],a16[6];
         cn.i       a16[11],a16[7];
         cn.o       a16[12],a16[8];

         ret;
    };

    assert_eq!(lib.libs, none!());
    assert_eq!(lib.data, none!());
    assert_eq!(lib.isae.to_string(), "ALU BPDIGEST RGB");
    assert_eq!(lib.code.to_hex(), "c10078c14570c18a68c1cf60c2b4c0472ac08f32c0d73ac01f4307");

    let desasm = disassemble(&lib);

    assert_eq!(
        desasm,
        "\
offset_0x0000: ld.c    s16[0],a16[0],a32[15]
offset_0x0003: ld.g    s16[1],a16[1],a16[14]
offset_0x0006: ld.i    s16[2],a16[2],a16[13]
offset_0x0009: ld.o    s16[3],a16[3],a16[12]
offset_0x000C: ld.m    s16[4],a16[11]
offset_0x000E: cn.c    a32[9],a16[5]
offset_0x0011: cn.g    a16[10],a16[6]
offset_0x0014: cn.i    a16[11],a16[7]
offset_0x0017: cn.o    a16[12],a16[8]
offset_0x001A: ret
"
    );

    assert_eq!(lib.code[0x00], INSTR_RGB_LD);
    assert_eq!(lib.code[0x03], INSTR_RGB_LD);
    assert_eq!(lib.code[0x06], INSTR_RGB_LD);
    assert_eq!(lib.code[0x09], INSTR_RGB_LD);
    assert_eq!(lib.code[0x0C], INSTR_RGB_LDM);
    assert_eq!(lib.code[0x0E], INSTR_RGB_CNT);
    assert_eq!(lib.code[0x11], INSTR_RGB_CNT);
    assert_eq!(lib.code[0x14], INSTR_RGB_CNT);
    assert_eq!(lib.code[0x17], INSTR_RGB_CNT);
}

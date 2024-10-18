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

// TODO: Re-enable once we will have a test ContractState object
/*
#[cfg(test)]
mod test {
    use aluvm::isa::Instr;
    use aluvm::library::Lib;
    use amplify::hex::ToHex;
    use strict_encoding::StrictSerialize;

    use super::*;
    use crate::vm::RgbIsa;

    #[test]
    fn encoding() {
        let code =
            [Instr::ExtensionCodes(RgbIsa::Contract(ContractOp::Pcvs(AssignmentType::from(4000))))];
        let alu_lib = Lib::assemble(&code).unwrap();
        eprintln!("{alu_lib}");
        let alu_id = alu_lib.id();

        assert_eq!(
            alu_id.to_string(),
            "alu:zI4PtPCR-Eut023!-Hqblf3X-N2J4GZb-TR2ZEsI-vQfhKOU#ruby-sherman-tonight"
        );
        assert_eq!(alu_lib.code.as_ref().to_hex(), "d0a00f");
        assert_eq!(
            alu_lib
                .to_strict_serialized::<{ usize::MAX }>()
                .unwrap()
                .to_hex(),
            "0303414c55084250444947455354035247420300d0a00f000000"
        );
        assert_eq!(alu_lib.disassemble::<Instr<RgbIsa<_>>>().unwrap(), code);
    }
}
*/

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

pub use aluvm::stl::aluvm_stl;
pub use bp::bc::stl::bp_tx_stl;
pub use bp::stl::bp_core_stl;
use commit_verify::stl::commit_verify_stl;
use strict_types::stl::{std_stl, strict_types_stl};
use strict_types::typelib::LibBuilder;
use strict_types::{CompileError, TypeLib};

use crate::{
    ContractHistory, DbcProof, Extension, Genesis, OpCommitment, Schema, TransitionBundle,
    XWitnessId, LIB_NAME_RGB, LIB_NAME_RGB_STATE,
};

/// Strict types id for the library providing data types for RGB consensus.
pub const LIB_ID_RGB: &str =
    "stl:DtU4CU7y-uIGqQFH-xs4K7Lw-dG5WL9E-RNK5oB5-IYQS$V4#diploma-montana-elastic";

/// Strict types id for the library providing data types for RGB contract state.
pub const LIB_ID_RGB_STATE: &str =
    "stl:Xl48C7OQ-!diM0pe-di2Evap-FNClN8v-dwJlFVj-DDK!0Uo#icon-passage-bonanza";

fn _rgb_core_stl() -> Result<TypeLib, CompileError> {
    LibBuilder::new(libname!(LIB_NAME_RGB), tiny_bset! {
        std_stl().to_dependency(),
        strict_types_stl().to_dependency(),
        commit_verify_stl().to_dependency(),
        bp_tx_stl().to_dependency(),
        bp_core_stl().to_dependency(),
        aluvm_stl().to_dependency()
    })
    .transpile::<Schema>()
    .transpile::<Genesis>()
    .transpile::<DbcProof>()
    .transpile::<XWitnessId>()
    .transpile::<TransitionBundle>()
    .transpile::<Extension>()
    .transpile::<OpCommitment>()
    .compile()
}

fn _rgb_state_stl() -> Result<TypeLib, CompileError> {
    LibBuilder::new(libname!(LIB_NAME_RGB_STATE), tiny_bset! {
        std_stl().to_dependency(),
        strict_types_stl().to_dependency(),
        commit_verify_stl().to_dependency(),
        bp_tx_stl().to_dependency(),
        bp_core_stl().to_dependency(),
        aluvm_stl().to_dependency(),
        rgb_core_stl().to_dependency()
    })
    .transpile::<ContractHistory>()
    .compile()
}

/// Generates strict type library providing data types for RGB consensus.
pub fn rgb_core_stl() -> TypeLib { _rgb_core_stl().expect("invalid strict type RGB Core library") }

/// Generates strict type library providing data types for RGB contract
/// consensus state.
pub fn rgb_state_stl() -> TypeLib {
    _rgb_state_stl().expect("invalid strict type RGB State library")
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn core_lib_id() {
        let lib = rgb_core_stl();
        assert_eq!(lib.id().to_string(), LIB_ID_RGB);
    }

    #[test]
    fn state_lib_id() {
        let lib = rgb_state_stl();
        assert_eq!(lib.id().to_string(), LIB_ID_RGB_STATE);
    }
}

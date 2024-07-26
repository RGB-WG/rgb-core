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

use crate::validation::DbcProof;
use crate::vm::GlobalOrd;
use crate::{
    Extension, Genesis, OpCommitment, Schema, TransitionBundle, XWitnessId, LIB_NAME_RGB_COMMIT,
    LIB_NAME_RGB_LOGIC,
};

/// Strict types id for the library providing data types for RGB consensus.
pub const LIB_ID_RGB_COMMIT: &str =
    "stl:!fGY8ly8-b4JlfE9-tH00YSF-aLoZPpU-Fplj9Sp-aOmGNN8#poem-amen-provide";
/// Strict types id for the library providing data types for RGB consensus.
pub const LIB_ID_RGB_LOGIC: &str =
    "stl:UMHaWn4i-HC$$goM-lrPiosO-cDL60HR-QfnpQAN-4fPoOZU#second-germany-cloud";

fn _rgb_commit_stl() -> Result<TypeLib, CompileError> {
    LibBuilder::new(libname!(LIB_NAME_RGB_COMMIT), tiny_bset! {
        std_stl().to_dependency(),
        strict_types_stl().to_dependency(),
        commit_verify_stl().to_dependency(),
        bp_tx_stl().to_dependency(),
        bp_core_stl().to_dependency(),
        aluvm_stl().to_dependency()
    })
    .transpile::<Schema>()
    .transpile::<Genesis>()
    .transpile::<XWitnessId>()
    .transpile::<TransitionBundle>()
    .transpile::<Extension>()
    .transpile::<OpCommitment>()
    .compile()
}

fn _rgb_logic_stl() -> Result<TypeLib, CompileError> {
    LibBuilder::new(libname!(LIB_NAME_RGB_LOGIC), tiny_bset! {
        std_stl().to_dependency(),
        strict_types_stl().to_dependency(),
        commit_verify_stl().to_dependency(),
        bp_tx_stl().to_dependency(),
        bp_core_stl().to_dependency(),
        aluvm_stl().to_dependency(),
        rgb_commit_stl().to_dependency()
    })
        .transpile::<GlobalOrd>()
        .transpile::<DbcProof>()
        // TODO: Commit to the RGB ISA once AluVM will support strict types
        // .transpile::<RgbIsa>()
        .compile()
}

/// Generates strict type library providing data types for RGB consensus.
pub fn rgb_commit_stl() -> TypeLib {
    _rgb_commit_stl().expect("invalid strict type RGB consensus commitments library")
}

/// Generates strict type library providing data types for RGB consensus.
pub fn rgb_logic_stl() -> TypeLib {
    _rgb_logic_stl().expect("invalid strict type RGB consensus logic library")
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn commit_lib_id() {
        let lib = rgb_commit_stl();
        assert_eq!(lib.id().to_string(), LIB_ID_RGB_COMMIT);
    }

    #[test]
    fn logic_lib_id() {
        let lib = rgb_logic_stl();
        assert_eq!(lib.id().to_string(), LIB_ID_RGB_LOGIC);
    }
}

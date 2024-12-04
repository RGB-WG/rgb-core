// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Designed in 2019-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
// Written in 2024-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association, Switzerland.
// Copyright (C) 2024-2025 LNP/BP Laboratories,
//                         Institute for Distributed and Cognitive Systems (InDCS), Switzerland.
// Copyright (C) 2025 RGB Consortium, Switzerland.
// Copyright (C) 2019-2025 Dr Maxim Orlovsky.
// All rights under the above copyrights are reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
// in compliance with the License. You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied. See the License for the specific language governing permissions and limitations under
// the License.

use bp::stl::bp_core_stl;
use commit_verify::stl::commit_verify_stl;
use strict_types::stl::{std_stl, strict_types_stl};
use strict_types::typelib::LibBuilder;
use strict_types::{CompileError, TypeLib};

use crate::{Bp, LIB_NAME_RGB_CORE};

/// Strict types id for the library providing data types for RGB consensus.
pub const LIB_ID_RGB_CORE: &str = "stl:CHVOQxpG-2DQFIdm-dcvmuYN-JfIIZdL-dXrpDtl-zFrVLPw#invent-newton-harvard";

fn _rgb_core_stl() -> Result<TypeLib, CompileError> {
    LibBuilder::new(libname!(LIB_NAME_RGB_CORE), tiny_bset! {
        std_stl().to_dependency(),
        strict_types_stl().to_dependency(),
        commit_verify_stl().to_dependency(),
        bp_core_stl().to_dependency(),
    })
    .transpile::<Bp>()
    .compile()
}

/// Generates strict type library providing data types for RGB consensus.
pub fn rgb_core_stl() -> TypeLib { _rgb_core_stl().expect("invalid strict type RGB consensus commitments library") }

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn lib_id() {
        let lib = rgb_core_stl();
        assert_eq!(lib.id().to_string(), LIB_ID_RGB_CORE);
    }
}

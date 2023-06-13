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

use aluvm::stl::aluvm_stl;
use bp::bc::stl::bitcoin_stl;
use bp::stl::bp_core_stl;
use strict_types::stl::strict_types_stl;
use strict_types::typelib::{LibBuilder, TranslateError};
use strict_types::TypeLib;

use crate::{Extension, Genesis, SubSchema, TransitionBundle, LIB_NAME_RGB};

/// Strict types id for the library providing data types for RGB consensus.
pub const LIB_ID_RGB: &str = "fiber_deal_falcon_3NhgEBNcHTwSGZ1zeoGvebAAZrkhxio9HEkc7dYUjaAF";

fn _rgb_core_stl() -> Result<TypeLib, TranslateError> {
    LibBuilder::new(libname!(LIB_NAME_RGB), tiny_bset! {
        strict_types_stl().to_dependency(),
        bitcoin_stl().to_dependency(),
        bp_core_stl().to_dependency(),
        aluvm_stl().to_dependency()
    })
    .transpile::<SubSchema>()
    .transpile::<Genesis>()
    .transpile::<TransitionBundle>()
    .transpile::<Extension>()
    .compile()
}

/// Generates strict type library providing data types for RGB consensus.
pub fn rgb_core_stl() -> TypeLib { _rgb_core_stl().expect("invalid strict type RGB library") }

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn lib_id() {
        let lib = rgb_core_stl();
        assert_eq!(lib.id().to_string(), LIB_ID_RGB);
    }
}

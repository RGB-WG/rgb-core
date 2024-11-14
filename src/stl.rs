// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2019-2024 Dr Maxim Orlovsky. All rights reserved.

use commit_verify::stl::commit_verify_stl;
use strict_types::stl::{std_stl, strict_types_stl};
use strict_types::typelib::LibBuilder;
use strict_types::{CompileError, TypeLib};

use crate::contract::Contract;
use crate::LIB_NAME_RGB_CORE;

/// Strict types id for the library providing data types for RGB consensus.
pub const LIB_ID_RGB_CORE: &str = "stl:e34bLx8U-iXAiLoF-Uvz.lun-EMEGotf-uzLJwMs-EVsilEU#annual-factor-object";

fn _rgb_core_stl() -> Result<TypeLib, CompileError> {
    LibBuilder::new(libname!(LIB_NAME_RGB_CORE), tiny_bset! {
        std_stl().to_dependency(),
        strict_types_stl().to_dependency(),
        commit_verify_stl().to_dependency(),
    })
    .transpile::<Contract>()
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

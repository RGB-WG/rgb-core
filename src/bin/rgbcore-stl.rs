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

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate strict_types;

use std::str::FromStr;

use bp::LIB_NAME_BP;
use rgb::{Extension, Genesis, Schema, TransitionBundle, LIB_NAME_RGB};
use strict_encoding::STRICT_TYPES_LIB;
use strict_types::typelib::LibBuilder;
use strict_types::{Dependency, TypeLibId};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sty_id =
        TypeLibId::from_str("5mWmf6wrAeNy4VgKwiqAaePHJEV9JUjsTeSyTwseo5wW#logic-drum-magenta")?;
    let imports = bmap! {
        libname!(STRICT_TYPES_LIB) => (lib_alias!(STRICT_TYPES_LIB), Dependency::with(sty_id, libname!(STRICT_TYPES_LIB), (0,10,0))),
        libname!(LIB_NAME_BP) => (lib_alias!(LIB_NAME_BP), Dependency::with(sty_id, libname!(LIB_NAME_BP), (0,10,0)))
    };

    let lib = LibBuilder::new(libname!(LIB_NAME_RGB))
        .process::<Schema>()?
        .process::<Genesis>()?
        .process::<TransitionBundle>()?
        .process::<Extension>()?
        .compile(imports)?;
    let id = lib.id();

    println!(
        "{{-
  Id: {id}
  Name: RGBCore
  Description: Consensus layer for RGB smart contracts
  Author: Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
  Copyright (C) 2023 LNP/BP Standards Association. All rights reserved.
  License: Apache-2.0
-}}\n"
    );
    println!("{{-\n-- Import this lib by putting in the file header\n-- import {id:+}\n-}}");
    println!("{lib}");

    Ok(())
}

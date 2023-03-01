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

use std::io::stdout;
use std::str::FromStr;
use std::{env, fs, io};

use amplify::num::u24;
use bp::dbc::LIB_NAME_BPCORE;
use bp::LIB_NAME_BITCOIN;
use rgb::{Extension, Genesis, Schema, TransitionBundle, LIB_NAME_RGB};
use strict_encoding::{StrictEncode, StrictWriter, STRICT_TYPES_LIB};
use strict_types::typelib::LibBuilder;
use strict_types::{Dependency, TypeLibId};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    let sty_id =
        TypeLibId::from_str("subject_leonid_rudolf_3VG9Cjoyx9MMAY2y4EZBgX9YQoyMngFfNrGLAUFbzQFU")?;
    let bitcoin_id =
        TypeLibId::from_str("oberon_parker_cobra_GVur9D96gWvVkXNkss6nTXn3qyLG4tvT3G7AeLwFZACo")?;
    let bpcore_id =
        TypeLibId::from_str("gate_garcia_robin_DsDVAwMKHjQjHHzWzJ4G1pMQ4ygkGUDezDZ5Aj7uJGta")?;

    let imports = bmap! {
        libname!(STRICT_TYPES_LIB) => (lib_alias!(STRICT_TYPES_LIB), Dependency::with(sty_id, libname!(STRICT_TYPES_LIB), (0,10,0))),
        libname!(LIB_NAME_BITCOIN) => (lib_alias!(LIB_NAME_BITCOIN), Dependency::with(bitcoin_id, libname!(LIB_NAME_BITCOIN), (0,10,0))),
        libname!(LIB_NAME_BPCORE) => (lib_alias!(LIB_NAME_BPCORE), Dependency::with(bpcore_id, libname!(LIB_NAME_BITCOIN), (0,10,0))),
    };

    let lib = LibBuilder::new(libname!(LIB_NAME_RGB))
        .process::<Schema>()?
        .process::<Genesis>()?
        .process::<TransitionBundle>()?
        .process::<Extension>()?
        .compile(imports)?;
    let id = lib.id();

    let ext = match args.get(2).map(String::as_str) {
        Some("-b") => "stl",
        Some("-h") => "asc.stl",
        _ => "sty",
    };
    let filename = args
        .get(3)
        .cloned()
        .unwrap_or_else(|| format!("stl/RGBCore.{ext}"));
    let mut file = match args.len() {
        2 => Box::new(stdout()) as Box<dyn io::Write>,
        3 | 4 => Box::new(fs::File::create(filename)?) as Box<dyn io::Write>,
        _ => panic!("invalid argument count"),
    };
    match ext {
        "stl" => {
            lib.strict_encode(StrictWriter::with(u24::MAX.into_usize(), file))?;
        }
        "asc.stl" => {
            writeln!(file, "{lib:X}")?;
        }
        _ => {
            writeln!(
                file,
                "{{-
  Id: {id}
  Name: RGBCore
  Description: Consensus layer for RGB smart contracts
  Author: Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
  Copyright (C) 2023 LNP/BP Standards Association. All rights reserved.
  License: Apache-2.0
-}}
"
            )?;
            writeln!(file, "{lib}")?;
        }
    }

    Ok(())
}

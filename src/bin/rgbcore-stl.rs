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

use std::fs;
use std::io::Write;

use aluvm::stl::aluvm_stl;
use bp::stl::bp_core_stl;
use commit_verify::stl::commit_verify_stl;
use commit_verify::CommitmentLayout;
use rgb::stl::bp_tx_stl;
use rgb::{SubSchema, Transition, TransitionBundle};
use strict_types::stl::{std_stl, strict_types_stl};
use strict_types::typelib::parse_args;
use strict_types::SystemBuilder;

fn main() {
    let (format, dir) = parse_args();

    let rgb = rgb::stl::rgb_core_stl();

    rgb.serialize(
        format,
        dir.as_ref(),
        "0.1.0",
        Some(
            "
  Description: Consensus layer for RGB smart contracts
  Author: Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
  Copyright (C) 2023-2024 LNP/BP Standards Association. All rights reserved.
  License: Apache-2.0",
        ),
    )
    .expect("unable to write to the file");

    let std = std_stl();
    let tx = bp_tx_stl();
    let bp = bp_core_stl();
    let cv = commit_verify_stl();
    let st = strict_types_stl();
    let vm = aluvm_stl();

    let sys = SystemBuilder::new()
        .import(rgb)
        .unwrap()
        .import(vm)
        .unwrap()
        .import(bp)
        .unwrap()
        .import(tx)
        .unwrap()
        .import(cv)
        .unwrap()
        .import(st)
        .unwrap()
        .import(std)
        .unwrap()
        .finalize()
        .expect("not all libraries present");

    let dir = dir.unwrap_or_else(|| ".".to_owned());

    let mut file = fs::File::create(format!("{dir}/Schema.vesper")).unwrap();
    writeln!(
        file,
        "{{-
  Description: RGB Schema
  Author: Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
  Copyright (C) 2024 LNP/BP Standards Association. All rights reserved.
  License: Apache-2.0
-}}

Schema vesper lexicon=types+commitments
"
    )
    .unwrap();
    let layout = SubSchema::commitment_layout();
    writeln!(file, "{layout}").unwrap();
    let tt = sys.type_tree("RGB.Schema").unwrap();
    writeln!(file, "{tt}").unwrap();

    let mut file = fs::File::create(format!("{dir}/Transition.vesper")).unwrap();
    writeln!(
        file,
        "{{-
  Description: RGB Transition
  Author: Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
  Copyright (C) 2024 LNP/BP Standards Association. All rights reserved.
  License: Apache-2.0
-}}

Transition vesper lexicon=types+commitments
"
    )
    .unwrap();
    let layout = Transition::commitment_layout();
    writeln!(file, "{layout}").unwrap();
    let tt = sys.type_tree("RGB.OpCommitment").unwrap();
    writeln!(file, "{tt}").unwrap();
    let tt = sys.type_tree("RGB.Transition").unwrap();
    writeln!(file, "{tt}").unwrap();

    let mut file = fs::File::create(format!("{dir}/TransitionBundle.vesper")).unwrap();
    writeln!(
        file,
        "{{-
  Description: RGB Transition Bundle
  Author: Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
  Copyright (C) 2024 LNP/BP Standards Association. All rights reserved.
  License: Apache-2.0
-}}

Bundles vesper lexicon=types+commitments
"
    )
    .unwrap();
    let layout = TransitionBundle::commitment_layout();
    writeln!(file, "{layout}").unwrap();
    let tt = sys.type_tree("RGB.XChainAnchorSet").unwrap();
    writeln!(file, "{tt}").unwrap();
    let tt = sys.type_tree("RGB.TransitionBundle").unwrap();
    writeln!(file, "{tt}").unwrap();
}

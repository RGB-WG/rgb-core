// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2019-2024 Dr Maxim Orlovsky. All rights reserved.

use std::fs;
use std::io::Write;

use aluvm::stl::aluvm_stl;
use commit_verify::stl::commit_verify_stl;
use commit_verify::CommitmentLayout;
use rgbcore::stl::Seal;
use rgbcore::{Genesis, Transition};
use strict_types::stl::{std_stl, strict_types_stl};
use strict_types::typelib::parse_args;
use strict_types::SystemBuilder;

fn main() {
    let (format, dir) = parse_args();

    let rgb_commit = rgbcore::stl::rgb_commit_stl();
    let rgb_logic = rgbcore::stl::rgb_logic_stl();

    rgb_commit
        .serialize(
            format,
            dir.as_ref(),
            "0.1.0",
            Some(
                "
  Description: Consensus commitment layer for RGB smart contracts
  Author: Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
  Copyright (C) 2023-2024 LNP/BP Standards Association. All rights reserved.
  License: Apache-2.0",
            ),
        )
        .expect("unable to write to the file");

    rgb_logic
        .serialize(
            format,
            dir.as_ref(),
            "0.1.0",
            Some(
                "
  Description: Consensus logic layer for RGB smart contracts
  Author: Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
  Copyright (C) 2023-2024 LNP/BP Standards Association. All rights reserved.
  License: Apache-2.0",
            ),
        )
        .expect("unable to write to the file");

    let std = std_stl();
    let cv = commit_verify_stl();
    let st = strict_types_stl();
    let vm = aluvm_stl();

    let sys = SystemBuilder::new()
        .import(rgb_logic)
        .unwrap()
        .import(rgb_commit)
        .unwrap()
        .import(vm)
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

    let mut file = fs::File::create(format!("{dir}/Genesis.vesper")).unwrap();
    writeln!(
        file,
        "{{-
  Description: RGB Genesis
  Author: Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
  Copyright (C) 2024 LNP/BP Standards Association. All rights reserved.
  License: Apache-2.0
-}}

Schema vesper lexicon=types+commitments
"
    )
    .unwrap();
    let layout = Genesis::<Seal>::commitment_layout();
    writeln!(file, "{layout}").unwrap();
    let tt = sys.type_tree("RGBCommit.GenesisSeal").unwrap();
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

Bundles vesper lexicon=types+commitments
"
    )
    .unwrap();
    let layout = Transition::<Seal>::commitment_layout();
    writeln!(file, "{layout}").unwrap();
    let tt = sys.type_tree("RGBCommit.TransitionSeal").unwrap();
    writeln!(file, "{tt}").unwrap();
}

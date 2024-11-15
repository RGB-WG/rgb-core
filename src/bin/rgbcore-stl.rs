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

use bp::bc::stl::bp_tx_stl;
use bp::stl::bp_core_stl;
use commit_verify::stl::commit_verify_stl;
use commit_verify::CommitmentLayout;
use rgbcore::{BpLayer, Contract};
use strict_types::stl::{std_stl, strict_types_stl};
use strict_types::typelib::parse_args;
use strict_types::SystemBuilder;
use ultrasonic::stl::{aluvm_stl, finite_field_stl, usonic_stl};

fn main() {
    let (format, dir) = parse_args();

    let rgb_commit = rgbcore::stl::rgb_core_stl();

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

    let std = std_stl();
    let tx = bp_tx_stl();
    let bp = bp_core_stl();
    let cv = commit_verify_stl();
    let st = strict_types_stl();
    let vm = aluvm_stl();
    let ff = finite_field_stl();
    let us = usonic_stl();

    let sys = SystemBuilder::new()
        .import(rgb_commit)
        .unwrap()
        .import(vm)
        .unwrap()
        .import(us)
        .unwrap()
        .import(ff)
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

    let mut file = fs::File::create(format!("{dir}/Contract.vesper")).unwrap();
    writeln!(
        file,
        "{{-
  Description: RGB Contract
  Author: Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
  Copyright (C) 2024 LNP/BP Standards Association. All rights reserved.
  License: Apache-2.0
-}}

Bundles vesper lexicon=types+commitments
"
    )
    .unwrap();
    let layout = Contract::<BpLayer>::commitment_layout();
    writeln!(file, "{layout}").unwrap();
    let tt = sys.type_tree("RGBCore.ContractBpLayer").unwrap();
    writeln!(file, "{tt}").unwrap();
}

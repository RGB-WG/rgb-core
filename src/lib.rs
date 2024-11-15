// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2019-2024 Dr Maxim Orlovsky. All rights reserved.

#![cfg_attr(docsrs, feature(doc_auto_cfg))]

extern crate core;

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate strict_encoding;
#[macro_use]
extern crate commit_verify;

#[cfg(feature = "serde")]
#[macro_use]
extern crate serde;

mod contract;
mod verify;

#[cfg(feature = "stl")]
pub mod stl;

pub use commit_verify::ReservedBytes;
pub use contract::{BpLayer, Contract, ContractId, Ffv, Layer1};
pub use verify::{ContractStash, ContractState, ContractVerify, VerificationError};

pub const LIB_NAME_RGB_CORE: &str = "RGBCore";

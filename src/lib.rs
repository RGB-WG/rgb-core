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
mod validate;

#[cfg(feature = "stl")]
pub mod stl;

pub use commit_verify::ReservedBytes;
pub use contract::{
    Assign, AssignmentType, Assignments, AttachId, ContractId, Extension, ExtensionType, Ffv, FieldArray, Genesis,
    GenesisHeader, GlobalState, GlobalStateType, GlobalValues, Identity, Input, Inputs, MetaType, Metadata,
    MetadataError, OpId, Opout, RgbSeal, Schema, SchemaId, State, Transition, TransitionType, TypedAssigns,
    UnverifiedState, Validators, VerifiableState, VmSchema, GLOBAL_STATE_MAX_ITEMS, SCHEMA_LIBS_MAX_COUNT,
    STATE_DATA_MAX_LEN, TYPED_ASSIGNMENTS_MAX_ITEMS,
};
pub use validate::{
    ContractRepository, GlobalRef, RgbInstr, RgbVm, RgbWitness, ValidationError, VerifiedContractState, VmContext,
    VmError, ISA_RGB1,
};

pub const LIB_NAME_RGB_COMMIT: &str = "RGBCommit";
pub const LIB_NAME_RGB_LOGIC: &str = "RGBLogic";

pub const BITCOIN_PREFIX: &str = "bc";
pub const LIQUID_PREFIX: &str = "lq";
pub const BITCOIN_TEST_PREFIX: &str = "tb";
pub const LIQUID_TEST_PREFIX: &str = "tl";

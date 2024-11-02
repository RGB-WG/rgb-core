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

mod schema;
mod state;
mod operations;
mod commit;
#[macro_use]
mod vm;
mod isa;
mod validation;

#[cfg(feature = "stl")]
pub mod stl;

pub use commit::{ContractId, OpId, SchemaId};
pub use commit_verify::ReservedBytes;
pub use isa::{RgbInstr, ISA_RGB1};
pub use operations::{
    Extension, ExtensionType, Genesis, GenesisHeader, Identity, Input, Inputs, Opout, Transition, TransitionType,
};
pub use schema::{Schema, Validators, VmSchema, SCHEMA_LIBS_MAX_COUNT};
pub use seal::RgbSeal;
pub use state::{
    Assign, AssignmentType, Assignments, AttachId, GlobalState, GlobalStateType, GlobalValues, MetaType, Metadata,
    MetadataError, State, TypedAssigns, UnverifiedState, VerifiableState, GLOBAL_STATE_MAX_ITEMS, STATE_DATA_MAX_LEN,
    TYPED_ASSIGNMENTS_MAX_ITEMS,
};
pub use validation::{ContractRepository, GlobalRef, RgbWitness, ValidationError, VerifiedContractState};
pub use vm::{RgbVm, VmContext, VmError};

pub const LIB_NAME_RGB_COMMIT: &str = "RGBCommit";
pub const LIB_NAME_RGB_LOGIC: &str = "RGBLogic";

pub const BITCOIN_PREFIX: &str = "bc";
pub const LIQUID_PREFIX: &str = "lq";
pub const BITCOIN_TEST_PREFIX: &str = "tb";
pub const LIQUID_TEST_PREFIX: &str = "tl";

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(lowercase)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT, tags = repr, into_u8, try_from_u8)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
#[repr(u8)]
pub enum Layer1 {
    #[strict_type(dumb)]
    Bitcoin = 0,
    Liquid = 1,

    BitcoinTest = 0xF0,
    LiquidTest = 0xF1,
}

mod seal {
    use std::fmt::{Debug, Display};

    use amplify::Bytes32;
    use commit_verify::CommitEncode;
    use strict_encoding::{StrictDecode, StrictDumb, StrictEncode};

    pub trait RgbSeal:
        Copy
        + Ord
        + Debug
        + Display
        + StrictEncode
        + StrictDecode
        + StrictDumb
        + CommitEncode<CommitmentId: Into<Bytes32>>
    {
    }
}

/// Fast-forward version code
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Default, Debug, Display)]
#[display("RGB/1.{0}")]
#[derive(StrictType, StrictEncode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct Ffv(u16);

mod _ffv {
    use strict_encoding::{DecodeError, ReadTuple, StrictDecode, TypedRead};

    use crate::Ffv;

    impl StrictDecode for Ffv {
        fn strict_decode(reader: &mut impl TypedRead) -> Result<Self, DecodeError> {
            let ffv = reader.read_tuple(|r| r.read_field().map(Self))?;
            if ffv != Ffv::default() {
                Err(DecodeError::DataIntegrityError(format!(
                    "unsupported fast-forward version code belonging to a future RGB version. Please update your \
                     software, or, if the problem persists, contact your vendor providing the following version \
                     information: {ffv}"
                )))
            } else {
                Ok(ffv)
            }
        }
    }
}

#[macro_export]
macro_rules! impl_serde_baid64 {
    ($ty:ty) => {
        #[cfg(feature = "serde")]
        mod _serde {
            use amplify::ByteArray;
            use serde::de::Error;
            use serde::{Deserialize, Deserializer, Serialize, Serializer};

            use super::*;

            impl Serialize for $ty {
                fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                where S: Serializer {
                    if serializer.is_human_readable() {
                        self.to_string().serialize(serializer)
                    } else {
                        self.to_byte_array().serialize(serializer)
                    }
                }
            }

            impl<'de> Deserialize<'de> for $ty {
                fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                where D: Deserializer<'de> {
                    if deserializer.is_human_readable() {
                        let s = String::deserialize(deserializer)?;
                        Self::from_str(&s).map_err(D::Error::custom)
                    } else {
                        let bytes = <[u8; 32]>::deserialize(deserializer)?;
                        Ok(Self::from_byte_array(bytes))
                    }
                }
            }
        }
    };
}

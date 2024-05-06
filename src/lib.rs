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

#![allow(unused_braces)] // Rust compiler can't properly parse derivation macros
#![deny(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    unused_mut,
    unused_imports,
    dead_code,
    // TODO: Uncomment missing_docs
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate strict_encoding;
#[macro_use]
extern crate commit_verify;

#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_crate as serde;
extern crate core;

mod contract;
pub mod schema;
pub mod validation;
#[macro_use]
pub mod vm;
#[cfg(feature = "stl")]
pub mod stl;

pub mod prelude {
    pub use commit_verify::ReservedBytes;
    pub use contract::*;
    pub use schema::*;

    #[cfg(feature = "stl")]
    pub use super::stl;
    use super::*;
    pub use super::{schema, validation, vm};
}

pub use prelude::*;

pub const LIB_NAME_RGB: &str = "RGB";

/// Fast-forward version code
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Default, Debug, Display)]
#[display("RGB/1.{0}")]
#[derive(StrictType, StrictEncode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Ffv(u16);

mod _ffv {
    use strict_encoding::{DecodeError, ReadTuple, StrictDecode, TypedRead};

    use crate::Ffv;

    impl StrictDecode for Ffv {
        fn strict_decode(reader: &mut impl TypedRead) -> Result<Self, DecodeError> {
            let ffv = reader.read_tuple(|r| r.read_field().map(Self))?;
            if ffv != Ffv::default() {
                Err(DecodeError::DataIntegrityError(format!(
                    "unsupported fast-forward version code belonging to a future RGB version. \
                     Please update your software, or, if the problem persists, contact your \
                     vendor providing the following version information: {ffv}"
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
            use serde_crate::de::Error;
            use serde_crate::{Deserialize, Deserializer, Serialize, Serializer};

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

// TODO: Validate strict type data
// TODO: Add parsed global and structured state to the ContractState

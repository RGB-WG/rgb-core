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

pub mod contract;
pub mod schema;
pub mod validation;
pub mod vm;
#[cfg(feature = "stl")]
pub mod stl;

pub mod prelude {
    pub use contract::*;
    pub use schema::*;

    use super::*;
    pub use super::{schema, vm};
}

pub use prelude::*;

pub const LIB_NAME_RGB: &str = "RGB";

// TODO: Move to amplify crate

/// Reserved bytes.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[display("reserved")]
#[derive(StrictType, StrictEncode)]
#[strict_type(lib = LIB_NAME_RGB)]
pub struct ReservedBytes<const LEN: usize, const VAL: u8 = 0>([u8; LEN]);

impl<const LEN: usize, const VAL: u8> Default for ReservedBytes<LEN, VAL> {
    fn default() -> Self { Self([VAL; LEN]) }
}

impl<const LEN: usize, const VAL: u8> From<[u8; LEN]> for ReservedBytes<LEN, VAL> {
    fn from(value: [u8; LEN]) -> Self {
        assert_eq!(value, [VAL; LEN]);
        Self(value)
    }
}

mod _reserved {
    use strict_encoding::{DecodeError, ReadTuple, StrictDecode, TypedRead};

    use crate::ReservedBytes;

    impl<const LEN: usize, const VAL: u8> StrictDecode for ReservedBytes<LEN, VAL> {
        fn strict_decode(reader: &mut impl TypedRead) -> Result<Self, DecodeError> {
            let reserved = reader.read_tuple(|r| r.read_field().map(Self))?;
            if reserved != ReservedBytes::<LEN, VAL>::default() {
                Err(DecodeError::DataIntegrityError(format!(
                    "unsupported reserved byte value indicating a future RGB version. Please \
                     update your software, or, if the problem persists, contact your vendor \
                     providing the following version information: {reserved}"
                )))
            } else {
                Ok(reserved)
            }
        }
    }

    #[cfg(feature = "serde")]
    mod _serde {
        use std::fmt;

        use serde_crate::de::Visitor;
        use serde_crate::{de, Deserialize, Deserializer, Serialize, Serializer};

        use super::*;

        impl<const LEN: usize, const VAL: u8> Serialize for ReservedBytes<LEN, VAL> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where S: Serializer {
                // Doing nothing
                serializer.serialize_unit()
            }
        }

        impl<'de, const LEN: usize, const VAL: u8> Deserialize<'de> for ReservedBytes<LEN, VAL> {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where D: Deserializer<'de> {
                #[derive(Default)]
                pub struct UntaggedUnitVisitor;

                impl<'de> Visitor<'de> for UntaggedUnitVisitor {
                    type Value = ();

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        write!(formatter, "reserved unit")
                    }

                    fn visit_none<E>(self) -> Result<(), E>
                    where E: de::Error {
                        Ok(())
                    }

                    fn visit_unit<E>(self) -> Result<(), E>
                    where E: de::Error {
                        Ok(())
                    }
                }

                deserializer.deserialize_unit(UntaggedUnitVisitor)?;
                Ok(default!())
            }
        }
    }
}

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

// TODO: Validate strict type data
// TODO: Add parsed global and structured state to the ContractState

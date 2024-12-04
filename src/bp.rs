// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Designed in 2019-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
// Written in 2024-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association, Switzerland.
// Copyright (C) 2024-2025 LNP/BP Laboratories,
//                         Institute for Distributed and Cognitive Systems (InDCS), Switzerland.
// Copyright (C) 2025 RGB Consortium, Switzerland.
// Copyright (C) 2019-2025 Dr Maxim Orlovsky.
// All rights under the above copyrights are reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
// in compliance with the License. You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied. See the License for the specific language governing permissions and limitations under
// the License.

use core::fmt::{self, Debug, Display, Formatter};

use strict_encoding::{StrictDecode, StrictDumb, StrictEncode, StrictWriter};
use ultrasonic::Capabilities;

use crate::LIB_NAME_RGB_CORE;

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_CORE)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct Bp {
    pub layer: BpLayer,
    pub testnet: bool,
}

impl From<Bp> for [u8; 4] {
    fn from(bp: Bp) -> Self {
        let ast_data = StrictWriter::in_memory::<4>();
        let data = bp
            .strict_encode(ast_data)
            .expect("invalid BpPubl structure")
            .unbox()
            .unconfine();
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&data);
        buf
    }
}

impl Display for Bp {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self.testnet {
            f.write_str("test-")?;
        }
        Display::fmt(&self.layer, f)
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_CORE, tags = custom, dumb = Self::Bitcoin(strict_dumb!()))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase", tag = "blockchain", content = "seals")
)]
#[repr(u8)]
pub enum BpLayer {
    #[strict_type(tag = 0x00)]
    #[display("bitcoin:{0}")]
    Bitcoin(bp::dbc::Method),

    #[strict_type(tag = 0x01)]
    #[display("liquid:{0}")]
    Liquid(bp::dbc::Method),
}

impl Capabilities for Bp {}

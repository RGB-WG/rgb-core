// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2019-2024 Dr Maxim Orlovsky. All rights reserved.

use core::fmt::{self, Debug, Display, Formatter};

use strict_encoding::{StrictDecode, StrictDumb, StrictEncode, StrictWriter};
use ultrasonic::{Contract, ProofOfPubl};

use crate::LIB_NAME_RGB_CORE;

pub type ContractBp = Contract<Bp>;

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

impl ProofOfPubl for Bp {}

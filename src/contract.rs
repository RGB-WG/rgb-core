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
use core::str::FromStr;

use amplify::confinement::SmallString;
use amplify::{Bytes32, Wrapper};
use baid64::{Baid64ParseError, DisplayBaid64, FromBaid64Str};
use bp::dbc;
use commit_verify::{mpc, CommitmentId, DigestExt, ReservedBytes, Sha256};
use strict_encoding::{StrictDecode, StrictDumb, StrictEncode};
use ultrasonic::{Codex, Operation};

use crate::LIB_NAME_RGB_CORE;

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
    Bitcoin(dbc::Method),

    #[strict_type(tag = 0x01)]
    #[display("liquid:{0}")]
    Liquid(dbc::Method),
}

pub trait Layer1: Copy + Eq + StrictDumb + StrictEncode + StrictDecode + Debug + Display {}

impl Layer1 for BpLayer {}

#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = ContractId)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_CORE)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct Contract<L1: Layer1 = BpLayer> {
    pub layer1: L1,
    pub testnet: bool,
    // aligning to 16 byte edge
    #[cfg_attr(feature = "serde", serde(skip))]
    pub reserved: ReservedBytes<13>,
    pub salt: u64,
    pub timestamp: i64,
    // ^^ above is a fixed-size contract header of 32 bytes
    pub issuer: SmallString,
    pub codex: Codex,
    pub initial: Operation,
}

/// Unique contract identifier equivalent to the contract genesis commitment
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_CORE)]
pub struct ContractId(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl DisplayBaid64 for ContractId {
    const HRI: &'static str = "rgb";
    const CHUNKING: bool = true;
    const PREFIX: bool = true;
    const EMBED_CHECKSUM: bool = false;
    const MNEMONIC: bool = false;
    fn to_baid64_payload(&self) -> [u8; 32] { self.to_byte_array() }
}
impl FromBaid64Str for ContractId {}
impl FromStr for ContractId {
    type Err = Baid64ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_baid64_str(s) }
}
impl Display for ContractId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { self.fmt_baid64(f) }
}

impl From<Sha256> for ContractId {
    fn from(hasher: Sha256) -> Self { hasher.finish().into() }
}

impl CommitmentId for ContractId {
    const TAG: &'static str = "urn:lnp-bp:rgb:contract#2024-11-14";
}

impl From<mpc::ProtocolId> for ContractId {
    fn from(id: mpc::ProtocolId) -> Self { ContractId(id.into_inner()) }
}

impl From<ContractId> for mpc::ProtocolId {
    fn from(id: ContractId) -> Self { mpc::ProtocolId::from_inner(id.into_inner()) }
}

#[cfg(feature = "serde")]
mod _serde {
    use amplify::ByteArray;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::*;

    impl Serialize for ContractId {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer {
            if serializer.is_human_readable() {
                self.to_string().serialize(serializer)
            } else {
                self.to_byte_array().serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for ContractId {
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

/// Fast-forward version code
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Default, Debug, Display)]
#[display("RGB/1.{0}")]
#[derive(StrictType, StrictEncode)]
#[strict_type(lib = LIB_NAME_RGB_CORE)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(rename_all = "camelCase"))]
pub struct Ffv(u16);

mod _ffv {
    use strict_encoding::{DecodeError, ReadTuple, StrictDecode, TypedRead};

    use super::Ffv;

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

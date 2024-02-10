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

use std::fmt;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use amplify::hex::{FromHex, ToHex};
use amplify::{hex, ByteArray, Bytes32, FromSliceError, Wrapper};
use baid58::{Baid58ParseError, Chunking, FromBaid58, ToBaid58, CHUNKING_32CHECKSUM};
use commit_verify::{mpc, CommitmentId, DigestExt, Sha256};

use crate::LIB_NAME_RGB;

/// Unique contract identifier equivalent to the contract genesis commitment
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct ContractId(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl PartialEq<OpId> for ContractId {
    fn eq(&self, other: &OpId) -> bool { self.to_byte_array() == other.to_byte_array() }
}
impl PartialEq<ContractId> for OpId {
    fn eq(&self, other: &ContractId) -> bool { self.to_byte_array() == other.to_byte_array() }
}

impl ContractId {
    pub fn copy_from_slice(slice: impl AsRef<[u8]>) -> Result<Self, FromSliceError> {
        Bytes32::copy_from_slice(slice).map(Self)
    }
}

impl ToBaid58<32> for ContractId {
    const HRI: &'static str = "rgb";
    const CHUNKING: Option<Chunking> = CHUNKING_32CHECKSUM;
    fn to_baid58_payload(&self) -> [u8; 32] { self.to_byte_array() }
    fn to_baid58_string(&self) -> String { self.to_string() }
}
impl FromBaid58<32> for ContractId {}
impl Display for ContractId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(f, "{::^}", self.to_baid58())
        } else {
            write!(f, "{::^.3}", self.to_baid58())
        }
    }
}
impl FromStr for ContractId {
    type Err = Baid58ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_baid58_maybe_chunked_str(s, ':', '#')
    }
}

impl From<mpc::ProtocolId> for ContractId {
    fn from(id: mpc::ProtocolId) -> Self { ContractId(id.into_inner()) }
}

impl From<ContractId> for mpc::ProtocolId {
    fn from(id: ContractId) -> Self { mpc::ProtocolId::from_inner(id.into_inner()) }
}

/// Unique operation (genesis, extensions & state transition) identifier
/// equivalent to the commitment hash
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[display(Self::to_hex)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct OpId(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl From<Sha256> for OpId {
    fn from(hasher: Sha256) -> Self { hasher.finish().into() }
}

impl CommitmentId for OpId {
    const TAG: &'static str = "urn:lnpbp:rgb:operation#2024-02-03";
}

impl FromStr for OpId {
    type Err = hex::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_hex(s) }
}

impl OpId {
    pub fn copy_from_slice(slice: impl AsRef<[u8]>) -> Result<Self, FromSliceError> {
        Bytes32::copy_from_slice(slice).map(Self)
    }
}

// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2023 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2019-2023 Dr Maxim Orlovsky. All rights reserved.
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

use std::str::FromStr;

use amplify::confinement::TinyString;
use amplify::{Bytes32, RawArray};
use baid58::{Baid58ParseError, FromBaid58, ToBaid58};
use bp::secp256k1::rand::{thread_rng, RngCore};
use commit_verify::{CommitStrategy, CommitVerify, Conceal, StrictEncodedProtocol};
use strict_encoding::StrictEncode;

use super::{ConfidentialState, ExposedState};
use crate::LIB_NAME_RGB;

/// Unique data attachment identifier
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[display(Self::to_baid58)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct AttachId(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl ToBaid58<32> for AttachId {
    const HRI: &'static str = "att";
    fn to_baid58_payload(&self) -> [u8; 32] { self.to_raw_array() }
}
impl FromBaid58<32> for AttachId {}

impl FromStr for AttachId {
    type Err = Baid58ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_baid58_str(s) }
}

#[derive(Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Debug, AsAny)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB, rename = "RevealedAttach")]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Revealed {
    pub id: AttachId,
    /// We do not enforce a MIME standard since non-standard types can be also
    /// used
    pub media_type: TinyString,
    pub salt: u64,
}

impl Revealed {
    /// Creates new revealed attachment for the attachment id and MIME type.
    /// Uses `thread_rng` to initialize [`Revealed::salt`].
    pub fn new(id: AttachId, media_type: impl Into<TinyString>) -> Self {
        Self {
            id,
            media_type: media_type.into(),
            salt: thread_rng().next_u64(),
        }
    }
}

impl ExposedState for Revealed {
    type Confidential = Confidential;
}

impl Conceal for Revealed {
    type Concealed = Confidential;

    fn conceal(&self) -> Self::Concealed { Confidential::commit(self) }
}
impl CommitStrategy for Revealed {
    type Strategy = commit_verify::strategies::ConcealStrict;
}

/// Confidential version of an attachment information.
///
/// See also revealed version [`Revealed`].
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From, AsAny)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB, rename = "ConcealedAttach")]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct Confidential(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl ConfidentialState for Confidential {}

impl CommitStrategy for Confidential {
    type Strategy = commit_verify::strategies::Strict;
}

impl CommitVerify<Revealed, StrictEncodedProtocol> for Confidential {
    fn commit(revealed: &Revealed) -> Self { Bytes32::commit(revealed).into() }
}

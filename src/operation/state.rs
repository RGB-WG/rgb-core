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

use core::fmt::Debug;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use amplify::confinement::{SmallBlob, U16 as U16MAX};
use amplify::{Bytes32, Wrapper};
use baid64::{Baid64ParseError, DisplayBaid64, FromBaid64Str};
use commit_verify::{CommitmentId, DigestExt, ReservedBytes, Sha256};
use strict_encoding::{StrictSerialize, StrictType};

use crate::{impl_serde_baid64, LIB_NAME_RGB_COMMIT};

/// Unique data attachment identifier
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
pub struct AttachId(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl DisplayBaid64 for AttachId {
    const HRI: &'static str = "rgb:fs";
    const CHUNKING: bool = true;
    const PREFIX: bool = true;
    const EMBED_CHECKSUM: bool = false;
    const MNEMONIC: bool = true;
    fn to_baid64_payload(&self) -> [u8; 32] { self.to_byte_array() }
}
impl FromBaid64Str for AttachId {}
impl FromStr for AttachId {
    type Err = Baid64ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_baid64_str(s) }
}
impl Display for AttachId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { self.fmt_baid64(f) }
}

impl_serde_baid64!(AttachId);

#[derive(Clone, PartialOrd, Ord, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = StateCommitment)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct State {
    pub reserved: ReservedBytes<1>,
    pub value: SmallBlob,
    pub attach: Option<AttachId>,
}

impl State {
    /// # Panics
    ///
    /// If the size of the serialized value exceeds 0xFFFF bytes.
    pub fn new(value: impl StrictSerialize) -> Self {
        State {
            reserved: default!(),
            value: value
                .to_strict_serialized::<U16MAX>()
                .expect("unable to fit in the data"),
            attach: None,
        }
    }

    /// # Panics
    ///
    /// If the size of the serialized value exceeds 0xFFFF bytes.
    pub fn with(value: impl StrictSerialize, attach: AttachId) -> Self {
        State {
            reserved: default!(),
            value: value
                .to_strict_serialized::<U16MAX>()
                .expect("unable to fit in the data"),
            attach: Some(attach),
        }
    }
}

/// Confidential version of a structured state data.
///
/// See also revealed version [`State`].
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT, rename = "ConcealedData")]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct StateCommitment(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl From<Sha256> for StateCommitment {
    fn from(hasher: Sha256) -> Self { hasher.finish().into() }
}

impl CommitmentId for StateCommitment {
    const TAG: &'static str = "urn:lnp-bp:rgb:state-data#2024-10-13";
}

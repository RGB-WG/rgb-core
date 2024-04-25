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

use amplify::{ByteArray, Bytes32};
use baid64::{Baid64ParseError, DisplayBaid64, FromBaid64Str};
use bp::secp256k1::rand::{random, Rng, RngCore};
use commit_verify::{CommitId, CommitmentId, Conceal, DigestExt, Sha256};
use strict_encoding::StrictEncode;

use super::{ConfidentialState, ExposedState};
use crate::{impl_serde_baid64, ConcealedState, MediaType, RevealedState, StateType, LIB_NAME_RGB};

/// Unique data attachment identifier
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
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

#[derive(Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = ConcealedAttach)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct RevealedAttach {
    pub id: AttachId,
    /// We do not enforce a MIME standard since non-standard types can be also
    /// used
    pub media_type: MediaType,
    pub salt: u64,
}

impl RevealedAttach {
    /// Constructs new state using the provided value using random blinding
    /// factor.
    pub fn new_random_salt(id: AttachId, media_type: impl Into<MediaType>) -> Self {
        Self::with_salt(id, media_type, random())
    }

    /// Constructs new state using the provided value and random generator for
    /// creating blinding factor.
    pub fn with_rng<R: Rng + RngCore>(
        id: AttachId,
        media_type: impl Into<MediaType>,
        rng: &mut R,
    ) -> Self {
        Self::with_salt(id, media_type, rng.next_u64())
    }

    /// Convenience constructor.
    pub fn with_salt(id: AttachId, media_type: impl Into<MediaType>, salt: u64) -> Self {
        Self {
            id,
            media_type: media_type.into(),
            salt,
        }
    }
}

impl ExposedState for RevealedAttach {
    type Confidential = ConcealedAttach;
    fn state_type(&self) -> StateType { StateType::Attachment }
    fn state_data(&self) -> RevealedState { RevealedState::Attachment(self.clone()) }
}

impl Conceal for RevealedAttach {
    type Concealed = ConcealedAttach;

    fn conceal(&self) -> Self::Concealed { self.commit_id() }
}

/// Confidential version of an attachment information.
///
/// See also revealed version [`RevealedAttach`].
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct ConcealedAttach(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl ConfidentialState for ConcealedAttach {
    fn state_type(&self) -> StateType { StateType::Attachment }
    fn state_commitment(&self) -> ConcealedState { ConcealedState::Attachment(*self) }
}

impl From<Sha256> for ConcealedAttach {
    fn from(hasher: Sha256) -> Self { hasher.finish().into() }
}

impl CommitmentId for ConcealedAttach {
    const TAG: &'static str = "urn:lnp-bp:rgb:state-attach#2024-02-12";
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn attach_id_display() {
        const ID: &str =
            "rgb:fs:bGxsbGxs-bGxsbGx-sbGxsbG-xsbGxsb-GxsbGxs-bGxsbGw#invite-potato-oval";
        let id = AttachId::from_byte_array([0x6c; 32]);
        assert_eq!(ID, id.to_string());
        assert_eq!(ID, id.to_baid64_string());
        assert_eq!("invite-potato-oval", id.to_baid64_mnemonic());
    }

    #[test]
    fn attach_id_from_str() {
        let id = AttachId::from_byte_array([0x6c; 32]);
        assert_eq!(
            id,
            AttachId::from_str(
                "rgb:fs:bGxsbGxs-bGxsbGx-sbGxsbG-xsbGxsb-GxsbGxs-bGxsbGw#invite-potato-oval"
            )
            .unwrap()
        );
        assert_eq!(
            id,
            AttachId::from_str("rgb:fs:bGxsbGxs-bGxsbGx-sbGxsbG-xsbGxsb-GxsbGxs-bGxsbGw").unwrap()
        );
    }
}

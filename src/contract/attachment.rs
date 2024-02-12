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

use std::str::FromStr;

use amplify::{ByteArray, Bytes32};
use baid58::{Baid58ParseError, Chunking, FromBaid58, ToBaid58, CHUNKING_32};
use bp::secp256k1::rand::{random, Rng, RngCore};
use commit_verify::{CommitId, CommitmentId, Conceal, DigestExt, Sha256};
use strict_encoding::StrictEncode;

use super::{ConfidentialState, ExposedState};
use crate::{ConcealedState, MediaType, RevealedState, StateType, LIB_NAME_RGB};

/// Unique data attachment identifier
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, From)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[display(Self::to_baid58_string)]
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
    const HRI: &'static str = "stashfs";
    const CHUNKING: Option<Chunking> = CHUNKING_32;
    fn to_baid58_payload(&self) -> [u8; 32] { self.to_byte_array() }
    fn to_baid58_string(&self) -> String { self.to_string() }
}
impl FromBaid58<32> for AttachId {}
impl FromStr for AttachId {
    type Err = Baid58ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_baid58_chunked_str(s, ':', '#') }
}
impl AttachId {
    pub fn to_baid58_string(&self) -> String { format!("{::<#.2}", self.to_baid58()) }
    pub fn to_mnemonic(&self) -> String { self.to_baid58().mnemonic() }
}

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
    const TAG: &'static str = "urn:lnpbp:rgb:state-attach#2024-02-12";
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn attach_id_display() {
        const ID: &str =
            "stashfs:8JEvTX-J6sD5U4n-1p7GEERY-MPN9ijjs-9ZM4ysJ3-qhgyqM#juice-empty-joker";
        let id = AttachId::from_byte_array([0x6c; 32]);
        assert_eq!(ID, id.to_string());
        assert_eq!(ID, id.to_baid58_string());
        assert_eq!("juice-empty-joker", id.to_mnemonic());
    }

    #[test]
    fn attach_id_from_str() {
        let id = AttachId::from_byte_array([0x6c; 32]);
        assert_eq!(
            Ok(id),
            AttachId::from_str(
                "stashfs:8JEvTX-J6sD5U4n-1p7GEERY-MPN9ijjs-9ZM4ysJ3-qhgyqM#juice-empty-joker"
            )
        );
        assert_eq!(
            Ok(id),
            AttachId::from_str("stashfs:8JEvTX-J6sD5U4n-1p7GEERY-MPN9ijjs-9ZM4ysJ3-qhgyqM")
        );
    }
}

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

use amplify::confinement::SmallBlob;
use amplify::{confinement, ByteArray, Bytes32, Wrapper};
use baid64::{Baid64ParseError, DisplayBaid64, FromBaid64Str};
use base64::alphabet::Alphabet;
use base64::engine::general_purpose::NO_PAD;
use base64::engine::GeneralPurpose;
use base64::Engine;
use commit_verify::{CommitmentId, DigestExt, ReservedBytes, Sha256};
use strict_encoding::{SerializeError, StrictDeserialize, StrictSerialize, StrictType};

use crate::{impl_serde_baid64, LIB_NAME_RGB_COMMIT};

pub const STATE_DATA_MAX_LEN: usize = confinement::U16;

// We put in the middle the least desirable characters to occur in typical numbers.
pub const STATE_DATA_BASE32_ALPHABET: &str =
    "-abcdefghijklmnopqrstuvwxyz!#@&$ABCDEFGHIJKLMNOPQRSTUVWXYZ*~;:.,";

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

/// Binary state data, serialized using strict type notation from the structured data type.
#[derive(Wrapper, Clone, PartialOrd, Ord, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, AsSlice, BorrowSlice, Index, RangeOps)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct StateData(SmallBlob);

impl StrictSerialize for StateData {}
impl StrictDeserialize for StateData {}

impl StateData {
    /// Constructs new state data by performing strict serialization of the provided structured
    /// data type.
    ///
    /// The data type must implement [`StrictSerialize`].
    ///
    /// # NB
    ///
    /// Use the function carefully, since the common pitfall here is to perform double serialization
    /// of an already serialized data type, like `SmallBlob`. This produces an invalid state object
    /// which can't be properly parsed later.
    ///
    /// # Errors
    ///
    /// If the size of the serialized value exceeds 0xFFFF bytes.
    pub fn from_serialized(typed_data: &impl StrictSerialize) -> Result<Self, SerializeError> {
        typed_data
            .to_strict_serialized::<STATE_DATA_MAX_LEN>()
            .map(Self)
    }

    pub fn from_checked(vec: Vec<u8>) -> Self { Self(SmallBlob::from_checked(vec)) }

    pub fn as_slice(&self) -> &[u8] { self.0.as_slice() }

    fn to_base64(&self) -> String {
        let alphabet =
            Alphabet::new(STATE_DATA_BASE32_ALPHABET).expect("invalid state data alphabet");
        let engine = GeneralPurpose::new(&alphabet, NO_PAD);
        engine.encode(&self)
    }

    fn from_base64(s: &str) -> Result<Self, StateParseError> {
        let alphabet =
            Alphabet::new(STATE_DATA_BASE32_ALPHABET).expect("invalid state data alphabet");
        let engine = GeneralPurpose::new(&alphabet, NO_PAD);
        let data = engine.decode(s)?;
        Ok(Self(SmallBlob::try_from(data)?))
    }
}

impl Display for StateData {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { f.write_str(&self.to_base64()) }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum StateParseError {
    /// encoded state data exceed maximal length of 0xFFFF bytes.
    #[from]
    Len(confinement::Error),
    /// state data have invalid encoding - {0}
    #[from]
    Base64(base64::DecodeError),
}

impl FromStr for StateData {
    type Err = StateParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_base64(s) }
}

#[derive(Clone, PartialOrd, Ord, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_COMMIT)]
#[derive(CommitEncode)]
#[commit_encode(strategy = strict, id = StateCommitment)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct State {
    pub reserved: ReservedBytes<1>,
    pub data: StateData,
    pub attach: Option<AttachId>,
}

impl From<StateData> for State {
    /// Constructs new state object using the provided pre-serialized binary data. Sets attachment
    /// to `None`.
    fn from(data: StateData) -> Self {
        State {
            reserved: default!(),
            data,
            attach: None,
        }
    }
}

impl State {
    /// Constructs new state object by performing strict serialization of the provided structured
    /// data type. Sets attachment to `None`.
    ///
    /// The data type must implement [`StrictSerialize`].
    ///
    /// # NB
    ///
    /// Use the function carefully, since the common pitfall here is to perform double serialization
    /// of an already serialized data type, like `SmallBlob`. This produces an invalid state object
    /// which can't be properly parsed later.
    ///
    /// # Panics
    ///
    /// If the size of the serialized value exceeds 0xFFFF bytes.
    pub fn from_serialized(typed_data: &impl StrictSerialize) -> Result<Self, SerializeError> {
        Ok(State {
            reserved: default!(),
            data: StateData::from_serialized(typed_data)?,
            attach: None,
        })
    }

    /// Constructs new state object using the provided pre-serialized binary data and attachment
    /// information.
    pub fn with(data: StateData, attach_id: AttachId) -> Self {
        State {
            reserved: default!(),
            data,
            attach: Some(attach_id),
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

#[cfg(test)]
mod test {
    use super::*;

    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Default, From)]
    #[display(inner)]
    #[derive(StrictType, StrictEncode, StrictDecode)]
    #[strict_type(lib = "Test")]
    struct Amount(pub u64);
    impl StrictSerialize for Amount {}
    impl StrictDeserialize for Amount {}

    #[test]
    fn state_data_encoding() {
        const STR: &str = "*-l--------";
        let amount = Amount(1000u64);
        let data = StateData::from_serialized(&amount).unwrap();
        assert_eq!(data.as_slice(), &[0xe8, 0x03, 0, 0, 0, 0, 0, 0]);
        assert_eq!(data.to_string(), STR);
        assert_eq!(StateData::from_str(STR).unwrap(), data);
        StateData::from_str("U").unwrap_err();
    }

    #[test]
    fn typical_encodings() {
        const ENC: &[&str] = &[
            "-----------", // 0
            "-p---------", // 1
            "-A---------", // 2
            "-Q---------", // 3
            "a----------", // 4
            "ap---------", // 5
            "aA---------", // 6
            "aQ---------", // 7
            "b----------", // 8
            "bp---------", // 9
            "bA---------", // 10
            "e----------", // 20
            "gA---------", // 30
            "j----------", // 40
            "lA---------", // 50
            "y----------", // 100
            "S----------", // 200
            ".A---------", // 250
            "k-d--------", // 300
            ":-d--------", // 500
            "~Ah--------", // 750
            "*-l--------", // 1000
            "db#--------", // 10000
            "hdY--------", // 20000
            "Kfd--------", // 25000
            "tll--------", // 50000
            "Ihxa-------", // 100000
            "hjdg-------", // 500000
            "pdho-------", // 1000000
        ];
        const VAL: &[u64] = &[
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 20, 30, 40, 50, 100, 200, 250, 300, 500, 750, 1000,
            10_000, 20_000, 25_000, 50_000, 100_000, 500_000, 1_000_000,
        ];
        for (idx, val) in VAL.iter().enumerate() {
            let data = StateData::from_serialized(&Amount(*val)).unwrap();
            //println!(r#""{data}", // {val}"#);
            assert_eq!(data.to_string(), ENC[idx]);
        }
    }

    // Ensures that no decimal integer represents a valid state encoding
    #[test]
    fn no_int_encoding() {
        for int in 1..100 {
            StateData::from_str(&int.to_string()).unwrap_err();
        }
        for int in 1..=10 {
            StateData::from_str(&(int * 10).to_string()).unwrap_err();
        }
        for int in 11..100 {
            StateData::from_str(&(int * 10).to_string()).unwrap_err();
        }
    }

    #[test]
    fn state_data_limits() {
        #[derive(Clone, Eq, PartialEq, Hash)]
        #[derive(StrictType, StrictEncode, StrictDecode)]
        #[strict_type(lib = "Test")]
        struct MaxData(Box<[u8; STATE_DATA_MAX_LEN]>);
        impl Default for MaxData {
            fn default() -> Self { Self(Box::new([0xACu8; STATE_DATA_MAX_LEN])) }
        }
        impl StrictSerialize for MaxData {}

        let data = StateData::from_serialized(&MaxData::default()).unwrap();
        assert_eq!(data.len(), STATE_DATA_MAX_LEN);
        for byte in data.0 {
            assert_eq!(byte, 0xAC)
        }
    }
}

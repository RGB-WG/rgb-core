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

#![allow(clippy::unnecessary_cast)]

use core::any::Any;
use core::fmt::Debug;
use std::io;

use amplify::AsAny;
use bitcoin_hashes::{sha256, sha256t};
use commit_verify::CommitEncode;

use super::{ConfidentialState, RevealedState};

/// Struct using for storing Void (i.e. absent) state
#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, Display, AsAny)]
#[display("void")]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct Void();

impl ConfidentialState for Void {}

impl RevealedState for Void {}

impl CommitConceal for Void {
    type ConcealedCommitment = Void;

    fn commit_conceal(&self) -> Self::ConcealedCommitment { self.clone() }
}
impl CommitEncode for Void {
    fn commit_encode<E: io::Write>(&self, _e: E) -> usize { 0 }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, AsAny)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct Revealed(Vec<u8>);

impl RevealedState for Revealed {}

impl CommitConceal for Revealed {
    type ConcealedCommitment = Confidential;

    fn commit_conceal(&self) -> Self::ConcealedCommitment {
        Confidential::hash(
            &strict_serialize(self).expect("Encoding of predefined data types must not fail"),
        )
    }
}
impl commit_encode::Strategy for Revealed {
    type Strategy = commit_encode::strategies::UsingConceal;
}

// "rgb:data:confidential"
static MIDSTATE_CONFIDENTIAL_DATA: [u8; 32] = [
    151, 235, 12, 105, 100, 154, 61, 159, 108, 179, 41, 229, 218, 159, 57, 12, 233, 248, 167, 213,
    228, 9, 202, 215, 27, 84, 249, 215, 93, 189, 75, 146,
];

/// Tag used for [`Confidential`] hash value of the data
pub struct ConfidentialTag;

impl sha256t::Tag for ConfidentialTag {
    #[inline]
    fn engine() -> sha256::HashEngine {
        let midstate = sha256::Midstate::from_inner(MIDSTATE_CONFIDENTIAL_DATA);
        sha256::HashEngine::from_midstate(midstate, 64)
    }
}

/// Blind version of transaction outpoint-based single-use-seal
#[derive(Wrapper, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, From)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
#[wrapper(Debug, Display, BorrowSlice)]
pub struct Confidential(sha256t::Hash<ConfidentialTag>);

impl commit_encode::Strategy for Confidential {
    type Strategy = commit_encode::strategies::UsingStrict;
}

impl ConfidentialState for Confidential {}

impl AsAny for Confidential {
    fn as_any(&self) -> &dyn Any { self as &dyn Any }
}

#[cfg(test)]
mod test {
    use amplify::Wrapper;
    use commit_verify::tagged_hash;

    use super::super::test::test_confidential;
    use super::*;

    // Hard coded test vectors
    static U_8: [u8; 2] = [0x0, 0x8];
    static U_16: [u8; 3] = [0x1, 0x10, 0x0];
    static U_32: [u8; 5] = [0x2, 0x20, 0x0, 0x0, 0x0];
    static U_64: [u8; 9] = [0x3, 0x40, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0];
    static I_8: [u8; 2] = [0x8, 0x8];
    static I_16: [u8; 3] = [0x9, 0x10, 0x0];
    static I_32: [u8; 5] = [0xa, 0x20, 0x0, 0x0, 0x0];
    static I_64: [u8; 9] = [0xb, 0x40, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0];
    static F_32: [u8; 5] = [0x12, 0x14, 0xae, 0x2, 0x42];
    static F_64: [u8; 9] = [0x13, 0x7b, 0x14, 0xae, 0x47, 0xe1, 0x2a, 0x50, 0x40];
    static BYTES: [u8; 36] = [
        0x20, 0x21, 0x0, 0x7c, 0x66, 0xc0, 0x28, 0x3e, 0xe9, 0xbe, 0x98, 0xe, 0x29, 0xce, 0x32,
        0x5a, 0xf, 0x46, 0x79, 0xef, 0x87, 0x28, 0x8e, 0xd7, 0x3c, 0xe4, 0x7f, 0xc4, 0xf5, 0xc7,
        0x9d, 0x19, 0xeb, 0xfa, 0x57, 0xda,
    ];
    static STRING: [u8; 20] = [
        0x21, 0x11, 0x0, 0x45, 0x54, 0x48, 0x20, 0x49, 0x53, 0x20, 0x41, 0x20, 0x53, 0x45, 0x43,
        0x55, 0x52, 0x49, 0x54, 0x59,
    ];

    static U8_CONCEALED: [u8; 32] = [
        161, 96, 17, 80, 21, 40, 216, 159, 16, 118, 181, 5, 129, 1, 104, 13, 140, 180, 187, 73,
        167, 191, 192, 20, 193, 188, 208, 129, 106, 33, 92, 39,
    ];
    static U16_CONCEALED: [u8; 32] = [
        80, 54, 157, 249, 250, 32, 49, 160, 128, 1, 178, 23, 207, 113, 37, 140, 67, 7, 13, 62, 216,
        70, 81, 20, 180, 35, 104, 112, 98, 181, 18, 102,
    ];
    static U32_CONCEALED: [u8; 32] = [
        121, 102, 29, 211, 144, 20, 177, 201, 217, 150, 2, 207, 78, 113, 204, 38, 38, 105, 164, 68,
        227, 224, 14, 236, 77, 60, 101, 225, 174, 12, 230, 161,
    ];
    static U64_CONCEALED: [u8; 32] = [
        80, 99, 180, 211, 149, 79, 160, 168, 50, 150, 54, 190, 65, 240, 179, 156, 212, 5, 211, 72,
        82, 27, 87, 184, 156, 76, 44, 148, 102, 137, 212, 28,
    ];
    static I8_CONCEALED: [u8; 20] = [
        0xf5, 0x39, 0x1f, 0xf2, 0x83, 0x2b, 0xc6, 0xb1, 0x78, 0x59, 0x54, 0x14, 0x28, 0xbf, 0xc1,
        0x49, 0xf6, 0xcf, 0xd7, 0x78,
    ];
    static I16_CONCEALED: [u8; 20] = [
        0x61, 0x0, 0xc2, 0x37, 0x7, 0x97, 0x33, 0xf, 0xcf, 0xbb, 0x40, 0xcb, 0xad, 0xf7, 0x81,
        0x7e, 0x10, 0xd, 0x55, 0xa5,
    ];
    static I32_CONCEALED: [u8; 20] = [
        0xaa, 0xbe, 0x9b, 0x73, 0xf8, 0xfa, 0x84, 0x9d, 0x28, 0x79, 0x8b, 0x5c, 0x13, 0x91, 0xe9,
        0xbf, 0xc8, 0xa4, 0x2a, 0xc3,
    ];
    static I64_CONCEALED: [u8; 20] = [
        0xd, 0x56, 0xef, 0xcb, 0x53, 0xba, 0xd5, 0x52, 0xb, 0xc6, 0xea, 0x4f, 0xe1, 0xa8, 0x56,
        0x42, 0x3d, 0x66, 0x34, 0xc5,
    ];
    static F32_CONCEALED: [u8; 20] = [
        0xa2, 0xb0, 0x80, 0x82, 0xa9, 0x52, 0xa5, 0x41, 0xb8, 0xbd, 0x2, 0xd4, 0x29, 0xf0, 0x90,
        0xca, 0x8b, 0xa4, 0x5d, 0xfc,
    ];
    static F64_CONCEALED: [u8; 20] = [
        0x5f, 0xe8, 0xdd, 0xd4, 0xca, 0x55, 0x41, 0x14, 0x50, 0x24, 0xcf, 0x85, 0x8c, 0xb4, 0x11,
        0x5d, 0x9f, 0x8a, 0xaf, 0x87,
    ];
    static BYTES_CONCEALED: [u8; 20] = [
        0xf, 0x33, 0xe5, 0xdf, 0x8, 0x7c, 0x5c, 0xef, 0x5f, 0xae, 0xbe, 0x76, 0x76, 0xd9, 0xe7,
        0xa6, 0xb8, 0x2b, 0x4a, 0x99,
    ];
    static STRING_CONCEALED: [u8; 20] = [
        0xf8, 0x3b, 0x1b, 0xcd, 0xd8, 0x82, 0x55, 0xe1, 0xf9, 0x37, 0x52, 0xeb, 0x20, 0x90, 0xfe,
        0xa9, 0x14, 0x4f, 0x8a, 0xe1,
    ];

    #[test]
    fn test_confidential_midstate() {
        let midstate = tagged_hash::Midstate::with(b"rgb:data:confidential");
        assert_eq!(midstate.into_inner().into_inner(), MIDSTATE_CONFIDENTIAL_DATA);
    }

    // Normal encode/decode testing
    /*
    #[test]
    #[ignore]
    fn test_encoding() {
    test_encode!(
        (U_8, Revealed),
        (U_16, Revealed),
        (U_32, Revealed),
        (U_64, Revealed),
        (I_8, Revealed),
        (I_16, Revealed),
        (I_32, Revealed),
        (I_64, Revealed),
        (F_32, Revealed),
        (F_64, Revealed),
        (BYTES, Revealed),
        (STRING, Revealed)
    );
    }

    // Garbage data encode/decode testing
    #[test]
    #[ignore]
    fn test_garbage() {
        let err = "Revealed";
        test_garbage_exhaustive!(150..255;
            (U_8, Revealed, err),
            (U_16, Revealed, err),
            (U_32, Revealed, err),
            (U_64, Revealed, err),
            (I_8, Revealed, err),
            (I_16, Revealed, err),
            (I_32, Revealed, err),
            (I_64, Revealed, err),
            (F_32, Revealed, err),
            (F_64, Revealed, err),
            (BYTES, Revealed, err),
            (STRING, Revealed, err)
        );
    }
     */

    #[test]
    #[ignore]
    fn test_conf1() {
        macro_rules! test_confidential {
            ($(($revealed:ident, $conf:ident, $T:ty)),*) => (
                {
                    $(
                        test_confidential::<$T>(&$revealed[..], &$conf[..], &$conf[..]);
                    )*
                }
            );
        }

        test_confidential!(
            (U_8, U8_CONCEALED, Revealed),
            (U_16, U16_CONCEALED, Revealed),
            (U_32, U32_CONCEALED, Revealed),
            (U_64, U64_CONCEALED, Revealed),
            (I_8, I8_CONCEALED, Revealed),
            (I_16, I16_CONCEALED, Revealed),
            (I_32, I32_CONCEALED, Revealed),
            (I_64, I64_CONCEALED, Revealed),
            (F_32, F32_CONCEALED, Revealed),
            (F_64, F64_CONCEALED, Revealed),
            (F_64, F64_CONCEALED, Revealed),
            (BYTES, BYTES_CONCEALED, Revealed),
            (STRING, STRING_CONCEALED, Revealed)
        );
    }
}

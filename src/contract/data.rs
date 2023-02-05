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

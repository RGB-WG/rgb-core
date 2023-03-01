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

use core::fmt::Debug;
use std::io;

use amplify::confinement::SmallVec;
use amplify::{AsAny, Bytes32};
use commit_verify::{CommitStrategy, CommitVerify, Conceal, StrictEncodedProtocol};
use strict_encoding::{DecodeError, StrictDecode, StrictEncode, StrictType, TypedRead, TypedWrite};

use super::{ConfidentialState, RevealedState};
use crate::LIB_NAME_RGB;

/// Struct using for storing Void (i.e. absent) state
#[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, Display, Default, AsAny)]
#[display("void")]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct Void;

impl StrictType for Void {
    const STRICT_LIB_NAME: &'static str = LIB_NAME_RGB;
}
impl StrictEncode for Void {
    fn strict_encode<W: TypedWrite>(&self, writer: W) -> io::Result<W> { Ok(writer) }
}
impl StrictDecode for Void {
    fn strict_decode(_reader: &mut impl TypedRead) -> Result<Self, DecodeError> { Ok(Void) }
}

impl ConfidentialState for Void {}

impl RevealedState for Void {}

impl Conceal for Void {
    type Concealed = Void;
    fn conceal(&self) -> Self::Concealed { *self }
}
impl CommitStrategy for Void {
    type Strategy = commit_verify::strategies::Strict;
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, AsAny)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB, rename = "RevealedData")]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct Revealed(SmallVec<u8>);

impl RevealedState for Revealed {}

impl Conceal for Revealed {
    type Concealed = Confidential;
    fn conceal(&self) -> Self::Concealed { Confidential::commit(self) }
}
impl CommitStrategy for Revealed {
    type Strategy = commit_verify::strategies::ConcealStrict;
}

/// Confidential version of an structured state data.
///
/// See also revealed version [`Revealed`].
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From, AsAny)]
#[wrapper(Deref, BorrowSlice, Hex, Index, RangeOps)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB, rename = "ConcealedData")]
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

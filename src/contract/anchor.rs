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

use std::cmp::Ordering;
use std::ops::{Deref, DerefMut};

use bp::dbc;
use commit_verify::mpc;
use strict_encoding::StrictDumb;

use crate::{TransitionBundle, WitnessId, WitnessOrd, LIB_NAME_RGB};

#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct AnchoredBundle {
    pub anchor: Anchor,
    pub bundle: TransitionBundle,
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB, tags = custom, dumb = Self::Bitcoin(strict_dumb!()))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[non_exhaustive]
pub enum Anchor<P: mpc::Proof + StrictDumb = mpc::MerkleProof> {
    #[strict_type(tag = 0x00)]
    Bitcoin(dbc::Anchor<P>),

    #[strict_type(tag = 0x01)]
    Liquid(dbc::Anchor<P>),
}

impl<P: mpc::Proof + StrictDumb> Deref for Anchor<P> {
    type Target = dbc::Anchor<P>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        match self {
            Anchor::Bitcoin(anchor) | Anchor::Liquid(anchor) => anchor,
        }
    }
}

impl<P: mpc::Proof + StrictDumb> DerefMut for Anchor<P> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Anchor::Bitcoin(anchor) | Anchor::Liquid(anchor) => anchor,
        }
    }
}

impl<P: mpc::Proof + StrictDumb> Anchor<P> {
    #[inline]
    pub fn layer1(&self) -> Layer1 {
        match self {
            Anchor::Bitcoin(_) => Layer1::Bitcoin,
            Anchor::Liquid(_) => Layer1::Liquid,
        }
    }
}

/// Txid and height information ordered according to the RGB consensus rules.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[display("{witness_id}/{witness_ord}")]
#[non_exhaustive]
pub struct WitnessAnchor {
    pub witness_ord: WitnessOrd,
    pub witness_id: WitnessId,
}

impl PartialOrd for WitnessAnchor {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl Ord for WitnessAnchor {
    fn cmp(&self, other: &Self) -> Ordering {
        if self == other {
            return Ordering::Equal;
        }
        match self.witness_ord.cmp(&other.witness_ord) {
            Ordering::Less => Ordering::Less,
            Ordering::Greater => Ordering::Greater,
            Ordering::Equal => self.witness_id.cmp(&other.witness_id),
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display(lowercase)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB, tags = repr, into_u8, try_from_u8)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[repr(u8)]
#[non_exhaustive]
pub enum Layer1 {
    #[strict_type(dumb)]
    Bitcoin = 0,
    Liquid = 1,
}

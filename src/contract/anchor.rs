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

use bp::{dbc, Txid};
use commit_verify::mpc;
use commit_verify::mpc::{Message, ProtocolId};

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
pub enum Anchor {
    #[strict_type(tag = 0x00)]
    Bitcoin(dbc::Anchor<mpc::MerkleProof>),

    #[strict_type(tag = 0x01)]
    Liquid(dbc::Anchor<mpc::MerkleProof>),
}

impl Anchor {
    pub fn layer1(&self) -> Layer1 {
        match self {
            Anchor::Bitcoin(_) => Layer1::Bitcoin,
            Anchor::Liquid(_) => Layer1::Liquid,
        }
    }

    /// Verifies that the anchor commits to the given message under the given
    /// protocol.
    pub fn convolve(
        &self,
        protocol_id: impl Into<ProtocolId>,
        message: Message,
    ) -> Result<mpc::Commitment, mpc::InvalidProof> {
        match self {
            Anchor::Bitcoin(anchor) | Anchor::Liquid(anchor) => {
                anchor.mpc_proof.convolve(protocol_id.into(), message)
            }
        }
    }
}

/// Txid and height information ordered according to the RGB consensus rules.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB, tags = custom, dumb = Self::Bitcoin(strict_dumb!(), strict_dumb!()))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[non_exhaustive]
pub enum WitnessAnchor {
    #[strict_type(tag = 0x00, dumb)]
    #[display("bitcoin:{0}/{1}")]
    Bitcoin(WitnessOrd, Txid),

    #[strict_type(tag = 0x01)]
    #[display("liquid:{0}/{1}")]
    Liquid(WitnessOrd, Txid),
}

impl PartialOrd for WitnessAnchor {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl Ord for WitnessAnchor {
    fn cmp(&self, other: &Self) -> Ordering {
        if self == other {
            return Ordering::Equal;
        }
        match (self, other) {
            (WitnessAnchor::Bitcoin(..), WitnessAnchor::Liquid(..)) => Ordering::Less,
            (WitnessAnchor::Liquid(..), WitnessAnchor::Bitcoin(..)) => Ordering::Greater,
            (
                WitnessAnchor::Bitcoin(ord1, txid1) | WitnessAnchor::Liquid(ord1, txid1),
                WitnessAnchor::Bitcoin(ord2, txid2) | WitnessAnchor::Liquid(ord2, txid2),
            ) if ord1 == ord2 => txid1.cmp(txid2),
            (
                WitnessAnchor::Bitcoin(ord1, _) | WitnessAnchor::Liquid(ord1, _),
                WitnessAnchor::Bitcoin(ord2, _) | WitnessAnchor::Liquid(ord2, _),
            ) => ord1.cmp(ord2),
        }
    }
}

impl WitnessAnchor {
    pub fn witness_id(self) -> WitnessId {
        match self {
            WitnessAnchor::Bitcoin(_, txid) => WitnessId::Bitcoin(txid),
            WitnessAnchor::Liquid(_, txid) => WitnessId::Liquid(txid),
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

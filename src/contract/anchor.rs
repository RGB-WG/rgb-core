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
use std::ops::Deref;

use bp::dbc::anchor::MergeError;
use bp::dbc::opret::OpretProof;
use bp::dbc::tapret::TapretProof;
use bp::{dbc, Txid};
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
pub enum Anchor<P: mpc::Proof + StrictDumb = mpc::MerkleProof> {
    #[strict_type(tag = 0x00)]
    Bitcoin(AnchorSet<P>),

    #[strict_type(tag = 0x01)]
    Liquid(AnchorSet<P>),
}

impl<P: mpc::Proof + StrictDumb> Deref for Anchor<P> {
    type Target = AnchorSet<P>;

    #[inline]
    fn deref(&self) -> &Self::Target {
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

    #[inline]
    pub fn witness_id(&self) -> WitnessId {
        match self {
            Anchor::Bitcoin(anchor) => WitnessId::Bitcoin(anchor.txid_unchecked()),
            Anchor::Liquid(anchor) => WitnessId::Liquid(anchor.txid_unchecked()),
        }
    }

    pub fn map<Q: mpc::Proof + StrictDumb, E>(
        self,
        f: impl FnOnce(AnchorSet<P>) -> Result<AnchorSet<Q>, E>,
    ) -> Result<Anchor<Q>, E> {
        match self {
            Anchor::Bitcoin(anchor) => f(anchor).map(Anchor::Bitcoin),
            Anchor::Liquid(anchor) => f(anchor).map(Anchor::Liquid),
        }
    }
}

impl Anchor<mpc::MerkleBlock> {
    pub fn merge_reveal(self, other: Self) -> Result<Self, MergeError> {
        match (self, other) {
            (Anchor::Bitcoin(anchor), Anchor::Bitcoin(other)) => {
                anchor.merge_reveal(other).map(Anchor::Bitcoin)
            }
            (Anchor::Liquid(anchor), Anchor::Liquid(other)) => {
                anchor.merge_reveal(other).map(Anchor::Liquid)
            }
            _ => Err(MergeError::TxidMismatch),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB, tags = custom, dumb = Self::Tapret(strict_dumb!()))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum AnchorSet<P: mpc::Proof + StrictDumb = mpc::MerkleProof> {
    #[strict_type(tag = 0x01)]
    Tapret(dbc::Anchor<P, TapretProof>),
    #[strict_type(tag = 0x02)]
    Opret(dbc::Anchor<P, OpretProof>),
    #[strict_type(tag = 0x03)]
    Dual {
        tapret: dbc::Anchor<P, TapretProof>,
        opret: dbc::Anchor<P, OpretProof>,
    },
}

impl<P: mpc::Proof + StrictDumb> AnchorSet<P> {
    pub fn txid(&self) -> Option<Txid> {
        match self {
            AnchorSet::Tapret(a) => Some(a.txid),
            AnchorSet::Opret(a) => Some(a.txid),
            AnchorSet::Dual { tapret, opret } if tapret.txid == opret.txid => Some(tapret.txid),
            _ => None,
        }
    }

    pub(crate) fn txid_unchecked(&self) -> Txid {
        match self {
            AnchorSet::Tapret(a) => a.txid,
            AnchorSet::Opret(a) => a.txid,
            AnchorSet::Dual { tapret, .. } => tapret.txid,
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn as_split(
        &self,
    ) -> (Option<&dbc::Anchor<P, TapretProof>>, Option<&dbc::Anchor<P, OpretProof>>) {
        match self {
            AnchorSet::Tapret(tapret) => (Some(tapret), None),
            AnchorSet::Opret(opret) => (None, Some(opret)),
            AnchorSet::Dual { tapret, opret } => (Some(tapret), Some(opret)),
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn into_split(
        self,
    ) -> (Option<dbc::Anchor<P, TapretProof>>, Option<dbc::Anchor<P, OpretProof>>) {
        match self {
            AnchorSet::Tapret(tapret) => (Some(tapret), None),
            AnchorSet::Opret(opret) => (None, Some(opret)),
            AnchorSet::Dual { tapret, opret } => (Some(tapret), Some(opret)),
        }
    }
}

impl AnchorSet<mpc::MerkleBlock> {
    pub fn merge_reveal(self, other: Self) -> Result<Self, MergeError> {
        let (tapret1, opret1) = self.into_split();
        let (tapret2, opret2) = other.into_split();

        let tapret = match (tapret1, tapret2) {
            (Some(tr), None) | (None, Some(tr)) => Some(tr),
            (Some(tapret1), Some(tapret2)) => Some(tapret1.merge_reveal(tapret2)?),
            (None, None) => None,
        };
        let opret = match (opret1, opret2) {
            (Some(or), None) | (None, Some(or)) => Some(or),
            (Some(opret1), Some(opret2)) => Some(opret1.merge_reveal(opret2)?),
            (None, None) => None,
        };
        Ok(match (tapret, opret) {
            (Some(tapret), None) => Self::Tapret(tapret),
            (None, Some(opret)) => Self::Opret(opret),
            (Some(tapret), Some(opret)) => Self::Dual { tapret, opret },
            _ => unreachable!(),
        })
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

impl WitnessAnchor {
    pub fn from_mempool(witness_id: WitnessId) -> Self {
        WitnessAnchor {
            witness_ord: WitnessOrd::OffChain,
            witness_id,
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
pub enum Layer1 {
    #[strict_type(dumb)]
    Bitcoin = 0,
    Liquid = 1,
}

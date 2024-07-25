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

use std::borrow::Borrow;
use std::cmp::Ordering;
use std::fmt::Debug;

use amplify::confinement::LargeOrdMap;
use strict_encoding::{StrictDecode, StrictDumb, StrictEncode};

use crate::{
    AssignmentType, DataState, FungibleState, GlobalStateType, RevealedAttach, WitnessOrd,
    XOutpoint, XWitnessId, LIB_NAME_RGB_LOGIC,
};

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Display, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_LOGIC, tags = custom)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase", untagged)
)]
pub enum AssignmentWitness {
    #[display("~")]
    #[strict_type(tag = 0, dumb)]
    Absent,

    #[from]
    #[display(inner)]
    #[strict_type(tag = 1)]
    Present(XWitnessId),
}

impl From<Option<XWitnessId>> for AssignmentWitness {
    fn from(value: Option<XWitnessId>) -> Self {
        match value {
            None => AssignmentWitness::Absent,
            Some(id) => AssignmentWitness::Present(id),
        }
    }
}

/// Txid and height information ordered according to the RGB consensus rules.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_LOGIC)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[display("{witness_id}/{witness_ord}")]
pub struct WitnessAnchor {
    pub witness_ord: WitnessOrd,
    pub witness_id: XWitnessId,
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
    pub fn from_mempool(witness_id: XWitnessId, priority: u32) -> Self {
        WitnessAnchor {
            witness_ord: WitnessOrd::OffChain { priority },
            witness_id,
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_LOGIC)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct GlobalOrd {
    pub witness_anchor: Option<WitnessAnchor>,
    pub idx: u16,
}

impl PartialOrd for GlobalOrd {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl Ord for GlobalOrd {
    fn cmp(&self, other: &Self) -> Ordering {
        if self == other {
            return Ordering::Equal;
        }
        match (self.witness_anchor, &other.witness_anchor) {
            (None, None) => self.idx.cmp(&other.idx),
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,
            (Some(ord1), Some(ord2)) if ord1 == *ord2 => self.idx.cmp(&other.idx),
            (Some(ord1), Some(ord2)) => ord1.cmp(ord2),
        }
    }
}

impl GlobalOrd {
    pub fn with_anchor(ord_txid: WitnessAnchor, idx: u16) -> Self {
        GlobalOrd {
            witness_anchor: Some(ord_txid),
            idx,
        }
    }
    pub fn genesis(idx: u16) -> Self {
        GlobalOrd {
            witness_anchor: None,
            idx,
        }
    }
}

pub trait ContractState {
    fn global(&self, ty: GlobalStateType)
    -> Option<LargeOrdMap<GlobalOrd, impl Borrow<DataState>>>;

    fn rights(&self, outpoint: XOutpoint, ty: AssignmentType, unspent: bool) -> Option<u32>;

    fn fungible(
        &self,
        outpoint: XOutpoint,
        ty: AssignmentType,
        unspent: bool,
    ) -> Option<impl DoubleEndedIterator<Item = FungibleState>>;

    fn data(
        &self,
        outpoint: XOutpoint,
        ty: AssignmentType,
        unspent: bool,
    ) -> Option<impl DoubleEndedIterator<Item = impl Borrow<DataState>>>;

    fn attach(
        &self,
        outpoint: XOutpoint,
        ty: AssignmentType,
        unspent: bool,
    ) -> Option<impl DoubleEndedIterator<Item = impl Borrow<RevealedAttach>>>;
}

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

//! Extraction of contract state.

use std::cmp::Ordering;
use std::fmt::Debug;
use std::hash::Hash;
use std::num::ParseIntError;
use std::str::FromStr;

use amplify::hex;
use strict_encoding::{StrictDecode, StrictDumb, StrictEncode};

use crate::{
    AssignmentType, DataState, ExposedSeal, ExposedState, OpId, WitnessAnchor, XChain, XOutputSeal,
    XWitnessId, LIB_NAME_RGB,
};

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[display("{op}/{ty}/{no}")]
/// RGB contract operation output pointer, defined by the operation ID and
/// output number.
pub struct Opout {
    pub op: OpId,
    pub ty: AssignmentType,
    pub no: u16,
}

impl Opout {
    pub fn new(op: OpId, ty: AssignmentType, no: u16) -> Opout { Opout { op, ty, no } }
}

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(inner)]
pub enum OpoutParseError {
    #[from]
    InvalidNodeId(hex::Error),

    InvalidType(ParseIntError),

    InvalidOutputNo(ParseIntError),

    /// invalid operation outpoint format ('{0}')
    #[display(doc_comments)]
    WrongFormat(String),
}

impl FromStr for Opout {
    type Err = OpoutParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split('/');
        match (split.next(), split.next(), split.next(), split.next()) {
            (Some(op), Some(ty), Some(no), None) => Ok(Opout {
                op: op.parse()?,
                ty: ty.parse().map_err(OpoutParseError::InvalidType)?,
                no: no.parse().map_err(OpoutParseError::InvalidOutputNo)?,
            }),
            _ => Err(OpoutParseError::WrongFormat(s.to_owned())),
        }
    }
}

/// Trait used by contract state. Unlike [`ExposedState`] it doesn't allow
/// concealment of the state, i.e. may contain incomplete data without blinding
/// factors, asset tags etc.
pub trait KnownState: Debug + StrictDumb + StrictEncode + StrictDecode + Eq + Clone {}
impl<S: ExposedState> KnownState for S {}

impl KnownState for () {}
impl KnownState for DataState {}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Display, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB, tags = custom)]
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

#[derive(Copy, Clone, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct OutputAssignment<State: KnownState> {
    pub opout: Opout,
    pub seal: XOutputSeal,
    pub state: State,
    pub witness: AssignmentWitness,
}

impl<State: KnownState> PartialEq for OutputAssignment<State> {
    fn eq(&self, other: &Self) -> bool {
        if self.opout == other.opout &&
            (self.seal != other.seal ||
                self.witness != other.witness ||
                self.state != other.state)
        {
            panic!(
                "RGB was provided with an updated operation using different witness transaction. \
                 This may happen for instance when some ephemeral state (like a commitment or \
                 HTLC transactions in the lightning channels) is added to the stash.\nThis error \
                 means the software uses RGB stash in an invalid way and has business logic bug \
                 which has to be fixed.\nOperation in stash: {:?}\nNew operation: {:?}\n",
                self, other
            )
        }
        self.opout == other.opout
    }
}

impl<State: KnownState> PartialOrd for OutputAssignment<State> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl<State: KnownState> Ord for OutputAssignment<State> {
    fn cmp(&self, other: &Self) -> Ordering {
        if self == other {
            return Ordering::Equal;
        }
        self.opout.cmp(&other.opout)
    }
}

impl<State: KnownState> OutputAssignment<State> {
    /// # Panics
    ///
    /// If the processing is done on invalid stash data, the seal is
    /// witness-based and the anchor chain doesn't match the seal chain.
    pub fn with_witness<Seal: ExposedSeal>(
        seal: XChain<Seal>,
        witness_id: XWitnessId,
        state: State,
        opid: OpId,
        ty: AssignmentType,
        no: u16,
    ) -> Self {
        OutputAssignment {
            opout: Opout::new(opid, ty, no),
            seal: seal.try_to_output_seal(witness_id).expect(
                "processing contract from unverified/invalid stash: witness seal chain doesn't \
                 match anchor's chain",
            ),
            state,
            witness: witness_id.into(),
        }
    }

    /// # Panics
    ///
    /// If the processing is done on invalid stash data, the seal is
    /// witness-based and the anchor chain doesn't match the seal chain.
    pub fn with_no_witness<Seal: ExposedSeal>(
        seal: XChain<Seal>,
        state: State,
        opid: OpId,
        ty: AssignmentType,
        no: u16,
    ) -> Self {
        OutputAssignment {
            opout: Opout::new(opid, ty, no),
            seal: seal.to_output_seal().expect(
                "processing contract from unverified/invalid stash: seal must have txid \
                 information since it comes from genesis or extension",
            ),
            state,
            witness: AssignmentWitness::Absent,
        }
    }

    pub fn transmute<S: KnownState>(self) -> OutputAssignment<S>
    where S: From<State> {
        OutputAssignment {
            opout: self.opout,
            seal: self.seal,
            state: self.state.into(),
            witness: self.witness,
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
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

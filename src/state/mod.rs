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

//! Extraction of contract state.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::hash::Hash;
use std::num::ParseIntError;
use std::str::FromStr;

use amplify::hex;
use bp::seals::txout::TxoSeal;
use bp::{Outpoint, Txid};
use commit_verify::Conceal;
use strict_encoding::{StrictDecode, StrictDumb, StrictEncode};

use crate::data::VoidState;
use crate::{
    assignment, attachment, data, fungible, seal, Assign, ContractId, Extension, Genesis,
    GlobalStateType, OpId, Operation, OwnedStateType, SchemaId, StatePair, Transition, TypedAssign,
    LIB_NAME_RGB,
};

pub trait StateTrait:
    Clone
    + Eq
    + Ord
    + Hash
    + Debug
    + StrictDumb
    + StrictEncode
    + StrictDecode
    + From<<Self::StateType as StatePair>::Revealed>
{
    type StateType: StatePair;
}
impl StateTrait for VoidState {
    type StateType = assignment::Right;
}
impl StateTrait for fungible::Revealed {
    type StateType = assignment::Fungible;
}
impl StateTrait for data::Revealed {
    type StateType = assignment::State;
}
impl StateTrait for attachment::Revealed {
    type StateType = assignment::Attach;
}

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
pub struct OpOut {
    pub op: OpId,
    pub ty: OwnedStateType,
    pub no: u16,
}

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(inner)]
pub enum OutpointParseError {
    #[from]
    InvalidNodeId(hex::Error),

    InvalidType(ParseIntError),

    InvalidOutputNo(ParseIntError),

    /// invalid node outpoint format ('{0}')
    #[display(doc_comments)]
    WrongFormat(String),
}

impl FromStr for OpOut {
    type Err = OutpointParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split('/');
        match (split.next(), split.next(), split.next(), split.next()) {
            (Some(op), Some(ty), Some(no), None) => Ok(OpOut {
                op: op.parse()?,
                ty: ty.parse().map_err(OutpointParseError::InvalidType)?,
                no: no.parse().map_err(OutpointParseError::InvalidOutputNo)?,
            }),
            _ => Err(OutpointParseError::WrongFormat(s.to_owned())),
        }
    }
}

impl OpOut {
    pub fn new(op: OpId, ty: u16, no: u16) -> OpOut { OpOut { op, ty, no } }
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct AssignedState<State>
where State: StateTrait
{
    pub op_out: OpOut,
    pub seal: Outpoint,
    pub state: State,
}

impl<State> AssignedState<State>
where State: StateTrait
{
    pub fn with(
        seal: seal::Revealed,
        witness_txid: Txid,
        state: State,
        op_id: OpId,
        ty: OwnedStateType,
        no: u16,
    ) -> Self {
        AssignedState {
            op_out: OpOut::new(op_id, ty, no),
            seal: seal.outpoint_or(witness_txid),
            state,
        }
    }
}

pub type OwnedRight = AssignedState<VoidState>;
pub type OwnedValue = AssignedState<fungible::Revealed>;
pub type OwnedData = AssignedState<data::Revealed>;
pub type OwnedAttachment = AssignedState<attachment::Revealed>;

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
// #[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
// #[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct ContractState {
    pub schema_id: SchemaId,
    pub root_schema_id: Option<SchemaId>,
    pub contract_id: ContractId,
    /*#[cfg_attr(
        feature = "serde",
        serde(with = "As::<BTreeMap<Same, BTreeMap<Same, Vec<DisplayFromStr>>>>")
    )]*/
    pub global: BTreeMap<OpId, BTreeMap<GlobalStateType, Vec<data::Revealed>>>,
    // #[cfg_attr(feature = "serde", serde(with = "As::<BTreeSet<DisplayFromStr>>"))]
    pub rights: BTreeSet<OwnedRight>,
    // #[cfg_attr(feature = "serde", serde(with = "As::<BTreeSet<DisplayFromStr>>"))]
    pub fungibles: BTreeSet<OwnedValue>,
    // #[cfg_attr(feature = "serde", serde(with = "As::<BTreeSet<DisplayFromStr>>"))]
    pub data: BTreeSet<OwnedData>,
    // #[cfg_attr(feature = "serde", serde(with = "As::<BTreeSet<DisplayFromStr>>"))]
    pub attach: BTreeSet<OwnedAttachment>,
}

impl ContractState {
    pub fn with(
        schema_id: SchemaId,
        root_schema_id: Option<SchemaId>,
        contract_id: ContractId,
        genesis: &Genesis,
    ) -> Self {
        let mut state = ContractState {
            schema_id,
            root_schema_id,
            contract_id,
            global: empty!(),
            rights: empty!(),
            fungibles: empty!(),
            data: empty!(),
            attach: empty!(),
        };
        state.add_node(Txid::all_zeros(), genesis);
        state
    }

    pub fn add_transition(&mut self, txid: Txid, transition: &Transition) {
        self.add_node(txid, transition);
    }

    pub fn add_extension(&mut self, extension: &Extension) {
        self.add_node(Txid::all_zeros(), extension);
    }

    fn add_node(&mut self, txid: Txid, op: &impl Operation) {
        let op_id = op.id();

        for (ty, meta) in op.global_state() {
            self.global
                .entry(op_id)
                .or_default()
                .entry(*ty)
                .or_default()
                .extend(meta.iter().cloned());
        }

        fn process<S: StateTrait>(
            contract_state: &mut BTreeSet<AssignedState<S>>,
            assignments: &[Assign<S::StateType>],
            op_id: OpId,
            ty: OwnedStateType,
            txid: Txid,
        ) where
            <S::StateType as StatePair>::Confidential:
                Eq + From<<<S::StateType as StatePair>::Revealed as Conceal>::Concealed>,
        {
            for (no, seal, state) in assignments
                .iter()
                .enumerate()
                .filter_map(|(n, a)| a.to_revealed().map(|(seal, state)| (n, seal, state)))
            {
                let assigned_state =
                    AssignedState::with(seal, txid, state.into(), op_id, ty, no as u16);
                contract_state.insert(assigned_state);
            }
        }

        // Remove invalidated state
        for output in op.parent_outputs() {
            if let Some(o) = self.rights.iter().find(|r| r.op_out == output) {
                let o = o.clone(); // need this b/c of borrow checker
                self.rights.remove(&o);
            }
            if let Some(o) = self.fungibles.iter().find(|r| r.op_out == output) {
                let o = o.clone();
                self.fungibles.remove(&o);
            }
            if let Some(o) = self.data.iter().find(|r| r.op_out == output) {
                let o = o.clone();
                self.data.remove(&o);
            }
            if let Some(o) = self.attach.iter().find(|r| r.op_out == output) {
                let o = o.clone();
                self.attach.remove(&o);
            }
        }

        for (ty, assignments) in op.owned_state().iter() {
            match assignments {
                TypedAssign::Declarative(assignments) => {
                    process(&mut self.rights, &assignments, op_id, *ty, txid)
                }
                TypedAssign::Fungible(assignments) => {
                    process(&mut self.fungibles, &assignments, op_id, *ty, txid)
                }
                TypedAssign::Structured(assignments) => {
                    process(&mut self.data, &assignments, op_id, *ty, txid)
                }
                TypedAssign::Attachment(assignments) => {
                    process(&mut self.attach, &assignments, op_id, *ty, txid)
                }
            }
        }
    }
}

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

use std::cmp::Ordering;
use std::fmt::Debug;
use std::hash::Hash;
use std::num::ParseIntError;
use std::str::FromStr;

use amplify::confinement::{LargeOrdMap, LargeOrdSet, TinyOrdMap};
use amplify::hex;
use bp::seals::txout::TxoSeal;
use bp::{Outpoint, Txid};
use strict_encoding::{StrictDecode, StrictDumb, StrictEncode};

use crate::data::VoidState;
use crate::{
    attachment, data, fungible, Assign, Assignments, AssignmentsRef, AssignmentsType, ContractId,
    ExposedSeal, ExposedState, Extension, Genesis, GlobalStateType, OpId, Operation, SchemaId,
    Transition, TypedAssigns, LIB_NAME_RGB,
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
    pub ty: AssignmentsType,
    pub no: u16,
}

impl Opout {
    pub fn new(op: OpId, ty: u16, no: u16) -> Opout { Opout { op, ty, no } }
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

#[derive(Clone, Eq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct OutputAssignment<State: ExposedState> {
    pub opout: Opout,
    pub seal: Outpoint,
    pub state: State,
}

impl<State: ExposedState> PartialEq for OutputAssignment<State> {
    fn eq(&self, other: &Self) -> bool {
        if self.opout == other.opout {
            debug_assert_eq!(self.seal, other.seal);
            debug_assert_eq!(self.state, other.state);
        }
        self.opout == other.opout
    }
}

impl<State: ExposedState> PartialOrd for OutputAssignment<State> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl<State: ExposedState> Ord for OutputAssignment<State> {
    fn cmp(&self, other: &Self) -> Ordering {
        if self == other {
            return Ordering::Equal;
        }
        self.opout.cmp(&other.opout)
    }
}

impl<State: ExposedState> OutputAssignment<State> {
    pub fn with_witness<Seal: TxoSeal>(
        seal: Seal,
        witness_txid: Txid,
        state: State,
        opid: OpId,
        ty: AssignmentsType,
        no: u16,
    ) -> Self {
        OutputAssignment {
            opout: Opout::new(opid, ty, no),
            seal: seal.outpoint_or(witness_txid),
            state,
        }
    }

    pub fn with_unwrap_txid<Seal: TxoSeal>(
        seal: Seal,
        state: State,
        opid: OpId,
        ty: AssignmentsType,
        no: u16,
    ) -> Self {
        OutputAssignment {
            opout: Opout::new(opid, ty, no),
            seal: seal
                .outpoint()
                .expect("seal must have txid information and come from genesis or state extension"),
            state,
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[display("{height}/{txid}/{idx}")]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct GlobalIdx {
    pub height: u32,
    pub txid: Txid,
    pub idx: u16,
}

impl PartialOrd for GlobalIdx {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl Ord for GlobalIdx {
    fn cmp(&self, other: &Self) -> Ordering {
        if self == other {
            return Ordering::Equal;
        }
        if self.height != other.height {
            return self.height.cmp(&other.height);
        }
        if self.txid != other.txid {
            return self.txid.cmp(&other.txid);
        }
        self.idx.cmp(&other.idx)
    }
}

impl GlobalIdx {
    pub fn new(height: u32, txid: Txid, idx: u16) -> Self { GlobalIdx { height, txid, idx } }
    pub fn genesis(idx: u16) -> Self {
        GlobalIdx {
            height: 0,
            txid: Txid::from([0x00; 32]),
            idx,
        }
    }
}

pub type RightsOutput = OutputAssignment<VoidState>;
pub type FungibleOutput = OutputAssignment<fungible::Revealed>;
pub type DataOutput = OutputAssignment<data::Revealed>;
pub type AttachOutput = OutputAssignment<attachment::Revealed>;

/// Contract history accumulates raw data from the contract history, extracted
/// from a series of consignments over the time. It does consensus ordering of
/// the state data, but it doesn't interpret or validates the state against the
/// schema.
///
/// To access the valid contract state use [`Contract`] APIs.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct ContractHistory {
    schema_id: SchemaId,
    root_schema_id: Option<SchemaId>,
    contract_id: ContractId,
    global: TinyOrdMap<GlobalStateType, LargeOrdMap<GlobalIdx, data::Revealed>>,
    rights: LargeOrdSet<RightsOutput>,
    fungibles: LargeOrdSet<FungibleOutput>,
    data: LargeOrdSet<DataOutput>,
    attach: LargeOrdSet<AttachOutput>,
}

impl ContractHistory {
    /// # Panics
    ///
    /// If genesis violates RGB consensus rules and wasn't checked against the
    /// schema before adding to the history.
    pub fn with(
        schema_id: SchemaId,
        root_schema_id: Option<SchemaId>,
        contract_id: ContractId,
        genesis: &Genesis,
    ) -> Self {
        let mut state = ContractHistory {
            schema_id,
            root_schema_id,
            contract_id,
            global: empty!(),
            rights: empty!(),
            fungibles: empty!(),
            data: empty!(),
            attach: empty!(),
        };
        state.update_genesis(genesis);
        state
    }

    /// # Panics
    ///
    /// If genesis violates RGB consensus rules and wasn't checked against the
    /// schema before adding to the history.
    pub fn update_genesis(&mut self, genesis: &Genesis) { self.add_operation(None, genesis, None); }

    /// # Panics
    ///
    /// If state transition violates RGB consensus rules and wasn't checked
    /// against the schema before adding to the history.
    pub fn add_transition(&mut self, transition: &Transition, txid: Txid, height: u32) {
        self.add_operation(Some(txid), transition, Some((txid, height)));
    }

    /// # Panics
    ///
    /// If state extension violates RGB consensus rules and wasn't checked
    /// against the schema before adding to the history.
    pub fn add_extension(&mut self, extension: &Extension, txid: Txid, height: u32) {
        self.add_operation(None, extension, Some((txid, height)));
    }

    fn add_operation(
        &mut self,
        witness_txid: Option<Txid>,
        op: &impl Operation,
        ordering: Option<(Txid, u32)>,
    ) {
        let opid = op.id();

        for (ty, state) in op.globals() {
            let map = match self.global.get_mut(ty) {
                Some(map) => map,
                None => {
                    // TODO: Do not panic here if we merge without checking against the schema
                    self.global.insert(*ty, empty!()).expect(
                        "consensus rules violation: do not add to the state consignments without \
                         validation against the schema",
                    );
                    self.global.get_mut(ty).expect("just inserted")
                }
            };
            for (idx, s) in state.iter().enumerate() {
                let idx = idx as u16;
                let glob_idx = ordering
                    .map(|(txid, height)| GlobalIdx::new(height, txid, idx))
                    .unwrap_or_else(|| GlobalIdx::genesis(idx));
                map.insert(glob_idx, s.clone())
                    .expect("contract global state exceeded 2^32 items, which is unrealistic");
            }
        }

        // Remove invalidated state
        for output in op.prev_outs() {
            if let Some(o) = self.rights.iter().find(|r| r.opout == output) {
                let o = o.clone(); // need this b/c of borrow checker
                self.rights
                    .remove(&o)
                    .expect("collection allows zero elements");
            }
            if let Some(o) = self.fungibles.iter().find(|r| r.opout == output) {
                let o = o.clone();
                self.fungibles
                    .remove(&o)
                    .expect("collection allows zero elements");
            }
            if let Some(o) = self.data.iter().find(|r| r.opout == output) {
                let o = o.clone();
                self.data
                    .remove(&o)
                    .expect("collection allows zero elements");
            }
            if let Some(o) = self.attach.iter().find(|r| r.opout == output) {
                let o = o.clone();
                self.attach
                    .remove(&o)
                    .expect("collection allows zero elements");
            }
        }

        match op.assignments() {
            AssignmentsRef::Genesis(assignments) => {
                self.add_assignments(witness_txid, opid, assignments)
            }
            AssignmentsRef::Graph(assignments) => {
                self.add_assignments(witness_txid, opid, assignments)
            }
        }
    }

    fn add_assignments<Seal: ExposedSeal>(
        &mut self,
        witness_txid: Option<Txid>,
        opid: OpId,
        assignments: &Assignments<Seal>,
    ) {
        fn process<State: ExposedState, Seal: ExposedSeal>(
            contract_state: &mut LargeOrdSet<OutputAssignment<State>>,
            assignments: &[Assign<State, Seal>],
            opid: OpId,
            ty: AssignmentsType,
            txid: Option<Txid>,
        ) {
            for (no, seal, state) in assignments
                .iter()
                .enumerate()
                .filter_map(|(n, a)| a.to_revealed().map(|(seal, state)| (n, seal, state)))
            {
                let assigned_state = if let Some(txid) = txid {
                    OutputAssignment::with_witness(seal, txid, state.into(), opid, ty, no as u16)
                } else {
                    OutputAssignment::with_unwrap_txid(seal, state.into(), opid, ty, no as u16)
                };
                contract_state
                    .push(assigned_state)
                    .expect("contract state exceeded 2^32 items, which is unrealistic");
            }
        }

        for (ty, assignments) in assignments.iter() {
            match assignments {
                TypedAssigns::Declarative(assignments) => {
                    process(&mut self.rights, &assignments, opid, *ty, witness_txid)
                }
                TypedAssigns::Fungible(assignments) => {
                    process(&mut self.fungibles, &assignments, opid, *ty, witness_txid)
                }
                TypedAssigns::Structured(assignments) => {
                    process(&mut self.data, &assignments, opid, *ty, witness_txid)
                }
                TypedAssigns::Attachment(assignments) => {
                    process(&mut self.attach, &assignments, opid, *ty, witness_txid)
                }
            }
        }
    }
}

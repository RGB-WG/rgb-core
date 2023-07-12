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
use std::num::{NonZeroU32, ParseIntError};
use std::ops::{Deref, DerefMut};
use std::str::FromStr;

use amplify::confinement::{LargeOrdMap, LargeOrdSet, SmallVec, TinyOrdMap};
use amplify::hex;
use bp::seals::txout::TxoSeal;
use bp::{Outpoint, Txid};
use strict_encoding::{StrictDecode, StrictDumb, StrictEncode};

use crate::contract::contract::WitnessOrd::OffChain;
use crate::{
    Assign, AssignmentType, Assignments, AssignmentsRef, ContractId, ExposedSeal, ExposedState,
    Extension, Genesis, GlobalStateType, OpId, Operation, RevealedAttach, RevealedData,
    RevealedValue, SchemaId, SealWitness, SubSchema, Transition, TypedAssigns, VoidState,
    LIB_NAME_RGB,
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

#[derive(Clone, Eq, Debug)]
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
    // `None` for state extensions
    pub witness: SealWitness,
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
        ty: AssignmentType,
        no: u16,
    ) -> Self {
        OutputAssignment {
            opout: Opout::new(opid, ty, no),
            seal: seal.outpoint_or(witness_txid),
            state,
            witness: SealWitness::Present(witness_txid),
        }
    }

    pub fn with_genesis<Seal: TxoSeal>(
        seal: Seal,
        state: State,
        opid: OpId,
        ty: AssignmentType,
        no: u16,
    ) -> Self {
        OutputAssignment {
            opout: Opout::new(opid, ty, no),
            seal: seal
                .outpoint()
                .expect("seal must have txid information and come from genesis"),
            state,
            witness: SealWitness::Genesis,
        }
    }

    pub fn with_extension<Seal: TxoSeal>(
        seal: Seal,
        state: State,
        opid: OpId,
        ty: AssignmentType,
        no: u16,
    ) -> Self {
        OutputAssignment {
            opout: Opout::new(opid, ty, no),
            seal: seal
                .outpoint()
                .expect("seal must have txid information and come from state extension"),
            state,
            witness: SealWitness::Extension,
        }
    }
}

#[derive(Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB, dumb = { Self(1) })]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[display(inner)]
pub struct WitnessHeight(u32);

impl WitnessHeight {
    pub fn new(height: u32) -> Option<Self> {
        match height {
            0 => None,
            height => Some(WitnessHeight(height)),
        }
    }

    pub fn get(&self) -> NonZeroU32 { NonZeroU32::new(self.0).expect("invariant") }
}

/// RGB consensus information about the current mined height of a witness
/// transaction defining the ordering of the contract state data.
#[derive(Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB, tags = order)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum WitnessOrd {
    #[display(inner)]
    OnChain(WitnessHeight),

    #[display("offchain")]
    #[strict_type(dumb)]
    OffChain,
}

impl WitnessOrd {
    pub fn from_electrum_height(height: u32) -> Self {
        WitnessHeight::new(height)
            .map(WitnessOrd::OnChain)
            .unwrap_or(OffChain)
    }
}

/// Txid and height information ordered according to the RGB consensus rules.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[display("{ord}/{txid}")]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct WitnessAnchor {
    pub ord: WitnessOrd,
    pub txid: Txid,
}

impl PartialOrd for WitnessAnchor {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl Ord for WitnessAnchor {
    fn cmp(&self, other: &Self) -> Ordering {
        if self == other {
            return Ordering::Equal;
        }
        if self.ord != other.ord {
            return self.ord.cmp(&other.ord);
        }
        self.txid.cmp(&other.txid)
    }
}

impl WitnessAnchor {
    pub fn new(ord: WitnessOrd, txid: Txid) -> Self { WitnessAnchor { ord, txid } }
    pub fn with_mempool(txid: Txid) -> Self {
        WitnessAnchor {
            ord: WitnessOrd::OffChain,
            txid,
        }
    }
    pub fn with_electrum_height(height: u32, txid: Txid) -> Self {
        WitnessAnchor {
            ord: WitnessOrd::from_electrum_height(height),
            txid,
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
    pub ord_txid: Option<WitnessAnchor>,
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
        match (self.ord_txid, &other.ord_txid) {
            (None, None) => self.idx.cmp(&other.idx),
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,
            (Some(ord1), Some(ord2)) if ord1 == *ord2 => self.idx.cmp(&other.idx),
            (Some(ord1), Some(ord2)) => ord1.cmp(ord2),
        }
    }
}

impl GlobalOrd {
    pub fn new(ord: WitnessOrd, txid: Txid, idx: u16) -> Self {
        GlobalOrd {
            ord_txid: Some(WitnessAnchor::new(ord, txid)),
            idx,
        }
    }
    pub fn with_electrum_height(height: u32, txid: Txid, idx: u16) -> Self {
        GlobalOrd {
            ord_txid: Some(WitnessAnchor::with_electrum_height(height, txid)),
            idx,
        }
    }
    pub fn with_anchor(ord_txid: WitnessAnchor, idx: u16) -> Self {
        GlobalOrd {
            ord_txid: Some(ord_txid),
            idx,
        }
    }
    pub fn genesis(idx: u16) -> Self {
        GlobalOrd {
            ord_txid: None,
            idx,
        }
    }
}

pub type RightsOutput = OutputAssignment<VoidState>;
pub type FungibleOutput = OutputAssignment<RevealedValue>;
pub type DataOutput = OutputAssignment<RevealedData>;
pub type AttachOutput = OutputAssignment<RevealedAttach>;

/// Contract history accumulates raw data from the contract history, extracted
/// from a series of consignments over the time. It does consensus ordering of
/// the state data, but it doesn't interpret or validates the state against the
/// schema.
///
/// To access the valid contract state use [`Contract`] APIs.
#[derive(Getters, Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct ContractHistory {
    #[getter(as_copy)]
    schema_id: SchemaId,
    #[getter(as_copy)]
    root_schema_id: Option<SchemaId>,
    #[getter(as_copy)]
    contract_id: ContractId,
    #[getter(skip)]
    global: TinyOrdMap<GlobalStateType, LargeOrdMap<GlobalOrd, RevealedData>>,
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
    pub fn update_genesis(&mut self, genesis: &Genesis) {
        self.add_operation(SealWitness::Genesis, genesis, None);
    }

    /// # Panics
    ///
    /// If state transition violates RGB consensus rules and wasn't checked
    /// against the schema before adding to the history.
    pub fn add_transition(&mut self, transition: &Transition, ord_txid: WitnessAnchor) {
        self.add_operation(SealWitness::Present(ord_txid.txid), transition, Some(ord_txid));
    }

    /// # Panics
    ///
    /// If state extension violates RGB consensus rules and wasn't checked
    /// against the schema before adding to the history.
    pub fn add_extension(&mut self, extension: &Extension, ord_txid: WitnessAnchor) {
        self.add_operation(SealWitness::Extension, extension, Some(ord_txid));
    }

    fn add_operation(
        &mut self,
        witness: SealWitness,
        op: &impl Operation,
        ord_txid: Option<WitnessAnchor>,
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
                let glob_idx = GlobalOrd { ord_txid, idx };
                map.insert(glob_idx, s.clone())
                    .expect("contract global state exceeded 2^32 items, which is unrealistic");
            }
        }

        // We skip removing of invalidated state for the cases of re-orgs or unmined
        // witness transactions committing to the new state.
        // TODO: Expose an API to prune historic state by witness txid
        /*
        // Remove invalidated state
        for input in &op.inputs() {
            if let Some(o) = self.rights.iter().find(|r| r.opout == input.prev_out) {
                let o = o.clone(); // need this b/c of borrow checker
                self.rights
                    .remove(&o)
                    .expect("collection allows zero elements");
            }
            if let Some(o) = self.fungibles.iter().find(|r| r.opout == input.prev_out) {
                let o = o.clone();
                self.fungibles
                    .remove(&o)
                    .expect("collection allows zero elements");
            }
            if let Some(o) = self.data.iter().find(|r| r.opout == input.prev_out) {
                let o = o.clone();
                self.data
                    .remove(&o)
                    .expect("collection allows zero elements");
            }
            if let Some(o) = self.attach.iter().find(|r| r.opout == input.prev_out) {
                let o = o.clone();
                self.attach
                    .remove(&o)
                    .expect("collection allows zero elements");
            }
        }
         */

        match op.assignments() {
            AssignmentsRef::Genesis(assignments) => {
                self.add_assignments(witness, opid, assignments)
            }
            AssignmentsRef::Graph(assignments) => self.add_assignments(witness, opid, assignments),
        }
    }

    fn add_assignments<Seal: ExposedSeal>(
        &mut self,
        witness: SealWitness,
        opid: OpId,
        assignments: &Assignments<Seal>,
    ) {
        fn process<State: ExposedState, Seal: ExposedSeal>(
            contract_state: &mut LargeOrdSet<OutputAssignment<State>>,
            assignments: &[Assign<State, Seal>],
            opid: OpId,
            ty: AssignmentType,
            witness: SealWitness,
        ) {
            for (no, seal, state) in assignments
                .iter()
                .enumerate()
                .filter_map(|(n, a)| a.to_revealed().map(|(seal, state)| (n, seal, state)))
            {
                let assigned_state = match witness {
                    SealWitness::Present(txid) => OutputAssignment::with_witness(
                        seal,
                        txid,
                        state.into(),
                        opid,
                        ty,
                        no as u16,
                    ),
                    SealWitness::Genesis => {
                        OutputAssignment::with_genesis(seal, state.into(), opid, ty, no as u16)
                    }
                    SealWitness::Extension => {
                        OutputAssignment::with_extension(seal, state.into(), opid, ty, no as u16)
                    }
                };
                contract_state
                    .push(assigned_state)
                    .expect("contract state exceeded 2^32 items, which is unrealistic");
            }
        }

        for (ty, assignments) in assignments.iter() {
            match assignments {
                TypedAssigns::Declarative(assignments) => {
                    process(&mut self.rights, &assignments, opid, *ty, witness)
                }
                TypedAssigns::Fungible(assignments) => {
                    process(&mut self.fungibles, &assignments, opid, *ty, witness)
                }
                TypedAssigns::Structured(assignments) => {
                    process(&mut self.data, &assignments, opid, *ty, witness)
                }
                TypedAssigns::Attachment(assignments) => {
                    process(&mut self.attach, &assignments, opid, *ty, witness)
                }
            }
        }
    }
}

/// Contract state provides API to read consensus-valid data from the
/// [`ContractHistory`].
#[derive(Clone, Eq, PartialEq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct ContractState {
    pub schema: SubSchema,
    pub history: ContractHistory,
}

impl Deref for ContractState {
    type Target = ContractHistory;
    fn deref(&self) -> &Self::Target { &self.history }
}

impl DerefMut for ContractState {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.history }
}

impl ContractState {
    /// # Panics
    ///
    /// If the specified state type is not part of the schema.
    pub unsafe fn global_unchecked(&self, state_type: GlobalStateType) -> SmallVec<&RevealedData> {
        let schema = self
            .schema
            .global_types
            .get(&state_type)
            .expect("global type is not in the schema");
        let Some(state) = self.global.get(&state_type) else {
            return SmallVec::new();
        };
        let iter = state.values().take(schema.max_items as usize);
        SmallVec::try_from_iter(iter).expect("same size as previous confined collection")
    }
}

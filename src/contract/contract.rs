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
use strict_encoding::{StrictDecode, StrictDumb, StrictEncode};

use crate::data::VoidState;
use crate::{
    attachment, data, fungible, Assign, AssignmentsType, ContractId, ExposedSeal, ExposedState,
    Extension, Genesis, GlobalStateType, OpId, Operation, SchemaId, Transition, TypedAssigns,
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

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
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

    // TODO: Refactor
    pub fn with<Seal: TxoSeal>(
        seal: Seal,
        state: State,
        opid: OpId,
        ty: AssignmentsType,
        no: u16,
    ) -> Self {
        OutputAssignment {
            opout: Opout::new(opid, ty, no),
            seal: seal.outpoint().unwrap(),
            state,
        }
    }
}

pub type RightsOutput = OutputAssignment<VoidState>;
pub type FungibleOutput = OutputAssignment<fungible::Revealed>;
pub type DataOutput = OutputAssignment<data::Revealed>;
pub type AttachOutput = OutputAssignment<attachment::Revealed>;

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
    pub rights: BTreeSet<RightsOutput>,
    // #[cfg_attr(feature = "serde", serde(with = "As::<BTreeSet<DisplayFromStr>>"))]
    pub fungibles: BTreeSet<FungibleOutput>,
    // #[cfg_attr(feature = "serde", serde(with = "As::<BTreeSet<DisplayFromStr>>"))]
    pub data: BTreeSet<DataOutput>,
    // #[cfg_attr(feature = "serde", serde(with = "As::<BTreeSet<DisplayFromStr>>"))]
    pub attach: BTreeSet<AttachOutput>,
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
        state.add_operation(None, genesis);
        state
    }

    pub fn add_transition(&mut self, txid: Txid, transition: &Transition) {
        self.add_operation(Some(txid), transition);
    }

    pub fn add_extension(&mut self, extension: &Extension) { self.add_operation(None, extension); }

    fn add_operation(&mut self, txid: Option<Txid>, op: &impl Operation) {
        let opid = op.id();

        for (ty, meta) in op.globals() {
            self.global
                .entry(opid)
                .or_default()
                .entry(*ty)
                .or_default()
                .extend(meta.iter().cloned());
        }

        fn process<State: ExposedState, Seal: ExposedSeal>(
            contract_state: &mut BTreeSet<OutputAssignment<State>>,
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
                    OutputAssignment::with(seal, state.into(), opid, ty, no as u16)
                };
                contract_state.insert(assigned_state);
            }
        }

        // Remove invalidated state
        for output in op.prev_outs() {
            if let Some(o) = self.rights.iter().find(|r| r.opout == output) {
                let o = o.clone(); // need this b/c of borrow checker
                self.rights.remove(&o);
            }
            if let Some(o) = self.fungibles.iter().find(|r| r.opout == output) {
                let o = o.clone();
                self.fungibles.remove(&o);
            }
            if let Some(o) = self.data.iter().find(|r| r.opout == output) {
                let o = o.clone();
                self.data.remove(&o);
            }
            if let Some(o) = self.attach.iter().find(|r| r.opout == output) {
                let o = o.clone();
                self.attach.remove(&o);
            }
        }

        for (ty, assignments) in op.assignments().iter() {
            match assignments {
                TypedAssigns::Declarative(assignments) => {
                    process(&mut self.rights, &assignments, opid, *ty, txid)
                }
                TypedAssigns::Fungible(assignments) => {
                    process(&mut self.fungibles, &assignments, opid, *ty, txid)
                }
                TypedAssigns::Structured(assignments) => {
                    process(&mut self.data, &assignments, opid, *ty, txid)
                }
                TypedAssigns::Attachment(assignments) => {
                    process(&mut self.attach, &assignments, opid, *ty, txid)
                }
            }
        }
    }
}

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
use std::cell::RefCell;
use std::cmp::Ordering;
use std::fmt::Debug;
use std::rc::Rc;

use amplify::num::u24;
use amplify::Bytes32;
use strict_encoding::{StrictDecode, StrictDumb, StrictEncode};

use crate::{
    AssetTags, AssignmentType, Assignments, AssignmentsRef, AttachState, ContractId, DataState,
    FungibleState, GlobalState, GlobalStateType, GraphSeal, Metadata, OpFullType, OpId, OpRef,
    Operation, TxOrd, Valencies, XOutpoint, XWitnessId, LIB_NAME_RGB_LOGIC,
};

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Display, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_LOGIC, tags = custom)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase", untagged)
)]
// TODO: Rename into `OpWitnessId`
pub enum AssignmentWitness {
    #[display("~")]
    #[strict_type(tag = 0, dumb)]
    Absent,

    // TODO: Consider separating transition and extension witnesses
    #[from]
    #[display(inner)]
    #[strict_type(tag = 1)]
    Present(XWitnessId),
}

impl PartialEq<XWitnessId> for AssignmentWitness {
    fn eq(&self, other: &XWitnessId) -> bool { self.witness_id() == Some(*other) }
}
impl PartialEq<AssignmentWitness> for XWitnessId {
    fn eq(&self, other: &AssignmentWitness) -> bool { other.witness_id() == Some(*self) }
}

impl From<Option<XWitnessId>> for AssignmentWitness {
    fn from(value: Option<XWitnessId>) -> Self {
        match value {
            None => AssignmentWitness::Absent,
            Some(id) => AssignmentWitness::Present(id),
        }
    }
}

impl AssignmentWitness {
    pub fn witness_id(&self) -> Option<XWitnessId> {
        match self {
            AssignmentWitness::Absent => None,
            AssignmentWitness::Present(witness_id) => Some(*witness_id),
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
// TODO: Rename into `WitnessOrd`
pub struct WitnessAnchor {
    pub witness_ord: TxOrd,
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
    pub fn with(witness_id: XWitnessId, witness_ord: TxOrd) -> Self {
        WitnessAnchor {
            witness_id,
            witness_ord,
        }
    }

    pub fn from_mempool(witness_id: XWitnessId, priority: u32) -> Self {
        WitnessAnchor {
            witness_ord: TxOrd::OffChain { priority },
            witness_id,
        }
    }
}

/// Consensus ordering of operations within a contract.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_LOGIC)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct OpOrd {
    pub witness_ord: WitnessAnchor,
    pub opid: OpId,
}

/// Consensus ordering of global state
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_LOGIC)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct GlobalOrd {
    // Absent for state defined in genesis
    // TODO: Change into `AssignmentWitness`
    pub witness_anchor: Option<WitnessAnchor>,
    pub opid: OpId,
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
    #[inline]
    pub fn with_witness(opid: OpId, witness_id: XWitnessId, ord: TxOrd, idx: u16) -> Self {
        GlobalOrd {
            witness_anchor: Some(WitnessAnchor::with(witness_id, ord)),
            opid,
            idx,
        }
    }
    #[inline]
    pub fn genesis(opid: OpId, idx: u16) -> Self {
        GlobalOrd {
            witness_anchor: None,
            opid,
            idx,
        }
    }
    #[inline]
    pub fn witness_id(&self) -> Option<XWitnessId> { self.witness_anchor.map(|a| a.witness_id) }
}

pub trait GlobalStateIter {
    type Data: Borrow<DataState>;
    fn size(&mut self) -> u24;
    fn prev(&mut self) -> Option<(GlobalOrd, Self::Data)>;
    fn last(&mut self) -> Option<(GlobalOrd, Self::Data)>;
    fn reset(&mut self, depth: u24);
}

impl<I: GlobalStateIter> GlobalStateIter for &mut I {
    type Data = I::Data;

    #[inline]
    fn size(&mut self) -> u24 { GlobalStateIter::size(*self) }

    #[inline]
    fn prev(&mut self) -> Option<(GlobalOrd, Self::Data)> { (*self).prev() }

    #[inline]
    fn last(&mut self) -> Option<(GlobalOrd, Self::Data)> { (*self).last() }

    #[inline]
    fn reset(&mut self, depth: u24) { (*self).reset(depth) }
}

pub struct GlobalContractState<I: GlobalStateIter> {
    checked_depth: u24,
    last_ord: GlobalOrd,
    iter: I,
}

impl<I: GlobalStateIter> GlobalContractState<I> {
    #[inline]
    pub fn new(mut iter: I) -> Self {
        let last_ord = iter.prev().map(|(ord, _)| ord).unwrap_or(GlobalOrd {
            // This is dumb object which must always have the lowest ordering.
            witness_anchor: None,
            opid: Bytes32::zero().into(),
            idx: 0,
        });
        iter.reset(u24::ZERO);
        Self {
            iter,
            checked_depth: u24::ONE,
            last_ord,
        }
    }

    #[inline]
    pub fn size(&mut self) -> u24 { self.iter.size() }

    /// Retrieves global state data located `depth` items back from the most
    /// recent global state value. Ensures that the global state ordering is
    /// consensus-based.
    pub fn nth(&mut self, depth: u24) -> Option<impl Borrow<DataState> + '_> {
        if depth >= self.iter.size() {
            return None;
        }
        if depth >= self.checked_depth {
            self.iter.reset(depth);
        } else {
            self.iter.reset(self.checked_depth);
            let size = self.iter.size();
            let to = (depth - self.checked_depth).to_u32();
            for inc in 0..to {
                let (ord, _) = self.iter.prev().unwrap_or_else(|| {
                    panic!(
                        "global contract state iterator has invalid implementation: it reports \
                         more global state items {size} than the contract has ({})",
                        self.checked_depth + inc
                    );
                });
                if ord >= self.last_ord {
                    panic!(
                        "global contract state iterator has invalid implementation: it fails to \
                         order global state according to the consensus ordering"
                    );
                }
                self.last_ord = ord;
            }
        }
        self.iter.last().map(|(_, item)| item)
    }
}

impl<I: GlobalStateIter> Iterator for GlobalContractState<I> {
    type Item = I::Data;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let (ord, item) = self.iter.prev()?;
        if ord >= self.last_ord {
            panic!(
                "global contract state iterator has invalid implementation: it fails to order \
                 global state according to the consensus ordering"
            );
        }
        self.checked_depth += u24::ONE;
        self.last_ord = ord;
        Some(item)
    }
}

#[derive(Copy, Clone, Debug, Display, Error)]
#[display("unknown global state type {0} requested from the contract")]
pub struct UnknownGlobalStateType(pub GlobalStateType);

// TODO: Separate mutable and immutable parts of the trait
pub trait ContractState: Debug + Default {
    fn global(
        &self,
        ty: GlobalStateType,
    ) -> Result<GlobalContractState<impl GlobalStateIter>, UnknownGlobalStateType>;

    fn rights(&self, outpoint: XOutpoint, ty: AssignmentType) -> u32;

    fn fungible(
        &self,
        outpoint: XOutpoint,
        ty: AssignmentType,
    ) -> impl DoubleEndedIterator<Item = FungibleState>;

    fn data(
        &self,
        outpoint: XOutpoint,
        ty: AssignmentType,
    ) -> impl DoubleEndedIterator<Item = impl Borrow<DataState>>;

    fn attach(
        &self,
        outpoint: XOutpoint,
        ty: AssignmentType,
    ) -> impl DoubleEndedIterator<Item = impl Borrow<AttachState>>;

    fn evolve_state(&mut self, op: OpRef);
}

pub struct VmContext<'op, S: ContractState> {
    pub op_info: OpInfo<'op>,
    pub contract_state: Rc<RefCell<S>>,
}

pub struct OpInfo<'op> {
    // TODO: Move to VmContext
    pub contract_id: ContractId,
    pub id: OpId,
    pub ty: OpFullType,
    // TODO: Move to VmContext
    pub asset_tags: &'op AssetTags,
    pub metadata: &'op Metadata,
    pub prev_state: &'op Assignments<GraphSeal>,
    pub owned_state: AssignmentsRef<'op>,
    pub redeemed: &'op Valencies,
    pub valencies: &'op Valencies,
    pub global: &'op GlobalState,
}

impl<'op> OpInfo<'op> {
    pub fn with(
        contract_id: ContractId,
        id: OpId,
        op: &'op OpRef<'op>,
        prev_state: &'op Assignments<GraphSeal>,
        redeemed: &'op Valencies,
        asset_tags: &'op AssetTags,
    ) -> Self {
        OpInfo {
            id,
            contract_id,
            ty: op.full_type(),
            asset_tags,
            metadata: op.metadata(),
            prev_state,
            owned_state: op.assignments(),
            redeemed,
            valencies: op.valencies(),
            global: op.globals(),
        }
    }
}

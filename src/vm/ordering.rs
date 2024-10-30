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
use std::fmt::{Debug, Display};
use std::num::NonZeroU32;
use std::rc::Rc;

use amplify::confinement;
use amplify::num::u24;
use single_use_seals::SealWitness;
use strict_types::{StrictDecode, StrictDumb, StrictEncode};

use crate::{
    Assign, AssignmentType, Assignments, AssignmentsRef, ContractId, ExposedSeal, Extension,
    ExtensionType, Genesis, GlobalState, GlobalStateType, GraphSeal, Inputs, Layer1, Metadata,
    OpFullType, OpId, OpType, Operation, Opout, State, Transition, TransitionType, TypedAssigns,
    UnverifiedState, Valencies, LIB_NAME_RGB_LOGIC,
};

/// RGB consensus information about the status of a witness transaction. This
/// information is used in ordering state transition and state extension
/// processing in the AluVM during the validation, as well as consensus ordering
/// of the contract global state data, as they are presented to all contract
/// users.
#[derive(Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Debug, Display, From)]
#[display(lowercase)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_LOGIC, tags = order)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum WitnessOrd {
    /// Seal witness is final (for instance, it was included into layer 1 blockchain at a safe
    /// depth).
    #[from]
    #[display(inner)]
    Final(u64),

    /// Valid witness which commits the most recent RGB state, but is not (yet) included into a
    /// layer 1. Such witnesses have a higher priority over the final witnesses (i.e. they
    /// are processed by the VM at the very end, and their global state becomes at the top of
    /// the contract state).
    ///
    /// NB: not each and every signed offchain transaction should have this
    /// status; all offchain cases which fall under [`Self::Archived`] must be
    /// excluded. Valid cases for assigning [`Self::Tentative`] status are:
    /// - transaction is present in the memepool;
    /// - transaction is a part of transaction graph inside a state channel (only actual channel
    ///   state is accounted for; all previous channel state must have corresponding transactions
    ///   set to [`Self::Archived`]);
    /// - transaction is an RBF replacement prepared to be broadcast (with the previous transaction
    ///   set to [`Self::Archived`] at the same moment).
    Tentative,
}

/// Operation ordering priority for contract state computation according to
/// [RCP-240731A].
///
/// The ordering is the following:
/// - Genesis is processed first.
/// - Other operations are ordered according to their witness transactions (see [`WitnessOrd`] for
///   the details).
/// - Extensions share witness transaction with the state transition which first to close one of the
///   seals defined in the extension, but are processed before that state transition.
/// - If two or more operations share the same witness transaction ordering, they are first ordered
///   basing on their `nonce` value, and if it is also the same, basing on their operation id value.
///
/// [RCP-240731A]: https://github.com/RGB-WG/RFC/issues/10
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_LOGIC, tags = custom)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum OpOrd {
    #[strict_type(tag = 0x00, dumb)]
    Genesis,
    #[strict_type(tag = 0x01)]
    Extension {
        witness: WitnessOrd,
        ty: ExtensionType,
        nonce: u64,
        opid: OpId,
    },
    #[strict_type(tag = 0xFF)]
    Transition {
        witness: WitnessOrd,
        ty: TransitionType,
        nonce: u64,
        opid: OpId,
    },
}

/// Consensus ordering of global state
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_LOGIC)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct GlobalOrd {
    pub op_ord: OpOrd,
    pub idx: u16,
}

impl GlobalOrd {
    pub fn genesis(idx: u16) -> Self {
        Self {
            op_ord: OpOrd::Genesis,
            idx,
        }
    }
    pub fn transition(
        opid: OpId,
        idx: u16,
        ty: TransitionType,
        nonce: u64,
        witness: WitnessOrd,
    ) -> Self {
        Self {
            op_ord: OpOrd::Transition {
                witness,
                ty,
                nonce,
                opid,
            },
            idx,
        }
    }
    pub fn extension(
        opid: OpId,
        idx: u16,
        ty: ExtensionType,
        nonce: u64,
        witness: WitnessOrd,
    ) -> Self {
        Self {
            op_ord: OpOrd::Extension {
                witness,
                ty,
                nonce,
                opid,
            },
            idx,
        }
    }
}

pub enum ImpossibleIter {}
impl Default for ImpossibleIter {
    fn default() -> Self { unreachable!() }
}
impl Iterator for ImpossibleIter {
    type Item = State;
    fn next(&mut self) -> Option<Self::Item> { unreachable!() }
}
impl DoubleEndedIterator for ImpossibleIter {
    fn next_back(&mut self) -> Option<Self::Item> { unreachable!() }
}

pub trait GlobalStateIter {
    type Data: Borrow<UnverifiedState>;
    fn size(&mut self) -> u24;
    fn prev(&mut self) -> Option<(GlobalOrd, Self::Data)>;
    fn last(&mut self) -> Option<(GlobalOrd, Self::Data)>;
    fn reset(&mut self, depth: u24);
}

impl GlobalStateIter for ImpossibleIter {
    type Data = UnverifiedState;
    fn size(&mut self) -> u24 { unreachable!() }
    fn prev(&mut self) -> Option<(GlobalOrd, Self::Data)> { unreachable!() }
    fn last(&mut self) -> Option<(GlobalOrd, Self::Data)> { unreachable!() }
    fn reset(&mut self, _: u24) { unreachable!() }
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
    last_ord: Option<GlobalOrd>,
    iter: I,
}

impl<I: GlobalStateIter> GlobalContractState<I> {
    #[inline]
    pub fn new(iter: I) -> Self {
        Self {
            iter,
            checked_depth: u24::ONE,
            last_ord: None,
        }
    }

    #[inline]
    pub fn size(&mut self) -> u24 { self.iter.size() }

    fn prev_checked(&mut self) -> Option<(GlobalOrd, I::Data)> {
        let (ord, item) = self.iter.prev()?;
        if self.last_ord.map(|last| ord <= last).unwrap_or_default() {
            panic!(
                "global contract state iterator has invalid implementation: it fails to order \
                 global state according to the consensus ordering"
            );
        }
        self.checked_depth += u24::ONE;
        self.last_ord = Some(ord);
        Some((ord, item))
    }

    /// Retrieves global state data located `depth` items back from the most
    /// recent global state value. Ensures that the global state ordering is
    /// consensus-based.
    pub fn nth(&mut self, depth: u24) -> Option<impl Borrow<UnverifiedState> + '_> {
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
                if self.prev_checked().is_none() {
                    panic!(
                        "global contract state iterator has invalid implementation: it reports \
                         more global state items {size} than the contract has ({})",
                        self.checked_depth + inc
                    );
                }
            }
        }
        self.iter.last().map(|(_, item)| item)
    }
}

impl<I: GlobalStateIter> Iterator for GlobalContractState<I> {
    type Item = I::Data;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> { Some(self.prev_checked()?.1) }
}

#[derive(Copy, Clone, Debug, Display, Error)]
#[display("unknown global state type {0} requested from the contract")]
pub struct UnknownGlobalStateType(pub GlobalStateType);

pub trait ContractStateAccess<Seal>: Debug {
    fn assignment(&self, opout: Opout) -> Option<impl Borrow<Assign<Seal>>>;

    /// Return an operator over a global state elements (in consensus ordering) of a given type
    /// `ty`.
    fn global(
        &self,
        ty: GlobalStateType,
    ) -> Result<GlobalContractState<impl GlobalStateIter>, UnknownGlobalStateType>;

    /// Return iterator over the state of a given type `ty` assigned to a specific `seal`.
    fn state(
        &self,
        seal: Seal,
        ty: AssignmentType,
    ) -> impl DoubleEndedIterator<Item = impl Borrow<State>>;
}

pub struct VmContext<'op, S: ContractStateAccess> {
    pub contract_id: ContractId,
    pub op_info: OpInfo<'op>,
    pub contract_state: Rc<RefCell<S>>,
}

pub struct OpInfo<'op> {
    pub id: OpId,
    pub ty: OpFullType,
    pub metadata: &'op Metadata,
    pub prev_state: &'op Assignments<GraphSeal>,
    pub owned_state: AssignmentsRef<'op>,
    pub redeemed: &'op Valencies,
    pub valencies: &'op Valencies,
    pub global: &'op GlobalState,
}

impl<'op> OpInfo<'op> {
    pub fn with(
        id: OpId,
        op: &'op OrdOpRef<'op>,
        prev_state: &'op Assignments<GraphSeal>,
        redeemed: &'op Valencies,
    ) -> Self {
        OpInfo {
            id,
            ty: op.full_type(),
            metadata: op.metadata(),
            prev_state,
            owned_state: op.assignments(),
            redeemed,
            valencies: op.valencies(),
            global: op.globals(),
        }
    }
}

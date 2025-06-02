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

use bc::{Outpoint, Txid};

use crate::{
    AssignmentType, AssignmentsRef, ContractId, FungibleState, Genesis, GlobalState,
    GlobalStateType, GraphSeal, Metadata, OpFullType, OpId, Operation, StructuredData, Transition,
    TransitionType, TypedAssigns,
};

/// The type is used during validation and computing a contract state. It
/// combines both the operation with the information required for its ordering
/// in the contract history (via construction of [`OpOrd`]) according to the
/// consensus rules.
#[derive(Copy, Clone, PartialEq, Eq, Debug, From)]
pub enum OrdOpRef<'op> {
    #[from]
    Genesis(&'op Genesis),
    Transition(&'op Transition, Txid, WitnessStatus, OpId),
}

impl PartialOrd for OrdOpRef<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl Ord for OrdOpRef<'_> {
    fn cmp(&self, other: &Self) -> Ordering { self.op_ord().cmp(&other.op_ord()) }
}

impl OrdOpRef<'_> {
    pub fn witness_id(&self) -> Option<Txid> {
        match self {
            OrdOpRef::Genesis(_) => None,
            OrdOpRef::Transition(_, witness_id, ..) => Some(*witness_id),
        }
    }

    pub fn opid(&self) -> Option<OpId> {
        match self {
            OrdOpRef::Genesis(_) => None,
            OrdOpRef::Transition(_, _, _, opid) => Some(*opid),
        }
    }

    pub fn op_ord(&self) -> OpOrd {
        match self {
            OrdOpRef::Genesis(_) => OpOrd::Genesis,
            OrdOpRef::Transition(op, _, witness_ord, _) => OpOrd::Transition {
                witness: *witness_ord,
                ty: op.transition_type,
                nonce: op.nonce,
                opid: op.id(),
            },
        }
    }
}

impl<'op> Operation for OrdOpRef<'op> {
    fn full_type(&self) -> OpFullType {
        match self {
            OrdOpRef::Genesis(op) => op.full_type(),
            OrdOpRef::Transition(op, ..) => op.full_type(),
        }
    }

    fn id(&self) -> OpId {
        match self {
            OrdOpRef::Genesis(op) => op.id(),
            OrdOpRef::Transition(op, ..) => op.id(),
        }
    }

    fn contract_id(&self) -> ContractId {
        match self {
            OrdOpRef::Genesis(op) => op.contract_id(),
            OrdOpRef::Transition(op, ..) => op.contract_id(),
        }
    }

    fn nonce(&self) -> u64 {
        match self {
            OrdOpRef::Genesis(op) => op.nonce(),
            OrdOpRef::Transition(op, ..) => op.nonce(),
        }
    }

    fn metadata(&self) -> &Metadata {
        match self {
            OrdOpRef::Genesis(op) => op.metadata(),
            OrdOpRef::Transition(op, ..) => op.metadata(),
        }
    }

    fn globals(&self) -> &GlobalState {
        match self {
            OrdOpRef::Genesis(op) => op.globals(),
            OrdOpRef::Transition(op, ..) => op.globals(),
        }
    }

    fn assignments(&self) -> AssignmentsRef<'op> {
        match self {
            OrdOpRef::Genesis(op) => op.assignments(),
            OrdOpRef::Transition(op, ..) => op.assignments(),
        }
    }

    fn assignments_by_type(&self, t: AssignmentType) -> Option<TypedAssigns<GraphSeal>> {
        match self {
            OrdOpRef::Genesis(op) => op.assignments_by_type(t),
            OrdOpRef::Transition(op, ..) => op.assignments_by_type(t),
        }
    }
}

/// RGB consensus information about the status of a witness transaction. This information is used
/// in ordering state transitions during the validation, as well as consensus ordering of the
/// contract global state data, as they are presented to all contract users.
#[derive(Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Debug, Display, From)]
#[display(lowercase)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum WitnessStatus {
    /// Transaction is included into layer 1 blockchain at a specific height.
    #[from]
    #[display(inner)]
    Mined(u32),

    /// Valid witness transaction which commits the most recent RGB state, but
    /// is not (yet) included into a layer 1 blockchain. Such transactions have
    /// a higher priority over onchain transactions (i.e. they are processed by
    /// the VM at the very end, and their global state becomes at the top of the
    /// contract state).
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

    /// Witness transaction must be ignored by the update witnesses process.
    Ignored,

    /// Witness transaction must be excluded from the state processing.
    ///
    /// Cases for the exclusion:
    /// - transaction was removed from blockchain after a re-org and its inputs were spent by other
    ///   transaction;
    /// - previous transaction(s) after RBF replacement, once it is excluded from the mempool and
    ///   replaced by RBFed successors;
    /// - past state channel transactions once a new channel state is signed (and until they may
    ///   become valid once again due to an uncooperative channel closing).
    Archived,
}

impl WitnessStatus {
    #[inline]
    pub fn is_valid(self) -> bool { self != Self::Archived }
}

/// Operation ordering priority for contract state computation according to
/// [RCP-240731A].
///
/// The ordering is the following:
/// - Genesis is processed first.
/// - Other operations are ordered according to their witness transactions (see [`WitnessStatus`]
///   for the details).
/// - If two or more operations share the same witness transaction ordering, they are first ordered
///   basing on their `nonce` value, and if it is also the same, basing on their operation id value.
///
/// [RCP-240731A]: https://github.com/RGB-WG/RFC/issues/10
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum OpOrd {
    Genesis,
    Transition {
        witness: WitnessStatus,
        ty: TransitionType,
        nonce: u64,
        opid: OpId,
    },
}

impl OpOrd {
    #[inline]
    pub fn is_archived(&self) -> bool {
        matches!(self, Self::Transition {
            witness: WitnessStatus::Archived,
            ..
        })
    }
}

#[derive(Copy, Clone, Debug, Display, Error)]
#[display("unknown global state type {0} requested from the contract")]
pub struct UnknownGlobalStateType(pub GlobalStateType);

pub trait ContractStateAccess: Debug {
    fn rights(&self, outpoint: Outpoint, ty: AssignmentType) -> u32;

    fn fungible(
        &self,
        outpoint: Outpoint,
        ty: AssignmentType,
    ) -> impl DoubleEndedIterator<Item = FungibleState>;

    fn data(
        &self,
        outpoint: Outpoint,
        ty: AssignmentType,
    ) -> impl DoubleEndedIterator<Item = impl Borrow<StructuredData>>;
}

pub trait ContractStateEvolve {
    type Context<'ctx>;
    type Error: std::error::Error;
    fn init(context: Self::Context<'_>) -> Self;
    fn evolve_state(&mut self, op: OrdOpRef) -> Result<(), Self::Error>;
}

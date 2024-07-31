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
use std::num::NonZeroU32;
use std::rc::Rc;

use amplify::num::u24;
use amplify::{confinement, Bytes32};
use bp::seals::txout::{CloseMethod, ExplicitSeal, VerifyError, Witness};
use bp::{dbc, Tx, Txid};
use commit_verify::mpc;
use single_use_seals::SealWitness;
use strict_encoding::{StrictDecode, StrictDumb, StrictEncode};

use crate::{
    AssetTags, AssignmentType, Assignments, AssignmentsRef, AttachState, ContractId, DataState,
    ExposedSeal, Extension, ExtensionType, FungibleState, Genesis, GlobalState, GlobalStateType,
    GraphSeal, Impossible, Inputs, Metadata, OpFullType, OpId, OpType, Operation, Transition,
    TransitionType, TxoSeal, TypedAssigns, Valencies, XChain, XOutpoint, XOutputSeal,
    LIB_NAME_RGB_LOGIC,
};

pub type XWitnessId = XChain<Txid>;

pub type XWitnessTx<X = Impossible> = XChain<Tx, X>;

impl XWitnessTx {
    pub fn witness_id(&self) -> XWitnessId {
        match self {
            Self::Bitcoin(tx) => XWitnessId::Bitcoin(tx.txid()),
            Self::Liquid(tx) => XWitnessId::Liquid(tx.txid()),
            Self::Other(_) => unreachable!(),
        }
    }
}

impl<Dbc: dbc::Proof> XChain<Witness<Dbc>> {
    pub fn witness_id(&self) -> XWitnessId {
        match self {
            Self::Bitcoin(w) => XWitnessId::Bitcoin(w.txid),
            Self::Liquid(w) => XWitnessId::Liquid(w.txid),
            Self::Other(_) => unreachable!(),
        }
    }
}

impl<Dbc: dbc::Proof, Seal: TxoSeal> SealWitness<Seal> for XChain<Witness<Dbc>> {
    type Message = mpc::Commitment;
    type Error = VerifyError<Dbc::Error>;

    fn verify_seal(&self, seal: &Seal, msg: &Self::Message) -> Result<(), Self::Error> {
        match self {
            Self::Bitcoin(witness) | Self::Liquid(witness) => witness.verify_seal(seal, msg),
            Self::Other(_) => unreachable!(),
        }
    }

    fn verify_many_seals<'seal>(
        &self,
        seals: impl IntoIterator<Item = &'seal Seal>,
        msg: &Self::Message,
    ) -> Result<(), Self::Error>
    where
        Seal: 'seal,
    {
        match self {
            Self::Bitcoin(witness) | Self::Liquid(witness) => witness.verify_many_seals(seals, msg),
            Self::Other(_) => unreachable!(),
        }
    }
}

impl<U: ExposedSeal> XChain<U> {
    pub fn method(self) -> CloseMethod
    where U: TxoSeal {
        match self {
            XChain::Bitcoin(seal) => seal.method(),
            XChain::Liquid(seal) => seal.method(),
            XChain::Other(_) => unreachable!(),
        }
    }

    #[inline]
    pub fn to_output_seal(self) -> Option<XOutputSeal>
    where U: TxoSeal {
        Some(match self {
            XChain::Bitcoin(seal) => {
                let outpoint = seal.outpoint()?;
                XChain::Bitcoin(ExplicitSeal::new(seal.method(), outpoint))
            }
            XChain::Liquid(seal) => {
                let outpoint = seal.outpoint()?;
                XChain::Liquid(ExplicitSeal::new(seal.method(), outpoint))
            }
            XChain::Other(_) => unreachable!(),
        })
    }

    pub fn try_to_output_seal(self, witness_id: XWitnessId) -> Result<XOutputSeal, Self>
    where U: TxoSeal {
        self.to_output_seal()
            .or(match (self, witness_id) {
                (XChain::Bitcoin(seal), XWitnessId::Bitcoin(txid)) => {
                    Some(XChain::Bitcoin(ExplicitSeal::new(seal.method(), seal.outpoint_or(txid))))
                }
                (XChain::Liquid(seal), XWitnessId::Liquid(txid)) => {
                    Some(XChain::Liquid(ExplicitSeal::new(seal.method(), seal.outpoint_or(txid))))
                }
                _ => None,
            })
            .ok_or(self)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, From)]
pub enum AnchoredOpRef<'op> {
    #[from]
    Genesis(&'op Genesis),
    Transition(&'op Transition, XWitnessId),
    Extension(&'op Extension, XWitnessId),
}

impl<'op> Operation for AnchoredOpRef<'op> {
    fn op_type(&self) -> OpType {
        match self {
            AnchoredOpRef::Genesis(op) => op.op_type(),
            AnchoredOpRef::Transition(op, _) => op.op_type(),
            AnchoredOpRef::Extension(op, _) => op.op_type(),
        }
    }

    fn full_type(&self) -> OpFullType {
        match self {
            AnchoredOpRef::Genesis(op) => op.full_type(),
            AnchoredOpRef::Transition(op, _) => op.full_type(),
            AnchoredOpRef::Extension(op, _) => op.full_type(),
        }
    }

    fn id(&self) -> OpId {
        match self {
            AnchoredOpRef::Genesis(op) => op.id(),
            AnchoredOpRef::Transition(op, _) => op.id(),
            AnchoredOpRef::Extension(op, _) => op.id(),
        }
    }

    fn contract_id(&self) -> ContractId {
        match self {
            AnchoredOpRef::Genesis(op) => op.contract_id(),
            AnchoredOpRef::Transition(op, _) => op.contract_id(),
            AnchoredOpRef::Extension(op, _) => op.contract_id(),
        }
    }

    fn transition_type(&self) -> Option<TransitionType> {
        match self {
            AnchoredOpRef::Genesis(op) => op.transition_type(),
            AnchoredOpRef::Transition(op, _) => op.transition_type(),
            AnchoredOpRef::Extension(op, _) => op.transition_type(),
        }
    }

    fn extension_type(&self) -> Option<ExtensionType> {
        match self {
            AnchoredOpRef::Genesis(op) => op.extension_type(),
            AnchoredOpRef::Transition(op, _) => op.extension_type(),
            AnchoredOpRef::Extension(op, _) => op.extension_type(),
        }
    }

    fn metadata(&self) -> &Metadata {
        match self {
            AnchoredOpRef::Genesis(op) => op.metadata(),
            AnchoredOpRef::Transition(op, _) => op.metadata(),
            AnchoredOpRef::Extension(op, _) => op.metadata(),
        }
    }

    fn globals(&self) -> &GlobalState {
        match self {
            AnchoredOpRef::Genesis(op) => op.globals(),
            AnchoredOpRef::Transition(op, _) => op.globals(),
            AnchoredOpRef::Extension(op, _) => op.globals(),
        }
    }

    fn valencies(&self) -> &Valencies {
        match self {
            AnchoredOpRef::Genesis(op) => op.valencies(),
            AnchoredOpRef::Transition(op, _) => op.valencies(),
            AnchoredOpRef::Extension(op, _) => op.valencies(),
        }
    }

    fn assignments(&self) -> AssignmentsRef<'op> {
        match self {
            AnchoredOpRef::Genesis(op) => (&op.assignments).into(),
            AnchoredOpRef::Transition(op, _) => (&op.assignments).into(),
            AnchoredOpRef::Extension(op, _) => (&op.assignments).into(),
        }
    }

    fn assignments_by_type(&self, t: AssignmentType) -> Option<TypedAssigns<GraphSeal>> {
        match self {
            AnchoredOpRef::Genesis(op) => op.assignments_by_type(t),
            AnchoredOpRef::Transition(op, _) => op.assignments_by_type(t),
            AnchoredOpRef::Extension(op, _) => op.assignments_by_type(t),
        }
    }

    fn inputs(&self) -> Inputs {
        match self {
            AnchoredOpRef::Genesis(op) => op.inputs(),
            AnchoredOpRef::Transition(op, _) => op.inputs(),
            AnchoredOpRef::Extension(op, _) => op.inputs(),
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Display)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_LOGIC)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[display("{height}@{timestamp}")]
pub struct WitnessPos {
    height: u32,
    timestamp: i64,
}

impl WitnessPos {
    pub fn new(height: u32, timestamp: i64) -> Option<Self> {
        if height == 0 || timestamp < 1231006505 {
            return None;
        }
        Some(WitnessPos { height, timestamp })
    }

    pub fn height(&self) -> NonZeroU32 { NonZeroU32::new(self.height).expect("invariant") }
}

impl PartialOrd for WitnessPos {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl Ord for WitnessPos {
    /// Since we support multiple layer 1, we have to order basing on the
    /// timestamp information and not height. The timestamp data are consistent
    /// accross multiple blockchains, while height evolves with a different
    /// speed and can't be used in comparisons.
    fn cmp(&self, other: &Self) -> Ordering {
        assert!(self.timestamp > 0);
        assert!(other.timestamp > 0);
        self.timestamp.cmp(&other.timestamp)
    }
}

/// RGB consensus information about the status of a witness transaction. This
/// information is used in ordering state transition and state extension
/// processing in the AluVM during the validation, as well as consensus ordering
/// of the contract global state data, as they are presented to all contract
/// users.
#[derive(Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Debug, Display, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_LOGIC, tags = order)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase", untagged)
)]
pub enum WitnessOrd {
    /// Witness transaction must be excluded from the state processing.
    ///
    /// Cases for the exclusion:
    /// - transaction was removed from blockchain after a re-org and its inputs
    ///   were spent by other transaction;
    /// - previous transaction(s) after RBF replacement, once it is excluded
    ///   from the mempool and replaced by RBFed successors;
    /// - past state channel transactions once a new channel state is signed
    ///   (and until they may become valid once again due to an uncooperative
    ///   channel closing).
    #[display("archived")]
    #[strict_type(dumb)]
    Archived,

    /// Transaction is included into layer 1 blockchain at a specific height and
    /// timestamp.
    ///
    /// NB: only timestamp is used in consensus ordering though, see
    /// [`WitnessPos::ord`] for the details.
    #[from]
    #[display(inner)]
    Mined(WitnessPos),

    /// Valid witness transaction which commits the most recent RGB state, but
    /// is not (yet) included into a layer 1 blockchain. Such transactions have
    /// a higher priority over onchain transactions (i.e. they are processed by
    /// the VM at the very end, and their global state becomes at the top of the
    /// contract state).
    ///
    /// NB: not each and every signed offchain transaction should have this
    /// status; all offchain cases which fall under [`Self::Archived`] must be
    /// excluded. Valid cases for assigning [`Self::Offchain`] status are:
    /// - transaction is present in the memepool;
    /// - transaction is a part of transaction graph inside a state channel
    ///   (only actual channel state is accounted for; all previous channel
    ///   state must have corresponding transactions set to [`Self::Archived`]);
    /// - transaction is an RBF replacement prepared to be broadcast (with the
    ///   previous transaction set to [`Self::Archived`] at the same moment).
    #[display("tentative")]
    Tentative,
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_LOGIC, tags = custom, dumb = { Self::Transition { nonce: 0 } })]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum OpTypeOrd {
    #[strict_type(tag = 0x00)]
    Extension { nonce: u8 },
    #[strict_type(tag = 0xFF)]
    Transition { nonce: u8 },
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
    pub witness_ord: WitnessOrd,
    pub op_type: OpTypeOrd,
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
    pub witness_ord: Option<WitnessOrd>,
    pub op_type: OpTypeOrd,
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
        match (self.witness_ord, &other.witness_ord) {
            (None, None) if self.opid.cmp(&other.opid) == Ordering::Equal => {
                self.idx.cmp(&other.idx)
            }
            (None, None) => self.opid.cmp(&other.opid),
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,
            (Some(ord1), Some(ord2)) if ord1 == *ord2 => self.idx.cmp(&other.idx),
            (Some(ord1), Some(ord2)) => ord1.cmp(ord2),
        }
    }
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
            witness_ord: None,
            opid: Bytes32::zero().into(),
            op_type: OpTypeOrd::Transition { nonce: 0 },
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

    fn prev_checked(&mut self) -> Option<(GlobalOrd, I::Data)> {
        let (ord, item) = self.iter.prev()?;
        if ord >= self.last_ord {
            panic!(
                "global contract state iterator has invalid implementation: it fails to order \
                 global state according to the consensus ordering"
            );
        }
        if ord.witness_ord == Some(WitnessOrd::Archived) {
            panic!("invalid GlobalStateIter implementation returning WitnessAnchor::Archived")
        }
        self.checked_depth += u24::ONE;
        self.last_ord = ord;
        Some((ord, item))
    }

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

pub trait ContractStateAccess: Debug {
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
}

pub trait ContractStateEvolve {
    type Context<'ctx>;
    fn init(context: Self::Context<'_>) -> Self;
    // TODO: Use more specific error type
    fn evolve_state(&mut self, op: AnchoredOpRef) -> Result<(), confinement::Error>;
}

pub struct VmContext<'op, S: ContractStateAccess> {
    pub contract_id: ContractId,
    pub asset_tags: &'op AssetTags,
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
        op: &'op AnchoredOpRef<'op>,
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

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
use std::fmt::{self, Debug, Display, Formatter};
use std::num::NonZeroU32;
use std::rc::Rc;

use amplify::confinement;
use amplify::num::u24;
use bp::seals::txout::{ExplicitSeal, VerifyError, Witness};
use bp::{dbc, Tx, Txid};
use chrono::{MappedLocalTime, TimeZone, Utc};
use commit_verify::mpc;
use single_use_seals::SealWitness;
use strict_encoding::{StrictDecode, StrictDumb, StrictEncode};

use crate::{
    AssignmentType, Assignments, AssignmentsRef, AttachState, BundleId, ContractId, DataState,
    ExposedSeal, Extension, ExtensionType, FungibleState, Genesis, GlobalState, GlobalStateType,
    GraphSeal, Impossible, Inputs, Layer1, Metadata, OpFullType, OpId, OpType, Operation,
    Transition, TransitionType, TxoSeal, TypedAssigns, Valencies, XChain, XOutpoint, XOutputSeal,
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
    #[inline]
    pub fn to_output_seal(self) -> Option<XOutputSeal>
    where U: TxoSeal {
        Some(match self {
            XChain::Bitcoin(seal) => {
                let outpoint = seal.outpoint()?;
                XChain::Bitcoin(ExplicitSeal::new(outpoint))
            }
            XChain::Liquid(seal) => {
                let outpoint = seal.outpoint()?;
                XChain::Liquid(ExplicitSeal::new(outpoint))
            }
            XChain::Other(_) => unreachable!(),
        })
    }

    pub fn try_to_output_seal(self, witness_id: XWitnessId) -> Result<XOutputSeal, Self>
    where U: TxoSeal {
        self.to_output_seal()
            .or(match (self, witness_id) {
                (XChain::Bitcoin(seal), XWitnessId::Bitcoin(txid)) => {
                    Some(XChain::Bitcoin(ExplicitSeal::new(seal.outpoint_or(txid))))
                }
                (XChain::Liquid(seal), XWitnessId::Liquid(txid)) => {
                    Some(XChain::Liquid(ExplicitSeal::new(seal.outpoint_or(txid))))
                }
                _ => None,
            })
            .ok_or(self)
    }
}

/// The type is used during validation and computing a contract state. It
/// combines both the operation with the information required for its ordering
/// in the contract history (via construction of [`OpOrd`]) according to the
/// consensus rules.
#[derive(Copy, Clone, PartialEq, Eq, Debug, From)]
pub enum OrdOpRef<'op> {
    #[from]
    Genesis(&'op Genesis),
    Transition(&'op Transition, XWitnessId, WitnessOrd, BundleId),
    Extension(&'op Extension, XWitnessId, WitnessOrd),
}

impl PartialOrd for OrdOpRef<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl Ord for OrdOpRef<'_> {
    fn cmp(&self, other: &Self) -> Ordering { self.op_ord().cmp(&other.op_ord()) }
}

impl OrdOpRef<'_> {
    pub fn witness_id(&self) -> Option<XWitnessId> {
        match self {
            OrdOpRef::Genesis(_) => None,
            OrdOpRef::Transition(_, witness_id, ..) | OrdOpRef::Extension(_, witness_id, ..) => {
                Some(*witness_id)
            }
        }
    }

    pub fn bundle_id(&self) -> Option<BundleId> {
        match self {
            OrdOpRef::Genesis(_) | OrdOpRef::Extension(..) => None,
            OrdOpRef::Transition(_, _, _, bundle_id) => Some(*bundle_id),
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
            OrdOpRef::Extension(op, _, witness_ord) => OpOrd::Extension {
                witness: *witness_ord,
                ty: op.extension_type,
                nonce: op.nonce,
                opid: op.id(),
            },
        }
    }
}

impl<'op> Operation for OrdOpRef<'op> {
    fn op_type(&self) -> OpType {
        match self {
            OrdOpRef::Genesis(op) => op.op_type(),
            OrdOpRef::Transition(op, ..) => op.op_type(),
            OrdOpRef::Extension(op, ..) => op.op_type(),
        }
    }

    fn full_type(&self) -> OpFullType {
        match self {
            OrdOpRef::Genesis(op) => op.full_type(),
            OrdOpRef::Transition(op, ..) => op.full_type(),
            OrdOpRef::Extension(op, ..) => op.full_type(),
        }
    }

    fn id(&self) -> OpId {
        match self {
            OrdOpRef::Genesis(op) => op.id(),
            OrdOpRef::Transition(op, ..) => op.id(),
            OrdOpRef::Extension(op, ..) => op.id(),
        }
    }

    fn contract_id(&self) -> ContractId {
        match self {
            OrdOpRef::Genesis(op) => op.contract_id(),
            OrdOpRef::Transition(op, ..) => op.contract_id(),
            OrdOpRef::Extension(op, ..) => op.contract_id(),
        }
    }

    fn nonce(&self) -> u64 {
        match self {
            OrdOpRef::Genesis(op) => op.nonce(),
            OrdOpRef::Transition(op, ..) => op.nonce(),
            OrdOpRef::Extension(op, ..) => op.nonce(),
        }
    }

    fn transition_type(&self) -> Option<TransitionType> {
        match self {
            OrdOpRef::Genesis(op) => op.transition_type(),
            OrdOpRef::Transition(op, ..) => op.transition_type(),
            OrdOpRef::Extension(op, ..) => op.transition_type(),
        }
    }

    fn extension_type(&self) -> Option<ExtensionType> {
        match self {
            OrdOpRef::Genesis(op) => op.extension_type(),
            OrdOpRef::Transition(op, ..) => op.extension_type(),
            OrdOpRef::Extension(op, ..) => op.extension_type(),
        }
    }

    fn metadata(&self) -> &Metadata {
        match self {
            OrdOpRef::Genesis(op) => op.metadata(),
            OrdOpRef::Transition(op, ..) => op.metadata(),
            OrdOpRef::Extension(op, ..) => op.metadata(),
        }
    }

    fn globals(&self) -> &GlobalState {
        match self {
            OrdOpRef::Genesis(op) => op.globals(),
            OrdOpRef::Transition(op, ..) => op.globals(),
            OrdOpRef::Extension(op, ..) => op.globals(),
        }
    }

    fn valencies(&self) -> &Valencies {
        match self {
            OrdOpRef::Genesis(op) => op.valencies(),
            OrdOpRef::Transition(op, ..) => op.valencies(),
            OrdOpRef::Extension(op, ..) => op.valencies(),
        }
    }

    fn assignments(&self) -> AssignmentsRef<'op> {
        match self {
            OrdOpRef::Genesis(op) => (&op.assignments).into(),
            OrdOpRef::Transition(op, ..) => (&op.assignments).into(),
            OrdOpRef::Extension(op, ..) => (&op.assignments).into(),
        }
    }

    fn assignments_by_type(&self, t: AssignmentType) -> Option<TypedAssigns<GraphSeal>> {
        match self {
            OrdOpRef::Genesis(op) => op.assignments_by_type(t),
            OrdOpRef::Transition(op, ..) => op.assignments_by_type(t),
            OrdOpRef::Extension(op, ..) => op.assignments_by_type(t),
        }
    }

    fn inputs(&self) -> Inputs {
        match self {
            OrdOpRef::Genesis(op) => op.inputs(),
            OrdOpRef::Transition(op, ..) => op.inputs(),
            OrdOpRef::Extension(op, ..) => op.inputs(),
        }
    }
}

#[derive(Getters, Copy, Clone, PartialEq, Eq, Hash, Debug)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_LOGIC)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct WitnessPos {
    #[getter(as_copy)]
    layer1: Layer1,

    // TODO: Move BlockHeight from bp-wallet to bp-consensus and use it here
    #[getter(as_copy)]
    height: NonZeroU32,

    #[getter(as_copy)]
    timestamp: i64,
}

impl StrictDumb for WitnessPos {
    fn strict_dumb() -> Self {
        Self {
            layer1: Layer1::Bitcoin,
            height: NonZeroU32::MIN,
            timestamp: 1231006505,
        }
    }
}

// Sat Jan 03 18:15:05 2009 UTC
const BITCOIN_GENESIS_TIMESTAMP: i64 = 1231006505;

// Sat Jan 03 18:15:05 2009 UTC
const LIQUID_GENESIS_TIMESTAMP: i64 = 1296692202;

impl WitnessPos {
    #[deprecated(
        since = "0.11.0-beta.9",
        note = "please use `WitnessPos::bitcoin` or `WitnessPos::liquid` instead"
    )]
    pub fn new(height: NonZeroU32, timestamp: i64) -> Option<Self> {
        Self::bitcoin(height, timestamp)
    }

    pub fn bitcoin(height: NonZeroU32, timestamp: i64) -> Option<Self> {
        if timestamp < BITCOIN_GENESIS_TIMESTAMP {
            return None;
        }
        Some(WitnessPos {
            layer1: Layer1::Bitcoin,
            height,
            timestamp,
        })
    }

    pub fn liquid(height: NonZeroU32, timestamp: i64) -> Option<Self> {
        if timestamp < LIQUID_GENESIS_TIMESTAMP {
            return None;
        }
        Some(WitnessPos {
            layer1: Layer1::Liquid,
            height,
            timestamp,
        })
    }
}

impl PartialOrd for WitnessPos {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl Ord for WitnessPos {
    /// Since we support multiple layer 1, we have to order basing on the
    /// timestamp information and not height. The timestamp data are consistent
    /// across multiple blockchains, while height evolves with a different
    /// speed and can't be used in comparisons.
    fn cmp(&self, other: &Self) -> Ordering {
        assert!(self.timestamp > 0);
        assert!(other.timestamp > 0);
        const BLOCK_TIME: i64 = 10 /*min*/ * 60 /*secs*/;
        match (self.layer1, other.layer1) {
            (a, b) if a == b => self.height.cmp(&other.height),
            (Layer1::Bitcoin, Layer1::Liquid)
                if (self.timestamp - other.timestamp).abs() < BLOCK_TIME =>
            {
                Ordering::Greater
            }
            (Layer1::Liquid, Layer1::Bitcoin)
                if (other.timestamp - self.timestamp).abs() < BLOCK_TIME =>
            {
                Ordering::Less
            }
            _ => self.timestamp.cmp(&other.timestamp),
        }
    }
}

impl Display for WitnessPos {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}, ", self.layer1, self.height)?;
        match Utc.timestamp_opt(self.timestamp, 0) {
            MappedLocalTime::Single(time) => write!(f, "{}", time.format("%Y-%m-%d %H:%M:%S")),
            _ => f.write_str("invalid timestamp"),
        }
    }
}

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
    #[strict_type(dumb)]
    Archived,

    /// Transaction is included into layer 1 blockchain at a specific height and
    /// timestamp.
    ///
    /// NB: only timestamp is used in consensus ordering though, see
    /// [`WitnessPos::cmp`] for the details.
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
    /// excluded. Valid cases for assigning [`Self::Tentative`] status are:
    /// - transaction is present in the memepool;
    /// - transaction is a part of transaction graph inside a state channel (only actual channel
    ///   state is accounted for; all previous channel state must have corresponding transactions
    ///   set to [`Self::Archived`]);
    /// - transaction is an RBF replacement prepared to be broadcast (with the previous transaction
    ///   set to [`Self::Archived`] at the same moment).
    Tentative,
}

impl WitnessOrd {
    #[inline]
    pub fn is_valid(self) -> bool { self != Self::Archived }
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

impl OpOrd {
    #[inline]
    pub fn is_archived(&self) -> bool {
        matches!(
            self,
            Self::Extension {
                witness: WitnessOrd::Archived,
                ..
            } | Self::Transition {
                witness: WitnessOrd::Archived,
                ..
            }
        )
    }
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
        if ord.op_ord.is_archived() {
            panic!("invalid GlobalStateIter implementation returning WitnessOrd::Archived")
        }
        self.checked_depth += u24::ONE;
        self.last_ord = Some(ord);
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
    // TODO: distinguish contract validation failure errors from connectivity
    //       errors. Allow custom error types here.
    fn evolve_state(&mut self, op: OrdOpRef) -> Result<(), confinement::Error>;
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn witness_post_timestamp() {
        assert_eq!(WitnessPos::bitcoin(NonZeroU32::MIN, BITCOIN_GENESIS_TIMESTAMP - 1), None);
        assert_eq!(WitnessPos::liquid(NonZeroU32::MIN, LIQUID_GENESIS_TIMESTAMP - 1), None);
        assert_eq!(WitnessPos::liquid(NonZeroU32::MIN, BITCOIN_GENESIS_TIMESTAMP), None);
        assert!(WitnessPos::bitcoin(NonZeroU32::MIN, BITCOIN_GENESIS_TIMESTAMP).is_some());
        assert!(WitnessPos::liquid(NonZeroU32::MIN, LIQUID_GENESIS_TIMESTAMP).is_some());
        assert!(WitnessPos::bitcoin(NonZeroU32::MIN, LIQUID_GENESIS_TIMESTAMP).is_some());
    }

    #[test]
    fn witness_pos_getters() {
        let pos = WitnessPos::bitcoin(NonZeroU32::MIN, BITCOIN_GENESIS_TIMESTAMP).unwrap();
        assert_eq!(pos.height(), NonZeroU32::MIN);
        assert_eq!(pos.timestamp(), BITCOIN_GENESIS_TIMESTAMP);
        assert_eq!(pos.layer1(), Layer1::Bitcoin);

        let pos = WitnessPos::liquid(NonZeroU32::MIN, LIQUID_GENESIS_TIMESTAMP).unwrap();
        assert_eq!(pos.height(), NonZeroU32::MIN);
        assert_eq!(pos.timestamp(), LIQUID_GENESIS_TIMESTAMP);
        assert_eq!(pos.layer1(), Layer1::Liquid);
    }
}

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

use core::ops::AddAssign;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt::{self, Display, Formatter};

use amplify::num::u24;
use bp::seals::txout::CloseMethod;
use bp::Txid;
use commit_verify::mpc::InvalidProof;
use strict_types::SemId;

use crate::schema::{self, SchemaId};
use crate::validation::WitnessResolverError;
use crate::{
    BundleId, ChainNet, ContractId, OccurrencesMismatch, OpFullType, OpId, Opout,
    SealClosingStrategy, StateType,
};

pub type UnsafeHistoryMap = HashMap<u32, HashSet<Txid>>;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Display)]
#[repr(u8)]
pub enum Validity {
    #[display("is valid")]
    Valid,

    #[display("valid, with warnings")]
    Warnings,

    #[display("is NOT valid")]
    Invalid,
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct Status {
    pub failures: Vec<Failure>,
    pub warnings: Vec<Warning>,
    pub info: Vec<Info>,
    pub validated_opids: BTreeSet<OpId>,
}

impl Display for Status {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            writeln!(f, "Consignment {}", self.validity())?;
        }

        if !self.failures.is_empty() {
            f.write_str("Validation failures:\n")?;
            for fail in &self.failures {
                writeln!(f, "- {fail}")?;
            }
        }

        if !self.warnings.is_empty() {
            f.write_str("Validation warnings:\n")?;
            for warn in &self.warnings {
                writeln!(f, "- {warn}")?;
            }
        }

        if !self.info.is_empty() {
            f.write_str("Validation info:\n")?;
            for info in &self.info {
                writeln!(f, "- {info}")?;
            }
        }

        Ok(())
    }
}

impl AddAssign for Status {
    fn add_assign(&mut self, rhs: Self) {
        self.failures.extend(rhs.failures);
        self.warnings.extend(rhs.warnings);
        self.info.extend(rhs.info);
    }
}

impl Status {
    pub fn from_error(v: Failure) -> Self {
        Status {
            failures: vec![v],
            warnings: vec![],
            info: vec![],
            validated_opids: bset![],
        }
    }
}

impl FromIterator<Failure> for Status {
    fn from_iter<T: IntoIterator<Item = Failure>>(iter: T) -> Self {
        Self {
            failures: iter.into_iter().collect(),
            ..Self::default()
        }
    }
}

impl Status {
    pub fn new() -> Self { Self::default() }

    pub fn with_failure(failure: impl Into<Failure>) -> Self {
        Self {
            failures: vec![failure.into()],
            ..Self::default()
        }
    }

    pub fn add_failure(&mut self, failure: impl Into<Failure>) -> &Self {
        self.failures.push(failure.into());
        self
    }

    pub fn add_warning(&mut self, warning: impl Into<Warning>) -> &Self {
        self.warnings.push(warning.into());
        self
    }

    pub fn add_info(&mut self, info: impl Into<Info>) -> &Self {
        self.info.push(info.into());
        self
    }

    pub fn validity(&self) -> Validity {
        if !self.failures.is_empty() {
            Validity::Invalid
        } else if !self.warnings.is_empty() {
            Validity::Warnings
        } else {
            Validity::Valid
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, From)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[display(doc_comments)]
pub enum Failure {
    /// the contract chain-network pair doesn't match (validator runs in chain_net={0}
    /// configuration).
    ContractChainNetMismatch(ChainNet),

    /// the resolver chain-network pair doesn't match (validator runs in chain_net={0}
    /// configuration).
    ResolverChainNetMismatch(ChainNet),

    /// schema {actual} provided for the consignment validation doesn't match
    /// schema {expected} used by the contract. This means that the consignment
    /// is invalid.
    SchemaMismatch {
        /// Expected schema id required by the contract genesis.
        expected: SchemaId,
        /// Actual schema id provided by the consignment.
        actual: SchemaId,
    },

    /// schema global state #{0} uses semantic data type absent in type library
    /// ({1}).
    SchemaGlobalSemIdUnknown(schema::GlobalStateType, SemId),
    /// schema owned state #{0} uses semantic data type absent in type library
    /// ({1}).
    SchemaOwnedSemIdUnknown(schema::AssignmentType, SemId),
    /// schema metadata #{0} uses semantic data type absent in type library
    /// ({1}).
    SchemaMetaSemIdUnknown(schema::MetaType, SemId),

    /// schema for {0} has zero inputs.
    SchemaOpEmptyInputs(OpFullType),
    /// schema for {0} references undeclared metadata type {1}.
    SchemaOpMetaTypeUnknown(OpFullType, schema::MetaType),
    /// schema for {0} references undeclared global state type {1}.
    SchemaOpGlobalTypeUnknown(OpFullType, schema::GlobalStateType),
    /// schema for {0} references undeclared owned state type {1}.
    SchemaOpAssignmentTypeUnknown(OpFullType, schema::AssignmentType),

    /// operation {0} uses invalid state transition type {1}.
    SchemaUnknownTransitionType(OpId, schema::TransitionType),
    /// operation {0} uses invalid metadata type {1}.
    SchemaUnknownMetaType(OpId, schema::MetaType),
    /// operation {0} uses invalid global state type {1}.
    SchemaUnknownGlobalStateType(OpId, schema::GlobalStateType),
    /// operation {0} uses invalid assignment type {1}.
    SchemaUnknownAssignmentType(OpId, schema::AssignmentType),
    /// operation {0} uses invalid seal closing strategy {1}.
    SchemaUnknownSealClosingStrategy(OpId, SealClosingStrategy),

    /// invalid number of global state entries of type {1} in operation {0} -
    /// {2}
    SchemaGlobalStateOccurrences(OpId, schema::GlobalStateType, OccurrencesMismatch),
    /// number of global state entries of type {1} in operation {0} exceeds
    /// schema-defined maximum for that global state type ({2} vs {3}).
    SchemaGlobalStateLimit(OpId, schema::GlobalStateType, u16, u24),
    /// required metadata type {1} is not present in the operation {0}.
    SchemaNoMetadata(OpId, schema::MetaType),
    /// invalid metadata in operation {0} not matching semantic type id {1}.
    SchemaInvalidMetadata(OpId, SemId),
    /// invalid global state value in operation {0}, state type #{1} which does
    /// not match semantic type id {2}.
    SchemaInvalidGlobalValue(OpId, schema::GlobalStateType, SemId),
    /// invalid owned state value in operation {0}, state type #{1} which does
    /// not match semantic type id {2}.
    SchemaInvalidOwnedValue(OpId, schema::AssignmentType, SemId),
    /// invalid number of input entries of type {1} in operation {0} - {2}  
    SchemaInputOccurrences(OpId, schema::AssignmentType, OccurrencesMismatch),
    /// invalid number of assignment entries of type {1} in operation {0} - {2}
    SchemaAssignmentOccurrences(OpId, schema::AssignmentType, OccurrencesMismatch),

    // Consignment consistency errors
    /// operation {0} is referenced within the history multiple times. RGB
    /// contracts allow only direct acyclic graphs.
    CyclicGraph(OpId),
    /// operation {0} is absent from the consignment.
    OperationAbsent(OpId),
    /// anchor for transitio bundle {0} is absent in the consignment.
    AnchorAbsent(BundleId),
    /// witness id for transition bundle {0} is absent in the consignment.
    WitnessIdAbsent(BundleId),
    /// bundle {0} public witness {1} is not known to the resolver; validation
    /// stopped since operations can't be consensus-ordered. The resolver
    /// responded with error {2}
    WitnessUnresolved(BundleId, Txid, WitnessResolverError),
    /// operation {0} is under a different contract {1}.
    ContractMismatch(OpId, ContractId),
    /// opout {0} appears more than once as input
    DoubleSpend(Opout),
    /// transition bundle {0} known transitions references a state transition which is not
    /// in the bundle input map.
    ExtraKnownTransition(BundleId),
    /// transition claims ID {0} which differs from the actual one {1}
    TransitionIdMismatch(OpId, OpId),
    /// found a transition {0} not in order.
    UnorderedTransition(OpId),

    // Errors checking bundle commitments
    /// transition bundle {0} references non-existing input in witness {2} for
    /// the state transition {1}.
    WitnessMissingInput(BundleId, OpId, Txid),
    /// transition bundle {0} input map is missing an opout {1} in input on a known transition
    MissingInputMapTransition(BundleId, OpId),

    // Errors checking seal closing
    /// transition {opid} references state type {state_type} absent in the
    /// outputs of previous state transition {prev_id}.
    NoPrevState {
        opid: OpId,
        prev_id: OpId,
        state_type: schema::AssignmentType,
    },
    /// transition {0} references non-existing previous output {1}.
    NoPrevOut(OpId, Opout),
    /// seal defined in the history as a part of operation output {0} is
    /// confidential and can't be validated.
    ConfidentialSeal(Opout),
    /// bundle {0} public witness {1} is not known to the resolver. Resolver
    /// reported error {2}
    SealNoPubWitness(BundleId, Txid, WitnessResolverError),
    /// transition bundle {0} doesn't close seal with the witness {1}. Details:
    /// {2}
    SealsInvalid(BundleId, Txid, String),
    /// single-use seals for the operation {0} were not validated, which
    /// probably indicates unanchored state transition.
    SealsUnvalidated(OpId),
    /// transition bundle {0} is not properly anchored to the witness {1}.
    /// Details: {2}
    MpcInvalid(BundleId, Txid, InvalidProof),
    /// witness transaction {0} has no taproot or OP_RETURN output.
    NoDbcOutput(Txid),
    /// first DBC-compatible output of witness transaction {0} doesn't match the provided proof
    /// type ({1})
    InvalidProofType(Txid, CloseMethod),

    // State check errors
    /// state in {opid}/{state_type} is of {found} type, while schema requires
    /// it to be {expected}.
    StateTypeMismatch {
        opid: OpId,
        state_type: schema::AssignmentType,
        expected: StateType,
        found: StateType,
    },
    /// state in {opid}/{state_type} is of {found} type, while schema requires
    /// it to be {expected}.
    FungibleTypeMismatch {
        opid: OpId,
        state_type: schema::AssignmentType,
        expected: schema::FungibleType,
        found: schema::FungibleType,
    },
    /// evaluation of AluVM script for operation {0} has failed with the code
    /// {1:?} and message {2:?}.
    ScriptFailure(OpId, Option<u8>, Option<String>),
    /// contract state can't fit more data (at operation id {0}).
    ContractStateFilled(OpId),

    /// Custom error by external services on top of RGB Core.
    #[display(inner)]
    Custom(String),
}

#[derive(Clone, PartialEq, Eq, Debug, Display, From)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[display(doc_comments)]
pub enum Warning {
    /// Map of transfer history TXs with potentially unsafe height.
    UnsafeHistory(UnsafeHistoryMap),

    /// Custom warning by external services on top of RGB Core.
    #[display(inner)]
    Custom(String),
}

#[derive(Clone, PartialEq, Eq, Debug, Display, From)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
#[display(doc_comments)]
pub enum Info {
    /// Custom info by external services on top of RGB Core.
    #[display(inner)]
    Custom(String),
}

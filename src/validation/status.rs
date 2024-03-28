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
use std::fmt::{self, Display, Formatter};

use bp::Txid;
use commit_verify::mpc::InvalidProof;
use strict_types::SemId;

use crate::contract::Opout;
use crate::schema::{self, SchemaId};
use crate::{
    BundleId, ContractId, Layer1, OccurrencesMismatch, OpFullType, OpId, SecretSeal, StateType,
    Vin, WitnessId, XChain, XGraphSeal,
};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Display)]
#[repr(u8)]
pub enum Validity {
    #[display("is valid")]
    Valid,

    #[display("has non-mined terminal(s)")]
    UnminedTerminals,

    #[display("contains unknown witness transactions")]
    UnresolvedTransactions,

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
    pub absent_pub_witnesses: Vec<WitnessId>,
    pub unmined_terminals: Vec<Txid>,
    pub failures: Vec<Failure>,
    pub warnings: Vec<Warning>,
    pub info: Vec<Info>,
}

impl Display for Status {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            writeln!(f, "Consignment {}", self.validity())?;
        }

        if !self.absent_pub_witnesses.is_empty() {
            f.write_str("Unknown public witnesses:\n")?;
            for txid in &self.absent_pub_witnesses {
                writeln!(f, "- {txid}")?;
            }
        }

        if !self.unmined_terminals.is_empty() {
            f.write_str("Non-mined terminals:\n")?;
            for txid in &self.unmined_terminals {
                writeln!(f, "- {txid}")?;
            }
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
        self.absent_pub_witnesses.extend(rhs.absent_pub_witnesses);
        self.unmined_terminals.extend(rhs.unmined_terminals);
        self.failures.extend(rhs.failures);
        self.warnings.extend(rhs.warnings);
        self.info.extend(rhs.info);
    }
}

impl Status {
    pub fn from_error(v: Failure) -> Self {
        Status {
            absent_pub_witnesses: vec![],
            unmined_terminals: vec![],
            failures: vec![v],
            warnings: vec![],
            info: vec![],
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
        if self.failures.is_empty() {
            if self.unmined_terminals.is_empty() {
                Validity::Valid
            } else {
                Validity::UnminedTerminals
            }
        } else if self.absent_pub_witnesses.is_empty() {
            Validity::Invalid
        } else {
            Validity::UnresolvedTransactions
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
    /// the contract network doesn't match (validator runs in testnet={0}
    /// configuration).
    NetworkMismatch(bool),

    /// schema {actual} provided for the consignment validation doesn't match
    /// schema {expected} used by the contract. This means that the consignment
    /// is invalid.
    SchemaMismatch {
        /// Expected schema id required by the contract genesis.
        expected: SchemaId,
        /// Actual schema id provided by the consignment.
        actual: SchemaId,
    },
    /// schema uses reserved type for the blank state transition.
    SchemaBlankTransitionRedefined,

    /// schema global state #{0} uses semantic data type absent in type library
    /// ({1}).
    SchemaGlobalSemIdUnknown(schema::GlobalStateType, SemId),
    /// schema owned state #{0} uses semantic data type absent in type library
    /// ({1}).
    SchemaOwnedSemIdUnknown(schema::AssignmentType, SemId),
    /// schema metadata in {0} uses semantic data type absent in type library
    /// ({1}).
    SchemaOpMetaSemIdUnknown(OpFullType, SemId),

    /// schema for {0} has zero inputs.
    SchemaOpEmptyInputs(OpFullType),
    /// schema for {0} references undeclared global state type {1}.
    SchemaOpGlobalTypeUnknown(OpFullType, schema::GlobalStateType),
    /// schema for {0} references undeclared owned state type {1}.
    SchemaOpAssignmentTypeUnknown(OpFullType, schema::AssignmentType),
    /// schema for {0} references undeclared valency type {1}.
    SchemaOpValencyTypeUnknown(OpFullType, schema::ValencyType),

    /// operation {0} uses invalid state extension type {1}.
    SchemaUnknownExtensionType(OpId, schema::ExtensionType),
    /// operation {0} uses invalid state transition type {1}.
    SchemaUnknownTransitionType(OpId, schema::TransitionType),
    /// operation {0} uses invalid global state type {1}.
    SchemaUnknownGlobalStateType(OpId, schema::GlobalStateType),
    /// operation {0} uses invalid assignment type {1}.
    SchemaUnknownAssignmentType(OpId, schema::AssignmentType),
    /// operation {0} uses invalid valency type {1}.
    SchemaUnknownValencyType(OpId, schema::ValencyType),

    /// invalid number of global state entries of type {1} in operation {0} -
    /// {2}
    SchemaGlobalStateOccurrences(OpId, schema::GlobalStateType, OccurrencesMismatch),
    /// number of global state entries of type {1} in operation {0} exceeds
    /// schema-defined maximum for that global state type ({2} vs {3}).
    SchemaGlobalStateLimit(OpId, schema::GlobalStateType, u16, u16),
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
    /// transition bundle {0} referenced in consignment terminals is absent from
    /// the consignment.
    TerminalBundleAbsent(BundleId),
    /// transition bundle {0} is absent from the consignment.
    BundleAbsent(BundleId),
    /// operation {0} is under a different contract {1}.
    ContractMismatch(OpId, ContractId),

    // Errors checking bundle commitments
    /// transition bundle {0} references state transition {1} which is not
    /// included into the bundle input map.
    BundleExtraTransition(BundleId, OpId),
    /// transition bundle {0} references non-existing input in witness {2} for
    /// the state transition {1}.
    BundleInvalidInput(BundleId, OpId, WitnessId),
    /// transition bundle {0} doesn't commit to the input {1} in the witness {2}
    /// which is an input of the state transition {3}.
    BundleInvalidCommitment(BundleId, Vin, WitnessId, OpId),

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
    /// anchors used inside bundle {0} reference different public witness ids.
    AnchorSetInvalid(BundleId),
    /// seal defined in the history as a part of operation output {0} is
    /// confidential and can't be validated.
    ConfidentialSeal(Opout),
    /// witness {0} is not known to the transaction resolver.
    SealNoWitnessTx(WitnessId),
    /// witness layer 1 {anchor} doesn't match seal definition {seal}.
    SealWitnessLayer1Mismatch { seal: Layer1, anchor: Layer1 },
    /// seal {1:?} is defined on {0} which is not in the set of layers allowed
    /// by the contract genesis.
    SealLayerMismatch(Layer1, XGraphSeal),
    /// transition bundle {0} doesn't close seal with the witness {1}. Details:
    /// {2}
    SealsInvalid(BundleId, WitnessId, String),
    /// single-use seals for the operation {0} were not validated, which
    /// probably indicates unanchored state transition.
    SealsUnvalidated(OpId),
    /// transition bundle {0} is not properly anchored to the witness {1}.
    /// Details: {2}
    MpcInvalid(BundleId, WitnessId, InvalidProof),

    // State extensions errors
    /// valency {valency} redeemed by state extension {opid} references
    /// non-existing operation {prev_id}
    ValencyNoParent {
        opid: OpId,
        prev_id: OpId,
        valency: schema::ValencyType,
    },
    /// state extension {opid} references valency {valency} absent in the parent
    /// {prev_id}.
    NoPrevValency {
        opid: OpId,
        prev_id: OpId,
        valency: schema::ValencyType,
    },

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
    MediaTypeMismatch {
        opid: OpId,
        state_type: schema::AssignmentType,
        expected: schema::MediaType,
        found: schema::MediaType,
    },
    /// state in {opid}/{state_type} is of {found} type, while schema requires
    /// it to be {expected}.
    FungibleTypeMismatch {
        opid: OpId,
        state_type: schema::AssignmentType,
        expected: schema::FungibleType,
        found: schema::FungibleType,
    },
    /// invalid bulletproofs in {0}:{1}: {2}
    BulletproofsInvalid(OpId, schema::AssignmentType, String),
    /// evaluation of AluVM script for operation {0} has failed with the code
    /// {1:?}
    ScriptFailure(OpId, Option<u8>),

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
    // TODO: Replace debug with display
    /// terminal seal {1:?} referencing operation {0} is not present in
    /// operation assignments.
    TerminalSealAbsent(OpId, XChain<SecretSeal>),
    /// terminal witness transaction {0} is not yet mined.
    TerminalWitnessNotMined(Txid),
    /// transition bundle {0} doesn't close all the seals defined for its
    /// inputs.
    UnclosedSeals(BundleId),

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
    /// operation {0} contains state in assignment {1} which is confidential and
    /// thus was not validated.
    UncheckableConfidentialState(OpId, schema::AssignmentType),

    /// Custom info by external services on top of RGB Core.
    #[display(inner)]
    Custom(String),
}

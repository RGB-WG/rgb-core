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

use core::iter::FromIterator;
use core::ops::AddAssign;

use bp::dbc::anchor;
use bp::{seals, Txid};
use strict_types::SemId;

use crate::contract::Opout;
use crate::schema::{self, SchemaId};
use crate::{
    AssignmentType, BundleId, OccurrencesMismatch, OpFullType, OpId, SecretSeal, StateType,
};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Display)]
#[display(Debug)]
#[repr(u8)]
pub enum Validity {
    Valid,
    ValidExceptEndpoints,
    UnresolvedTransactions,
    Invalid,
}

#[derive(Clone, Debug, Display, Default)]
//#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
// TODO #42: Display via YAML
#[display(Debug)]
pub struct Status {
    pub unresolved_txids: Vec<Txid>,
    pub unmined_endpoint_txids: Vec<Txid>,
    pub failures: Vec<Failure>,
    pub warnings: Vec<Warning>,
    pub info: Vec<Info>,
}

impl AddAssign for Status {
    fn add_assign(&mut self, rhs: Self) {
        self.unresolved_txids.extend(rhs.unresolved_txids);
        self.unmined_endpoint_txids
            .extend(rhs.unmined_endpoint_txids);
        self.failures.extend(rhs.failures);
        self.warnings.extend(rhs.warnings);
        self.info.extend(rhs.info);
    }
}

impl Status {
    pub fn from_error(v: Failure) -> Self {
        Status {
            unresolved_txids: vec![],
            unmined_endpoint_txids: vec![],
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
            if self.unmined_endpoint_txids.is_empty() {
                Validity::Valid
            } else {
                Validity::ValidExceptEndpoints
            }
        } else if self.unresolved_txids.is_empty() {
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
    /// schema {actual} provided for the consignment validation doesn't match
    /// schema {expected} used by the contract. This means that the consignment
    /// is invalid.
    SchemaMismatch {
        /// Expected schema id required by the contracts genesis.
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

    /// invalid schema - no match with root schema requirements for global state
    /// type #{0}.
    SubschemaGlobalStateMismatch(schema::GlobalStateType),
    /// invalid schema - no match with root schema requirements for assignment
    /// type #{0}.
    SubschemaAssignmentTypeMismatch(schema::AssignmentType),
    /// invalid schema - no match with root schema requirements for valency
    /// type #{0}.
    SubschemaValencyTypeMismatch(schema::ValencyType),
    /// invalid schema - no match with root schema requirements for transition
    /// type #{0}.
    SubschemaTransitionTypeMismatch(schema::TransitionType),
    /// invalid schema - no match with root schema requirements for extension
    /// type #{0}.
    SubschemaExtensionTypeMismatch(schema::ExtensionType),

    /// invalid schema - no match with root schema requirements for metadata
    /// type (required {expected}, found {actual}).
    SubschemaOpMetaMismatch {
        op_type: OpFullType,
        expected: SemId,
        actual: SemId,
    },
    /// invalid schema - no match with root schema requirements for global state
    /// type #{1} used in {0}.
    SubschemaOpGlobalStateMismatch(OpFullType, schema::GlobalStateType),
    /// invalid schema - no match with root schema requirements for input
    /// type #{1} used in {0}.
    SubschemaOpInputMismatch(OpFullType, schema::AssignmentType),
    /// invalid schema - no match with root schema requirements for redeem
    /// type #{1} used in {0}.
    SubschemaOpRedeemMismatch(OpFullType, schema::ValencyType),
    /// invalid schema - no match with root schema requirements for assignment
    /// type #{1} used in {0}.
    SubschemaOpAssignmentsMismatch(OpFullType, schema::AssignmentType),
    /// invalid schema - no match with root schema requirements for valency
    /// type #{1} used in {0}.
    SubschemaOpValencyMismatch(OpFullType, schema::ValencyType),

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
    /// operation {0} is absent from the consignment.
    OperationAbsent(OpId),
    /// state transition {0} is absent from the consignment.
    TransitionAbsent(OpId),
    /// bundle with id {0} is invalid.
    BundleInvalid(BundleId),

    // Errors checking seal closing
    /// transition {0} is not anchored.
    NotAnchored(OpId),
    /// anchor for transition {0} doesn't commit to the actual transition data.
    NotInAnchor(OpId, Txid),
    /// transition {opid} references state type {state_type} absent in the
    /// outputs of previous state transition {prev_id}.
    NoPrevState {
        opid: OpId,
        prev_id: OpId,
        state_type: schema::AssignmentType,
    },
    /// transition {0} references non-existing previous output {1}.
    NoPrevOut(OpId, Opout),
    /// seal {0} present in the history is confidential and can't be validated.
    ConfidentialSeal(Opout),
    /// transition {0} is not a part of multi-protocol commitment for witness
    /// {1}; anchor is invalid.
    MpcInvalid(OpId, Txid),
    /// witness transaction {0} is not known to the transaction resolver.
    SealNoWitnessTx(Txid),
    /// transition {0} doesn't close seal with the witness transaction {1}.
    /// Details: {2}
    SealInvalid(OpId, Txid, seals::txout::VerifyError),
    /// transition {0} is not properly anchored to the witness transaction {1}.
    /// Details: {2}
    AnchorInvalid(OpId, Txid, anchor::VerifyError),

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

    // Data check errors
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
    BulletproofsInvalid(OpId, u16, String),
    /// operation {0} is invalid: {1}
    ScriptFailure(OpId, String),

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
    /// duplicated terminal seal {1} in operation {0}.
    TerminalDuplication(OpId, SecretSeal),
    /// terminal seal {1} referencing operation {0} is not present in operation
    /// assignments.
    TerminalSealAbsent(OpId, SecretSeal),
    /// operation {0} present in the consignment is excessive and not a part of
    /// the validated contract history.
    ExcessiveOperation(OpId),
    /// terminal witness transaction {0} is not yet mined.
    TerminalWitnessNotMined(Txid),

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
    UncheckableConfidentialState(OpId, AssignmentType),

    /// Custom info by external services on top of RGB Core.
    #[display(inner)]
    Custom(String),
}

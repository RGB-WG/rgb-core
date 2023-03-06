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

mod apis;
mod vm;
mod subschema;
mod model;
mod state;
mod verify;

use core::iter::FromIterator;
use core::ops::AddAssign;

pub use apis::{ConsistencyError, ContainerApi, HistoryApi};
use bp::Txid;
pub(crate) use model::OpInfo;
pub use verify::{ResolveTx, TxResolverError, Validator};

use crate::schema::{self, OpType, SchemaId};
use crate::state::Opout;
use crate::{data, seal, BundleId, OccurrencesMismatch, OpId};

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

    pub fn with_failure(failure: Failure) -> Self {
        Self {
            failures: vec![failure],
            ..Self::default()
        }
    }

    pub fn add_failure(&mut self, failure: Failure) -> &Self {
        self.failures.push(failure);
        self
    }

    pub fn add_warning(&mut self, warning: Warning) -> &Self {
        self.warnings.push(warning);
        self
    }

    pub fn add_info(&mut self, info: Info) -> &Self {
        self.info.push(info);
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
//#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
// TODO #44: (v0.3) convert to detailed error description using doc_comments
#[display(Debug)]
pub enum Failure {
    SchemaUnknown(SchemaId),
    /// schema is a subschema, so root schema {0} must be provided for the
    /// validation
    SchemaRootRequired(SchemaId),
    /// Root schema for this schema has another root, which is prohibited
    SchemaRootHierarchy,
    SchemaRootNoFieldTypeMatch(schema::GlobalStateType),
    SchemaRootNoOwnedRightTypeMatch(schema::OwnedStateType),
    SchemaRootNoPublicRightTypeMatch(schema::ValencyType),
    SchemaRootNoTransitionTypeMatch(schema::TransitionType),
    SchemaRootNoExtensionTypeMatch(schema::ExtensionType),

    SchemaRootNoMetadataMatch(OpType, schema::GlobalStateType),
    SchemaRootNoParentOwnedRightsMatch(OpType, schema::OwnedStateType),
    SchemaRootNoParentPublicRightsMatch(OpType, schema::ValencyType),
    SchemaRootNoOwnedRightsMatch(OpType, schema::OwnedStateType),
    SchemaRootNoPublicRightsMatch(OpType, schema::ValencyType),

    SchemaUnknownExtensionType(OpId, schema::ExtensionType),
    SchemaUnknownTransitionType(OpId, schema::TransitionType),
    SchemaUnknownFieldType(OpId, schema::GlobalStateType),
    SchemaUnknownOwnedRightType(OpId, schema::OwnedStateType),
    SchemaUnknownPublicRightType(OpId, schema::ValencyType),

    SchemaDeniedScriptExtension(OpId),

    SchemaMetaValueTooSmall(schema::GlobalStateType),
    SchemaMetaValueTooLarge(schema::GlobalStateType),
    SchemaStateValueTooSmall(schema::OwnedStateType),
    SchemaStateValueTooLarge(schema::OwnedStateType),

    SchemaWrongEnumValue {
        field_or_state_type: u16,
        unexpected: u8,
    },
    SchemaWrongDataLength {
        field_or_state_type: u16,
        max_expected: u16,
        found: usize,
    },
    SchemaMismatchedDataType(u16),
    SchemaMismatchedStateType(schema::OwnedStateType),

    SchemaMetaOccurrencesError(OpId, schema::GlobalStateType, OccurrencesMismatch),
    SchemaParentOwnedRightOccurrencesError(OpId, schema::OwnedStateType, OccurrencesMismatch),
    SchemaOwnedRightOccurrencesError(OpId, schema::OwnedStateType, OccurrencesMismatch),

    SchemaScriptOverrideDenied,
    SchemaScriptVmChangeDenied,

    SchemaTypeSystem(/* TODO: use error from strict types */),

    BundleInvalid(BundleId),

    OperationAbsent(OpId),

    TransitionAbsent(OpId),
    TransitionNotAnchored(OpId),
    TransitionNotInAnchor(OpId, Txid),

    // Errors checking seal closing
    /// transition {op} references state type {ty} absent in the outputs of
    /// previous state transition {prev_id}.
    NoPrevState {
        opid: OpId,
        prev_id: OpId,
        state_type: schema::OwnedStateType,
    },
    /// transition {0} references non-existing previous output {1}
    NoPrevOut(OpId, Opout),
    /// seal {0} present in the history is confidential and can't be validated.
    ConfidentialSeal(Opout),
    /// witness transaction of {opid} doesn't closes referenced seal {outpoint}.
    UnclosedSeal {
        opid: OpId,
        prev_out: Opout,
        outpoint: bp::Outpoint,
    },
    /// genesis or state extension output {0} defines seal which doesn't
    /// specifies transaction id (so-called witness seal, which can be present
    /// only in state transitions).
    UnexpectedWitnessSeal(Opout),

    ExtensionAbsent(OpId),
    ExtensionParentWrongValenciesType {
        opid: OpId,
        ancestor_id: OpId,
        valencies_type: schema::ValencyType,
    },

    WitnessTransactionMissed(Txid),
    WitnessNoCommitment(OpId, Txid),

    EndpointTransitionNotFound(OpId),

    InvalidStateDataType(OpId, u16, /* TODO: Use strict type */ data::Revealed),
    InvalidStateDataValue(OpId, u16, /* TODO: Use strict type */ Vec<u8>),

    /// invalid bulletproofs in {0}:{1}: {3}
    InvalidBulletproofs(OpId, u16, String),

    /// operation {0} is invalid: {1}
    ScriptFailure(OpId, String),
}

#[derive(Clone, PartialEq, Eq, Debug, Display, From)]
//#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
// TODO #44: (v0.3) convert to detailed descriptions using doc_comments
#[display(Debug)]
pub enum Warning {
    EndpointDuplication(OpId, seal::Confidential),
    EndpointTransitionSealNotFound(OpId, seal::Confidential),
    ExcessiveNode(OpId),
    EndpointTransactionMissed(Txid),
}

#[derive(Clone, PartialEq, Eq, Debug, Display, From)]
//#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
// TODO #44: (v0.3) convert to detailed descriptions using doc_comments
#[display(Debug)]
pub enum Info {
    UncheckableConfidentialStateData(OpId, u16),
}

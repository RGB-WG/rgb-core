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

mod graph;
mod vm;
mod subschema;
mod state;

use core::iter::FromIterator;
use core::ops::AddAssign;

use bp::Txid;

use crate::schema::{self, NodeType, SchemaId};
use crate::{data, BundleId, NodeId, OccurrencesMismatch, SealEndpoint};

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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
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
        } else {
            if self.unresolved_txids.is_empty() {
                Validity::Invalid
            } else {
                Validity::UnresolvedTransactions
            }
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, From)]
//#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
// TODO #44: (v0.3) convert to detailed error description using doc_comments
#[display(Debug)]
pub enum Failure {
    SchemaUnknown(SchemaId),
    /// schema is a subschema, so root schema {0} must be provided for the
    /// validation
    SchemaRootRequired(SchemaId),
    /// Root schema for this schema has another root, which is prohibited
    SchemaRootHierarchy(SchemaId),
    SchemaRootNoFieldTypeMatch(schema::FieldType),
    SchemaRootNoOwnedRightTypeMatch(schema::OwnedRightType),
    SchemaRootNoPublicRightTypeMatch(schema::PublicRightType),
    SchemaRootNoTransitionTypeMatch(schema::TransitionType),
    SchemaRootNoExtensionTypeMatch(schema::ExtensionType),

    SchemaRootNoMetadataMatch(NodeType, schema::FieldType),
    SchemaRootNoParentOwnedRightsMatch(NodeType, schema::OwnedRightType),
    SchemaRootNoParentPublicRightsMatch(NodeType, schema::PublicRightType),
    SchemaRootNoOwnedRightsMatch(NodeType, schema::OwnedRightType),
    SchemaRootNoPublicRightsMatch(NodeType, schema::PublicRightType),

    SchemaUnknownExtensionType(NodeId, schema::ExtensionType),
    SchemaUnknownTransitionType(NodeId, schema::TransitionType),
    SchemaUnknownFieldType(NodeId, schema::FieldType),
    SchemaUnknownOwnedRightType(NodeId, schema::OwnedRightType),
    SchemaUnknownPublicRightType(NodeId, schema::PublicRightType),

    SchemaDeniedScriptExtension(NodeId),

    SchemaMetaValueTooSmall(schema::FieldType),
    SchemaMetaValueTooLarge(schema::FieldType),
    SchemaStateValueTooSmall(schema::OwnedRightType),
    SchemaStateValueTooLarge(schema::OwnedRightType),

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
    SchemaMismatchedStateType(schema::OwnedRightType),

    SchemaMetaOccurrencesError(NodeId, schema::FieldType, OccurrencesMismatch),
    SchemaParentOwnedRightOccurrencesError(NodeId, schema::OwnedRightType, OccurrencesMismatch),
    SchemaOwnedRightOccurrencesError(NodeId, schema::OwnedRightType, OccurrencesMismatch),

    SchemaScriptOverrideDenied,
    SchemaScriptVmChangeDenied,

    SchemaTypeSystem(/* TODO: use error from strict types */),

    BundleInvalid(BundleId),

    TransitionAbsent(NodeId),
    TransitionNotAnchored(NodeId),
    TransitionNotInAnchor(NodeId, Txid),
    TransitionParentWrongSealType {
        node_id: NodeId,
        ancestor_id: NodeId,
        assignment_type: schema::OwnedRightType,
    },
    TransitionParentWrongSeal {
        node_id: NodeId,
        ancestor_id: NodeId,
        assignment_type: schema::OwnedRightType,
        seal_index: u16,
    },
    TransitionParentConfidentialSeal {
        node_id: NodeId,
        ancestor_id: NodeId,
        assignment_type: schema::OwnedRightType,
        seal_index: u16,
    },
    TransitionParentIsNotWitnessInput {
        node_id: NodeId,
        ancestor_id: NodeId,
        assignment_type: schema::OwnedRightType,
        seal_index: u16,
        outpoint: bp::Outpoint,
    },

    ExtensionAbsent(NodeId),
    ExtensionParentWrongValenciesType {
        node_id: NodeId,
        ancestor_id: NodeId,
        valencies_type: schema::PublicRightType,
    },

    WitnessTransactionMissed(Txid),
    WitnessNoCommitment(NodeId, Txid),

    EndpointTransitionNotFound(NodeId),

    InvalidStateDataType(NodeId, u16, /* TODO: Use strict type */ data::Revealed),
    InvalidStateDataValue(NodeId, u16, /* TODO: Use strict type */ Vec<u8>),

    /// invalid bulletproofs in {0}:{1}: {3}
    InvalidBulletproofs(NodeId, u16, String),

    ScriptFailure(NodeId),
}

#[derive(Clone, PartialEq, Eq, Debug, Display, From)]
//#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
// TODO #44: (v0.3) convert to detailed descriptions using doc_comments
#[display(Debug)]
pub enum Warning {
    EndpointDuplication(NodeId, SealEndpoint),
    EndpointTransitionSealNotFound(NodeId, SealEndpoint),
    ExcessiveNode(NodeId),
    EndpointTransactionMissed(Txid),
}

#[derive(Clone, PartialEq, Eq, Debug, Display, From)]
//#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
// TODO #44: (v0.3) convert to detailed descriptions using doc_comments
#[display(Debug)]
pub enum Info {
    UncheckableConfidentialStateData(NodeId, u16),
}

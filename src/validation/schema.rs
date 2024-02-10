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

use crate::validation::Status;
use crate::{validation, OpFullType, OpSchema, Schema, StateSchema, SubSchema, TransitionType};

impl SubSchema {
    pub fn verify(&self) -> validation::Status {
        let mut status = validation::Status::new();

        if let Some(ref root) = self.subset_of {
            status += self.verify_subschema(root);
        }

        // Validate internal schema consistency
        status += self.verify_consistency();

        status
    }

    fn verify_consistency(&self) -> validation::Status {
        let mut status = validation::Status::new();

        status += self.verify_operation(OpFullType::Genesis, &self.genesis);
        for (type_id, schema) in &self.transitions {
            status += self.verify_operation(OpFullType::StateTransition(*type_id), schema);
        }
        for (type_id, schema) in &self.extensions {
            status += self.verify_operation(OpFullType::StateExtension(*type_id), schema);
        }
        // Check that the schema doesn't contain reserved type ids
        if self.transitions.contains_key(&TransitionType::BLANK) {
            status.add_failure(validation::Failure::SchemaBlankTransitionRedefined);
        }

        for (type_id, schema) in &self.global_types {
            if !self.type_system.contains_key(&schema.sem_id) {
                status.add_failure(validation::Failure::SchemaGlobalSemIdUnknown(
                    *type_id,
                    schema.sem_id,
                ));
            }
        }

        for (type_id, schema) in &self.owned_types {
            if let StateSchema::Structured(sem_id) = schema {
                if !self.type_system.contains_key(sem_id) {
                    status.add_failure(validation::Failure::SchemaOwnedSemIdUnknown(
                        *type_id, *sem_id,
                    ));
                }
            }
        }

        status
    }

    fn verify_operation(&self, op_type: OpFullType, schema: &impl OpSchema) -> Status {
        let mut status = validation::Status::new();

        if !self.type_system.contains_key(&schema.metadata()) {
            status.add_failure(validation::Failure::SchemaOpMetaSemIdUnknown(
                op_type,
                schema.metadata(),
            ));
        }
        if matches!(schema.inputs(), Some(inputs) if inputs.is_empty()) {
            status.add_failure(validation::Failure::SchemaOpEmptyInputs(op_type));
        }
        if matches!(schema.redeems(), Some(inputs) if inputs.is_empty()) {
            status.add_failure(validation::Failure::SchemaOpEmptyInputs(op_type));
        }
        for type_id in schema.globals().keys() {
            if !self.global_types.contains_key(type_id) {
                status
                    .add_failure(validation::Failure::SchemaOpGlobalTypeUnknown(op_type, *type_id));
            }
        }
        for type_id in schema.assignments().keys() {
            if !self.owned_types.contains_key(type_id) {
                status.add_failure(validation::Failure::SchemaOpAssignmentTypeUnknown(
                    op_type, *type_id,
                ));
            }
        }
        for type_id in schema.valencies() {
            if !self.valency_types.contains(type_id) {
                status.add_failure(validation::Failure::SchemaOpValencyTypeUnknown(
                    op_type, *type_id,
                ));
            }
        }

        status
    }

    fn verify_subschema(&self, root: &Schema<()>) -> validation::Status {
        let mut status = validation::Status::new();

        if self.subset_of.as_ref() != Some(root) {
            panic!("SubSchema::schema_verify called with a root schema not matching subset_of");
        }

        for (global_type, data_format) in &self.global_types {
            match root.global_types.get(global_type) {
                None => status
                    .add_failure(validation::Failure::SubschemaGlobalStateMismatch(*global_type)),
                Some(root_data_format) if root_data_format != data_format => status
                    .add_failure(validation::Failure::SubschemaGlobalStateMismatch(*global_type)),
                _ => &status,
            };
        }

        for (assignments_type, state_schema) in &self.owned_types {
            match root.owned_types.get(assignments_type) {
                None => status.add_failure(validation::Failure::SubschemaAssignmentTypeMismatch(
                    *assignments_type,
                )),
                Some(root_state_schema) if root_state_schema != state_schema => status.add_failure(
                    validation::Failure::SubschemaAssignmentTypeMismatch(*assignments_type),
                ),
                _ => &status,
            };
        }

        for valencies_type in &self.valency_types {
            match root.valency_types.contains(valencies_type) {
                false => status.add_failure(validation::Failure::SubschemaValencyTypeMismatch(
                    *valencies_type,
                )),
                _ => &status,
            };
        }

        status += self
            .genesis
            .verify_subschema(OpFullType::Genesis, &root.genesis);

        for (type_id, transition_schema) in &self.transitions {
            if let Some(root_transition_schema) = root.transitions.get(type_id) {
                status += transition_schema.verify_subschema(
                    OpFullType::StateTransition(*type_id),
                    root_transition_schema,
                );
            } else {
                status.add_failure(validation::Failure::SubschemaTransitionTypeMismatch(*type_id));
            }
        }
        for (type_id, extension_schema) in &self.extensions {
            if let Some(root_extension_schema) = root.extensions.get(type_id) {
                status += extension_schema
                    .verify_subschema(OpFullType::StateExtension(*type_id), root_extension_schema);
            } else {
                status.add_failure(validation::Failure::SubschemaExtensionTypeMismatch(*type_id));
            }
        }

        status
    }
}

/// Trait used for internal schema validation against some root schema
pub(crate) trait SchemaVerify {
    type Root;
    fn verify_subschema(&self, op_type: OpFullType, root: &Self::Root) -> validation::Status;
}

impl<T> SchemaVerify for T
where T: OpSchema
{
    type Root = T;

    fn verify_subschema(&self, op_type: OpFullType, root: &Self) -> validation::Status {
        let mut status = validation::Status::new();

        if self.metadata() != root.metadata() {
            status.add_failure(validation::Failure::SubschemaOpMetaMismatch {
                op_type,
                expected: root.metadata(),
                actual: self.metadata(),
            });
        }

        for (type_id, occ) in self.globals() {
            match root.globals().get(type_id) {
                None => status.add_failure(validation::Failure::SubschemaOpGlobalStateMismatch(
                    op_type, *type_id,
                )),
                Some(root_occ) if occ != root_occ => status.add_failure(
                    validation::Failure::SubschemaOpGlobalStateMismatch(op_type, *type_id),
                ),
                _ => &status,
            };
        }

        if let Some(inputs) = self.inputs() {
            let root_inputs = root.inputs().expect("generic guarantees");
            for (type_id, occ) in inputs {
                match root_inputs.get(type_id) {
                    None => status.add_failure(validation::Failure::SubschemaOpInputMismatch(
                        op_type, *type_id,
                    )),
                    Some(root_occ) if occ != root_occ => status.add_failure(
                        validation::Failure::SubschemaOpInputMismatch(op_type, *type_id),
                    ),
                    _ => &status,
                };
            }
        }

        for (type_id, occ) in self.assignments() {
            match root.assignments().get(type_id) {
                None => status.add_failure(validation::Failure::SubschemaOpAssignmentsMismatch(
                    op_type, *type_id,
                )),
                Some(root_occ) if occ != root_occ => status.add_failure(
                    validation::Failure::SubschemaOpAssignmentsMismatch(op_type, *type_id),
                ),
                _ => &status,
            };
        }

        if let Some(redeems) = self.redeems() {
            let root_redeems = root.redeems().expect("generic guarantees");
            for type_id in redeems {
                if !root_redeems.contains(type_id) {
                    status.add_failure(validation::Failure::SubschemaOpRedeemMismatch(
                        op_type, *type_id,
                    ));
                }
            }
        }

        for type_id in self.valencies() {
            if !root.valencies().contains(type_id) {
                status.add_failure(validation::Failure::SubschemaOpValencyMismatch(
                    op_type, *type_id,
                ));
            }
        }

        status
    }
}

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

use strict_types::TypeSystem;

use crate::{validation, OpFullType, OpSchema, OwnedStateSchema, Schema, TransitionType};

impl Schema {
    pub fn verify(&self, types: &TypeSystem) -> validation::Status {
        let mut status = validation::Status::new();

        status += self.verify_operation(OpFullType::Genesis, &self.genesis, types);
        for (type_id, schema) in &self.transitions {
            status += self.verify_operation(OpFullType::StateTransition(*type_id), schema, types);
        }
        for (type_id, schema) in &self.extensions {
            status += self.verify_operation(OpFullType::StateExtension(*type_id), schema, types);
        }
        // Check that the schema doesn't contain reserved type ids
        if self.transitions.contains_key(&TransitionType::BLANK) {
            status.add_failure(validation::Failure::SchemaBlankTransitionRedefined);
        }

        for (type_id, schema) in &self.global_types {
            if !types.contains_key(&schema.sem_id) {
                status.add_failure(validation::Failure::SchemaGlobalSemIdUnknown(
                    *type_id,
                    schema.sem_id,
                ));
            }
        }

        for (type_id, schema) in &self.owned_types {
            if let OwnedStateSchema::Structured(sem_id) = schema {
                if !types.contains_key(sem_id) {
                    status.add_failure(validation::Failure::SchemaOwnedSemIdUnknown(
                        *type_id, *sem_id,
                    ));
                }
            }
        }

        status
    }

    fn verify_operation(
        &self,
        op_type: OpFullType,
        schema: &impl OpSchema,
        types: &TypeSystem,
    ) -> validation::Status {
        let mut status = validation::Status::new();

        if !types.contains_key(&schema.metadata()) {
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
}

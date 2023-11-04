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

use std::collections::{BTreeMap, BTreeSet};

use amplify::confinement::{Confined, SmallBlob};
use amplify::Wrapper;
use strict_types::SemId;

use crate::schema::{AssignmentsSchema, GlobalSchema, ValencySchema};
use crate::validation::{ConsignmentApi, VirtualMachine};
use crate::{
    validation, AssetTag, AssignmentType, Assignments, AssignmentsRef, ContractId, ExposedSeal,
    GlobalState, GlobalStateSchema, GlobalValues, GraphSeal, Inputs, OpFullType, OpId, OpRef,
    Operation, Opout, Redeemed, Schema, SchemaRoot, TransitionType, TypedAssigns, Valencies,
};

impl<Root: SchemaRoot> Schema<Root> {
    pub fn validate<C: ConsignmentApi>(
        &self,
        consignment: &C,
        op: OpRef,
        vm: &dyn VirtualMachine,
    ) -> validation::Status {
        let id = op.id();

        let empty_assign_schema = AssignmentsSchema::default();
        let empty_valency_schema = ValencySchema::default();
        let blank_transition = self.blank_transition();
        let (
            metadata_schema,
            global_schema,
            owned_schema,
            redeem_schema,
            assign_schema,
            valency_schema,
        ) = match (op.transition_type(), op.extension_type()) {
            (None, None) => {
                // Right now we do not have actions to implement; but later
                // we may have embedded procedures which must be verified
                // here
                /*
                if let Some(procedure) = self.genesis.abi.get(&GenesisAction::NoOp) {

                }
                 */

                (
                    &self.genesis.metadata,
                    &self.genesis.globals,
                    &empty_assign_schema,
                    &empty_valency_schema,
                    &self.genesis.assignments,
                    &self.genesis.valencies,
                )
            }
            (Some(transition_type), None) => {
                // Right now we do not have actions to implement; but later
                // we may have embedded procedures which must be verified
                // here
                /*
                if let Some(procedure) = transition_type.abi.get(&TransitionAction::NoOp) {

                }
                 */

                let transition_schema = match self.transitions.get(&transition_type) {
                    None if transition_type == TransitionType::BLANK => &blank_transition,
                    None => {
                        return validation::Status::with_failure(
                            validation::Failure::SchemaUnknownTransitionType(id, transition_type),
                        );
                    }
                    Some(transition_schema) => transition_schema,
                };

                (
                    &transition_schema.metadata,
                    &transition_schema.globals,
                    &transition_schema.inputs,
                    &empty_valency_schema,
                    &transition_schema.assignments,
                    &transition_schema.valencies,
                )
            }
            (None, Some(extension_type)) => {
                // Right now we do not have actions to implement; but later
                // we may have embedded procedures which must be verified
                // here
                /*
                if let Some(procedure) = extension_type.abi.get(&ExtensionAction::NoOp) {

                }
                 */

                let extension_schema = match self.extensions.get(&extension_type) {
                    None => {
                        return validation::Status::with_failure(
                            validation::Failure::SchemaUnknownExtensionType(id, extension_type),
                        );
                    }
                    Some(extension_schema) => extension_schema,
                };

                (
                    &extension_schema.metadata,
                    &extension_schema.globals,
                    &empty_assign_schema,
                    &extension_schema.redeems,
                    &extension_schema.assignments,
                    &extension_schema.redeems,
                )
            }
            _ => unreachable!("Node can't be extension and state transition at the same time"),
        };

        let mut status = validation::Status::new();

        // Validate type system
        status += self.validate_type_system();
        status += self.validate_metadata(id, *metadata_schema, op.metadata());
        status += self.validate_global_state(id, op.globals(), global_schema);
        let prev_state = if let OpRef::Transition(transition) = op {
            let prev_state = extract_prev_state(consignment, id, &transition.inputs, &mut status);
            status += self.validate_prev_state(id, &prev_state, owned_schema);
            prev_state
        } else {
            Assignments::default()
        };
        let redeemed = if let OpRef::Extension(extension) = op {
            let redeemed =
                extract_redeemed_valencies(consignment, &extension.redeemed, &mut status);
            status += self.validate_redeemed(id, &redeemed, redeem_schema);
            redeemed
        } else {
            Valencies::default()
        };
        status += match op.assignments() {
            AssignmentsRef::Genesis(assignments) => {
                self.validate_owned_state(id, assignments, assign_schema)
            }
            AssignmentsRef::Graph(assignments) => {
                self.validate_owned_state(id, assignments, assign_schema)
            }
        };

        status += self.validate_valencies(id, op.valencies(), valency_schema);

        let op_info = OpInfo::with(
            consignment.genesis().contract_id(),
            id,
            self.subset_of.is_some(),
            &op,
            &prev_state,
            &redeemed,
            consignment.asset_tags(),
        );

        // We need to run scripts as the very last step, since before that
        // we need to make sure that the operation data match the schema, so
        // scripts are not required to validate the structure of the state
        status += self.validate_state_evolution(op_info, vm);
        status
    }

    fn validate_type_system(&self) -> validation::Status {
        validation::Status::new()
        // TODO: Validate type system
        // Currently, validation is performed at the level of state values, i.e.
        // if the system is inconsistent (references semantic ids not
        // present in it) this will be detected during state validation.
        // We should not prohibit schema with inconsistent type system, instead
        // we need just to issue warnings here if some of semantic ids are
        // missed - and add information messages if some excessive semantic ids
        // are present.
    }

    fn validate_metadata(
        &self,
        opid: OpId,
        sem_id: SemId,
        metadata: &SmallBlob,
    ) -> validation::Status {
        let mut status = validation::Status::new();

        if self
            .type_system
            .strict_deserialize_type(sem_id, metadata.as_ref())
            .is_err()
        {
            status.add_failure(validation::Failure::SchemaInvalidMetadata(opid, sem_id));
        };

        status
    }

    fn validate_global_state(
        &self,
        opid: OpId,
        global: &GlobalState,
        global_schema: &GlobalSchema,
    ) -> validation::Status {
        let mut status = validation::Status::new();

        global
            .keys()
            .collect::<BTreeSet<_>>()
            .difference(&global_schema.keys().collect())
            .for_each(|field_id| {
                status.add_failure(validation::Failure::SchemaUnknownGlobalStateType(
                    opid, **field_id,
                ));
            });

        for (type_id, occ) in global_schema {
            let set = global
                .get(type_id)
                .cloned()
                .map(GlobalValues::into_inner)
                .map(Confined::unbox)
                .unwrap_or_default();

            let GlobalStateSchema { sem_id, max_items } = self.global_types.get(type_id).expect(
                "if the field were absent, the schema would not be able to pass the internal \
                 validation and we would not reach this point",
            );

            // Checking number of field occurrences
            let count = set.len() as u16;
            if let Err(err) = occ.check(count) {
                status.add_failure(validation::Failure::SchemaGlobalStateOccurrences(
                    opid, *type_id, err,
                ));
            }
            if count > *max_items {
                status.add_failure(validation::Failure::SchemaGlobalStateLimit(
                    opid, *type_id, count, *max_items,
                ));
            }

            // Validating data types
            for data in set {
                if self
                    .type_system
                    .strict_deserialize_type(*sem_id, data.as_ref())
                    .is_err()
                {
                    status.add_failure(validation::Failure::SchemaInvalidGlobalValue(
                        opid, *type_id, *sem_id,
                    ));
                };
            }
        }

        status
    }

    fn validate_prev_state<Seal: ExposedSeal>(
        &self,
        id: OpId,
        owned_state: &Assignments<Seal>,
        assign_schema: &AssignmentsSchema,
    ) -> validation::Status {
        let mut status = validation::Status::new();

        owned_state
            .keys()
            .collect::<BTreeSet<_>>()
            .difference(&assign_schema.keys().collect())
            .for_each(|owned_type_id| {
                status.add_failure(validation::Failure::SchemaUnknownAssignmentType(
                    id,
                    **owned_type_id,
                ));
            });

        for (owned_type_id, occ) in assign_schema {
            let len = owned_state
                .get(owned_type_id)
                .map(TypedAssigns::len_u16)
                .unwrap_or(0);

            // Checking number of ancestor's assignment occurrences
            if let Err(err) = occ.check(len) {
                status.add_failure(validation::Failure::SchemaInputOccurrences(
                    id,
                    *owned_type_id,
                    err,
                ));
            }
        }

        status
    }

    fn validate_redeemed(
        &self,
        id: OpId,
        valencies: &Valencies,
        valency_schema: &ValencySchema,
    ) -> validation::Status {
        let mut status = validation::Status::new();

        valencies
            .difference(valency_schema)
            .for_each(|public_type_id| {
                status.add_failure(validation::Failure::SchemaUnknownValencyType(
                    id,
                    *public_type_id,
                ));
            });

        status
    }

    fn validate_owned_state<Seal: ExposedSeal>(
        &self,
        id: OpId,
        owned_state: &Assignments<Seal>,
        assign_schema: &AssignmentsSchema,
    ) -> validation::Status {
        let mut status = validation::Status::new();

        owned_state
            .keys()
            .collect::<BTreeSet<_>>()
            .difference(&assign_schema.keys().collect())
            .for_each(|assignment_type_id| {
                status.add_failure(validation::Failure::SchemaUnknownAssignmentType(
                    id,
                    **assignment_type_id,
                ));
            });

        for (state_id, occ) in assign_schema {
            let len = owned_state
                .get(state_id)
                .map(TypedAssigns::len_u16)
                .unwrap_or(0);

            // Checking number of assignment occurrences
            if let Err(err) = occ.check(len) {
                status.add_failure(validation::Failure::SchemaAssignmentOccurrences(
                    id, *state_id, err,
                ));
            }

            let assignment = &self.owned_types.get(state_id).expect(
                "If the assignment were absent, the schema would not be able to pass the internal \
                 validation and we would not reach this point",
            );

            match owned_state.get(state_id) {
                None => {}
                Some(TypedAssigns::Declarative(set)) => set.iter().for_each(|data| {
                    status += assignment.validate(&self.type_system, &id, *state_id, data)
                }),
                Some(TypedAssigns::Fungible(set)) => set.iter().for_each(|data| {
                    status += assignment.validate(&self.type_system, &id, *state_id, data)
                }),
                Some(TypedAssigns::Structured(set)) => set.iter().for_each(|data| {
                    status += assignment.validate(&self.type_system, &id, *state_id, data)
                }),
                Some(TypedAssigns::Attachment(set)) => set.iter().for_each(|data| {
                    status += assignment.validate(&self.type_system, &id, *state_id, data)
                }),
            };
        }

        status
    }

    fn validate_valencies(
        &self,
        id: OpId,
        valencies: &Valencies,
        valency_schema: &ValencySchema,
    ) -> validation::Status {
        let mut status = validation::Status::new();

        valencies
            .difference(valency_schema)
            .for_each(|public_type_id| {
                status.add_failure(validation::Failure::SchemaUnknownValencyType(
                    id,
                    *public_type_id,
                ));
            });

        status
    }

    fn validate_state_evolution(
        &self,
        op_info: OpInfo,
        vm: &dyn VirtualMachine,
    ) -> validation::Status {
        let mut status = validation::Status::new();

        // We do not validate public rights, since they do not have an
        // associated state and there is nothing to validate beyond schema

        if let Err(err) = vm.validate(op_info) {
            status.add_failure(err);
        }

        status
    }
}

pub struct OpInfo<'op> {
    pub subschema: bool,
    pub contract_id: ContractId,
    pub id: OpId,
    pub ty: OpFullType,
    pub asset_tags: &'op BTreeMap<AssignmentType, AssetTag>,
    pub metadata: &'op SmallBlob,
    pub prev_state: &'op Assignments<GraphSeal>,
    pub owned_state: AssignmentsRef<'op>,
    pub redeemed: &'op Valencies,
    pub valencies: &'op Valencies,
    pub global: &'op GlobalState,
}

impl<'op> OpInfo<'op> {
    pub fn with(
        contract_id: ContractId,
        id: OpId,
        subschema: bool,
        op: &'op OpRef<'op>,
        prev_state: &'op Assignments<GraphSeal>,
        redeemed: &'op Valencies,
        asset_tags: &'op BTreeMap<AssignmentType, AssetTag>,
    ) -> Self {
        OpInfo {
            id,
            subschema,
            contract_id,
            ty: op.full_type(),
            asset_tags,
            metadata: op.metadata(),
            prev_state,
            owned_state: op.assignments(),
            redeemed,
            valencies: op.valencies(),
            global: op.globals(),
        }
    }
}

fn extract_prev_state<C: ConsignmentApi>(
    consignment: &C,
    opid: OpId,
    inputs: &Inputs,
    status: &mut validation::Status,
) -> Assignments<GraphSeal> {
    let mut assignments = bmap! {};
    for input in inputs {
        let Opout { op, ty, no } = input.prev_out;

        let prev_op = match consignment.operation(op) {
            None => {
                status.add_failure(validation::Failure::OperationAbsent(op));
                continue;
            }
            Some(op) => op,
        };

        let no = no as usize;
        match prev_op.assignments_by_type(ty) {
            Some(TypedAssigns::Declarative(prev_assignments)) => {
                if let Some(prev_assign) = prev_assignments.get(no) {
                    if let Some(typed_assigns) = assignments
                        .entry(ty)
                        .or_insert_with(|| TypedAssigns::Declarative(Default::default()))
                        .as_declarative_mut()
                    {
                        typed_assigns.push(prev_assign.clone()).expect("same size");
                    }
                } else {
                    status.add_failure(validation::Failure::NoPrevOut(opid, input.prev_out));
                }
            }
            Some(TypedAssigns::Fungible(prev_assignments)) => {
                if let Some(prev_assign) = prev_assignments.get(no) {
                    if let Some(typed_assigns) = assignments
                        .entry(ty)
                        .or_insert_with(|| TypedAssigns::Fungible(Default::default()))
                        .as_fungible_mut()
                    {
                        typed_assigns.push(prev_assign.clone()).expect("same size");
                    }
                } else {
                    status.add_failure(validation::Failure::NoPrevOut(opid, input.prev_out));
                }
            }
            Some(TypedAssigns::Structured(prev_assignments)) => {
                if let Some(prev_assign) = prev_assignments.get(no) {
                    if let Some(typed_assigns) = assignments
                        .entry(ty)
                        .or_insert_with(|| TypedAssigns::Structured(Default::default()))
                        .as_structured_mut()
                    {
                        typed_assigns.push(prev_assign.clone()).expect("same size");
                    }
                } else {
                    status.add_failure(validation::Failure::NoPrevOut(opid, input.prev_out));
                }
            }
            Some(TypedAssigns::Attachment(prev_assignments)) => {
                if let Some(prev_assign) = prev_assignments.get(no) {
                    if let Some(typed_assigns) = assignments
                        .entry(ty)
                        .or_insert_with(|| TypedAssigns::Attachment(Default::default()))
                        .as_attachment_mut()
                    {
                        typed_assigns.push(prev_assign.clone()).expect("same size");
                    }
                } else {
                    status.add_failure(validation::Failure::NoPrevOut(opid, input.prev_out));
                }
            }
            None => {
                // Presence of the required owned rights type in the
                // parent operation was already validated; we have nothing
                // to report here
            }
        }
    }
    Confined::try_from(assignments)
        .expect("collections is assembled from another collection with the same size requirements")
        .into()
}

fn extract_redeemed_valencies<C: ConsignmentApi>(
    consignment: &C,
    redeemed: &Redeemed,
    status: &mut validation::Status,
) -> Valencies {
    let mut public_rights = Valencies::default();
    for (valency, id) in redeemed.iter() {
        if consignment.has_operation(*id) {
            status.add_failure(validation::Failure::OperationAbsent(*id));
        } else {
            public_rights.push(*valency).expect("same size");
        }
    }
    public_rights
}

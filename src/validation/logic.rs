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

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;

use aluvm::data::Number;
use aluvm::isa::Instr;
use aluvm::reg::{Reg32, RegA};
use aluvm::Vm;
use amplify::confinement::Confined;
use amplify::Wrapper;
use strict_types::TypeSystem;

use crate::schema::{AssignmentsSchema, GlobalSchema, ValencySchema};
use crate::validation::{CheckedConsignment, ConsignmentApi};
use crate::vm::{ContractStateAccess, ContractStateEvolve, OpInfo, OrdOpRef, RgbIsa, VmContext};
use crate::{
    validation, Assign, AssignmentType, Assignments, AssignmentsRef, ExposedSeal, ExposedState,
    Extension, GlobalState, GlobalStateSchema, GlobalValues, GraphSeal, Inputs, MetaSchema,
    Metadata, OpId, Operation, Opout, OwnedStateSchema, RevealedState, Schema, Transition,
    TypedAssigns, Valencies,
};

impl Schema {
    pub fn validate_state<
        'validator,
        C: ConsignmentApi,
        S: ContractStateAccess + ContractStateEvolve,
    >(
        &'validator self,
        consignment: &'validator CheckedConsignment<'_, C>,
        op: OrdOpRef,
        contract_state: Rc<RefCell<S>>,
    ) -> validation::Status {
        let opid = op.id();
        let mut status = validation::Status::new();

        let empty_assign_schema = AssignmentsSchema::default();
        let empty_valency_schema = ValencySchema::default();
        let (
            metadata_schema,
            global_schema,
            owned_schema,
            redeem_schema,
            assign_schema,
            valency_schema,
            validator,
            ty,
        ) = match op {
            OrdOpRef::Genesis(_) => (
                &self.genesis.metadata,
                &self.genesis.globals,
                &empty_assign_schema,
                &empty_valency_schema,
                &self.genesis.assignments,
                &self.genesis.valencies,
                self.genesis.validator,
                None::<u16>,
            ),
            OrdOpRef::Transition(
                Transition {
                    transition_type, ..
                },
                ..,
            ) => {
                // Right now we do not have actions to implement; but later
                // we may have embedded procedures which must be verified
                // here
                /*
                if let Some(procedure) = transition_type.abi.get(&TransitionAction::NoOp) {

                }
                 */

                let transition_schema = match self.transitions.get(transition_type) {
                    None => {
                        return validation::Status::with_failure(
                            validation::Failure::SchemaUnknownTransitionType(
                                opid,
                                *transition_type,
                            ),
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
                    transition_schema.validator,
                    Some(transition_type.into_inner()),
                )
            }
            OrdOpRef::Extension(Extension { extension_type, .. }, ..) => {
                // Right now we do not have actions to implement; but later
                // we may have embedded procedures which must be verified
                // here
                /*
                if let Some(procedure) = extension_type.abi.get(&ExtensionAction::NoOp) {

                }
                 */

                let extension_schema = match self.extensions.get(extension_type) {
                    None => {
                        return validation::Status::with_failure(
                            validation::Failure::SchemaUnknownExtensionType(opid, *extension_type),
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
                    extension_schema.validator,
                    Some(extension_type.into_inner()),
                )
            }
        };

        // Validate type system
        status += self.validate_type_system();
        status += self.validate_metadata(opid, op.metadata(), metadata_schema, consignment.types());
        status +=
            self.validate_global_state(opid, op.globals(), global_schema, consignment.types());
        let prev_state = if let OrdOpRef::Transition(transition, ..) = op {
            let prev_state = extract_prev_state(consignment, opid, &transition.inputs, &mut status);
            status += self.validate_prev_state(opid, &prev_state, owned_schema);
            prev_state
        } else {
            Assignments::default()
        };
        let mut redeemed = Valencies::default();
        if let OrdOpRef::Extension(extension, ..) = op {
            for valency in extension.redeemed.keys() {
                redeemed.push(*valency).expect("same size");
            }
            status += self.validate_redeemed(opid, &redeemed, redeem_schema);
        }
        status += match op.assignments() {
            AssignmentsRef::Genesis(assignments) => {
                self.validate_owned_state(opid, assignments, assign_schema, consignment.types())
            }
            AssignmentsRef::Graph(assignments) => {
                self.validate_owned_state(opid, assignments, assign_schema, consignment.types())
            }
        };

        status += self.validate_valencies(opid, op.valencies(), valency_schema);

        let genesis = consignment.genesis();
        let op_info = OpInfo::with(opid, &op, &prev_state, &redeemed);
        let context = VmContext {
            contract_id: genesis.contract_id(),
            op_info,
            contract_state,
        };

        // We need to run scripts as the very last step, since before that
        // we need to make sure that the operation data match the schema, so
        // scripts are not required to validate the structure of the state
        if let Some(validator) = validator {
            let scripts = consignment.scripts();
            let mut vm = Vm::<Instr<RgbIsa<S>>>::new();
            if let Some(ty) = ty {
                vm.registers.set_n(RegA::A16, Reg32::Reg0, ty);
            }
            if !vm.exec(validator, |id| scripts.get(&id), &context) {
                let error_code: Option<Number> = vm.registers.get_n(RegA::A8, Reg32::Reg0).into();
                status.add_failure(validation::Failure::ScriptFailure(
                    opid,
                    error_code.map(u8::from),
                    None,
                ));
                // We return here since all other validations will have no valid state to access
                return status;
            }
            let contract_state = context.contract_state;
            if contract_state.borrow_mut().evolve_state(op).is_err() {
                status.add_failure(validation::Failure::ContractStateFilled(opid));
                // We return here since all other validations will have no valid state to access
                return status;
            }
        }
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
        metadata: &Metadata,
        metadata_schema: &MetaSchema,
        types: &TypeSystem,
    ) -> validation::Status {
        let mut status = validation::Status::new();

        metadata
            .keys()
            .copied()
            .collect::<BTreeSet<_>>()
            .difference(metadata_schema.as_unconfined())
            .for_each(|type_id| {
                status.add_failure(validation::Failure::SchemaUnknownMetaType(opid, *type_id));
            });

        for type_id in metadata_schema {
            let Some(value) = metadata.get(type_id) else {
                status.add_failure(validation::Failure::SchemaNoMetadata(opid, *type_id));
                continue;
            };

            let sem_id = self.meta_types.get(type_id).expect(
                "if this metadata type were absent, the schema would not be able to pass the \
                 internal validation and we would not reach this point",
            );

            if types
                .strict_deserialize_type(*sem_id, value.as_ref())
                .is_err()
            {
                status.add_failure(validation::Failure::SchemaInvalidMetadata(opid, *sem_id));
            };
        }

        status
    }

    fn validate_global_state(
        &self,
        opid: OpId,
        global: &GlobalState,
        global_schema: &GlobalSchema,
        types: &TypeSystem,
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
                .map(Confined::release)
                .unwrap_or_default();

            let GlobalStateSchema {
                sem_id,
                max_items,
                reserved: _,
            } = self.global_types.get(type_id).expect(
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
            if count as u32 > max_items.to_u32() {
                status.add_failure(validation::Failure::SchemaGlobalStateLimit(
                    opid, *type_id, count, *max_items,
                ));
            }

            // Validating data types
            for data in set {
                if types
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
        types: &TypeSystem,
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
                Some(TypedAssigns::Declarative(set)) => set
                    .iter()
                    .for_each(|data| status += assignment.validate(id, *state_id, data, types)),
                Some(TypedAssigns::Fungible(set)) => set
                    .iter()
                    .for_each(|data| status += assignment.validate(id, *state_id, data, types)),
                Some(TypedAssigns::Structured(set)) => set
                    .iter()
                    .for_each(|data| status += assignment.validate(id, *state_id, data, types)),
                Some(TypedAssigns::Attachment(set)) => set
                    .iter()
                    .for_each(|data| status += assignment.validate(id, *state_id, data, types)),
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

impl OwnedStateSchema {
    pub fn validate<State: ExposedState, Seal: ExposedSeal>(
        &self,
        opid: OpId,
        state_type: AssignmentType,
        data: &Assign<State, Seal>,
        type_system: &TypeSystem,
    ) -> validation::Status {
        let mut status = validation::Status::new();
        match data {
            Assign::Revealed { state, .. } | Assign::ConfidentialSeal { state, .. } => {
                match (self, state.state_data()) {
                    (OwnedStateSchema::Declarative, RevealedState::Void) => {}
                    (
                        OwnedStateSchema::Attachment(media_type),
                        RevealedState::Attachment(attach),
                    ) if !attach.file.media_type.conforms(media_type) => {
                        status.add_failure(validation::Failure::MediaTypeMismatch {
                            opid,
                            state_type,
                            expected: *media_type,
                            found: attach.file.media_type,
                        });
                    }
                    (OwnedStateSchema::Fungible(schema), RevealedState::Fungible(v))
                        if v.value.fungible_type() != *schema =>
                    {
                        status.add_failure(validation::Failure::FungibleTypeMismatch {
                            opid,
                            state_type,
                            expected: *schema,
                            found: v.value.fungible_type(),
                        });
                    }
                    (OwnedStateSchema::Fungible(_), RevealedState::Fungible(_)) => {}
                    (OwnedStateSchema::Structured(sem_id), RevealedState::Structured(data)) => {
                        if type_system
                            .strict_deserialize_type(*sem_id, data.value.as_ref())
                            .is_err()
                        {
                            status.add_failure(validation::Failure::SchemaInvalidOwnedValue(
                                opid, state_type, *sem_id,
                            ));
                        };
                    }
                    // all other options are mismatches
                    (state_schema, found) => {
                        status.add_failure(validation::Failure::StateTypeMismatch {
                            opid,
                            state_type,
                            expected: state_schema.state_type(),
                            found: found.state_type(),
                        });
                    }
                }
            }
        }
        status
    }
}

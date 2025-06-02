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

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use amplify::confinement::{Confined, NonEmptyVec};
use amplify::Wrapper;
use secp256k1::{ecdsa, Message, PublicKey};
use strict_types::TypeSystem;

use super::{
    CheckedConsignment, ConsignmentApi, ContractStateAccess, ContractStateEvolve, FullOpRef,
};
use crate::assignments::AssignVec;
use crate::schema::{AssignmentsSchema, GlobalSchema};
use crate::{
    validation, AnyState, Assign, AssignmentType, Assignments, AssignmentsRef, ExposedSeal,
    ExposedState, GlobalState, GlobalStateSchema, GlobalValues, GraphSeal, Inputs, MetaSchema,
    Metadata, OpId, Operation, Opout, OwnedStateSchema, Schema, SealClosingStrategy, Transition,
    TypedAssigns, Verifier,
};

impl Schema {
    pub fn validate_state<
        'validator,
        C: ConsignmentApi,
        S: ContractStateAccess + ContractStateEvolve,
    >(
        &'validator self,
        consignment: &'validator CheckedConsignment<'_, C>,
        op: FullOpRef,
        contract_state: &mut S,
    ) -> validation::Status {
        let opid = op.id();
        let mut status = validation::Status::new();

        let empty_assign_schema = AssignmentsSchema::default();
        let (metadata_schema, global_schema, owned_schema, assign_schema, verifier) = match op {
            FullOpRef::Genesis(genesis) => {
                if genesis.seal_closing_strategy != SealClosingStrategy::FirstOpretOrTapret {
                    return validation::Status::with_failure(
                        validation::Failure::SchemaUnknownSealClosingStrategy(
                            opid,
                            genesis.seal_closing_strategy,
                        ),
                    );
                }
                (
                    &self.genesis.metadata,
                    &self.genesis.globals,
                    &empty_assign_schema,
                    &self.genesis.assignments,
                    Verifier::None,
                )
            }
            FullOpRef::Transition(
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
                    Some(transition_details) => &transition_details.transition_schema,
                };

                (
                    &transition_schema.metadata,
                    &transition_schema.globals,
                    &transition_schema.inputs,
                    &transition_schema.assignments,
                    transition_schema.verifier,
                )
            }
        };

        status += self.validate_metadata(opid, op.metadata(), metadata_schema, consignment.types());
        status +=
            self.validate_global_state(opid, op.globals(), global_schema, consignment.types());
        let prev_state = if let FullOpRef::Transition(transition, ..) = op {
            let prev_state = extract_prev_state(consignment, opid, &transition.inputs, &mut status);
            status += self.validate_prev_state(opid, &prev_state, owned_schema);
            prev_state
        } else {
            Assignments::default()
        };
        status += match op.assignments() {
            AssignmentsRef::Genesis(assignments) => {
                self.validate_owned_state(opid, assignments, assign_schema, consignment.types())
            }
            AssignmentsRef::Graph(assignments) => {
                self.validate_owned_state(opid, assignments, assign_schema, consignment.types())
            }
        };

        // Run the validation logic
        match verifier {
            Verifier::None => {}
            Verifier::EqSums(ty) => {
                let Some(sum_in) = prev_state
                    .get(&ty)
                    .into_iter()
                    .flat_map(TypedAssigns::as_fungible)
                    .map(Assign::as_state)
                    .try_fold(0u64, |sum, state| sum.checked_add(state.0))
                else {
                    status.add_failure(validation::Failure::Verifier(verifier, opid));
                    return status;
                };
                let Some(sum_out) = op
                    .assignments()
                    .get(ty)
                    .iter()
                    .flat_map(TypedAssigns::as_fungible)
                    .map(Assign::as_state)
                    .try_fold(0u64, |sum, state| sum.checked_add(state.0))
                else {
                    status.add_failure(validation::Failure::Verifier(verifier, opid));
                    return status;
                };
                if sum_in != sum_out {
                    status.add_failure(validation::Failure::Verifier(verifier, opid));
                    return status;
                }
            }
            Verifier::EqVals(ty) => {
                if prev_state
                    .get(&ty)
                    .map(TypedAssigns::len_u16)
                    .unwrap_or_default()
                    != op
                        .assignments()
                        .get(ty)
                        .as_ref()
                        .map(TypedAssigns::len_u16)
                        .unwrap_or_default()
                {
                    status.add_failure(validation::Failure::Verifier(verifier, opid));
                    return status;
                }
                if prev_state
                    .get(&ty)
                    .into_iter()
                    .flat_map(TypedAssigns::as_declarative)
                    .map(Assign::as_state)
                    .collect::<BTreeSet<_>>()
                    != op
                        .assignments()
                        .get(ty)
                        .iter()
                        .flat_map(TypedAssigns::as_declarative)
                        .map(Assign::as_state)
                        .collect::<BTreeSet<_>>()
                {
                    status.add_failure(validation::Failure::Verifier(verifier, opid));
                    return status;
                }
            }
            Verifier::CheckSigEcdsa(glob_ty, meta_ty) => {
                let genesis = consignment.genesis();
                let Some(pk) = genesis
                    .globals
                    .get(&glob_ty)
                    .into_iter()
                    .flatten()
                    .map(|pk| PublicKey::from_slice(pk.as_slice()).ok())
                    .next()
                    .flatten()
                else {
                    status.add_failure(validation::Failure::Verifier(verifier, opid));
                    return status;
                };
                let Some(sig) = op
                    .metadata()
                    .get(&meta_ty)
                    .into_iter()
                    .map(|meta| ecdsa::Signature::from_compact(meta).ok())
                    .next()
                    .flatten()
                else {
                    status.add_failure(validation::Failure::Verifier(verifier, opid));
                    return status;
                };
                let msg = Message::from_digest(opid.to_byte_array());
                if sig.verify(&msg, &pk).is_err() {
                    status.add_failure(validation::Failure::Verifier(verifier, opid));
                    return status;
                }
            }
        }
        if contract_state.evolve_state(op).is_err() {
            status.add_failure(validation::Failure::ContractStateFilled(opid));
            // We return here since all other validations will have no valid state to access
            return status;
        }

        status
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

            let sem_id = self
                .meta_types
                .get(type_id)
                .expect(
                    "if this metadata type were absent, the schema would not be able to pass the \
                     internal validation and we would not reach this point",
                )
                .sem_id;

            if types
                .strict_deserialize_type(sem_id, value.as_ref())
                .is_err()
            {
                status.add_failure(validation::Failure::SchemaInvalidMetadata(opid, sem_id));
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

            let GlobalStateSchema { sem_id, max_items } = self
                .global_types
                .get(type_id)
                .expect(
                    "if the field were absent, the schema would not be able to pass the internal \
                     validation and we would not reach this point",
                )
                .global_state_schema;

            // Checking number of field occurrences
            let count = set.len() as u16;
            if let Err(err) = occ.check(count) {
                status.add_failure(validation::Failure::SchemaGlobalStateOccurrences(
                    opid, *type_id, err,
                ));
            }
            if count as u32 > max_items.to_u32() {
                status.add_failure(validation::Failure::SchemaGlobalStateLimit(
                    opid, *type_id, count, max_items,
                ));
            }

            // Validating data types
            for data in set {
                if types
                    .strict_deserialize_type(sem_id, data.as_ref())
                    .is_err()
                {
                    status.add_failure(validation::Failure::SchemaInvalidGlobalValue(
                        opid, *type_id, sem_id,
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

            let assignment = &self
                .owned_types
                .get(state_id)
                .expect(
                    "If the assignment were absent, the schema would not be able to pass the \
                     internal validation and we would not reach this point",
                )
                .owned_state_schema;

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
            };
        }

        status
    }
}

fn extract_prev_state<C: ConsignmentApi>(
    consignment: &C,
    opid: OpId,
    inputs: &Inputs,
    status: &mut validation::Status,
) -> Assignments<GraphSeal> {
    let mut assignments: BTreeMap<AssignmentType, TypedAssigns<_>> = bmap! {};
    for input in inputs {
        let Opout { op, ty, no } = input;

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
                    match assignments.entry(ty) {
                        Entry::Occupied(mut entry) => {
                            if let Some(typed_assigns) = entry.get_mut().as_declarative_mut() {
                                typed_assigns.push(prev_assign.clone()).expect("same size");
                            }
                        }
                        Entry::Vacant(entry) => {
                            entry.insert(TypedAssigns::Declarative(AssignVec::with(
                                NonEmptyVec::with(prev_assign.clone()),
                            )));
                        }
                    }
                } else {
                    status.add_failure(validation::Failure::NoPrevOut(opid, input));
                }
            }
            Some(TypedAssigns::Fungible(prev_assignments)) => {
                if let Some(prev_assign) = prev_assignments.get(no) {
                    match assignments.entry(ty) {
                        Entry::Occupied(mut entry) => {
                            if let Some(typed_assigns) = entry.get_mut().as_fungible_mut() {
                                typed_assigns.push(prev_assign.clone()).expect("same size");
                            }
                        }
                        Entry::Vacant(entry) => {
                            entry.insert(TypedAssigns::Fungible(AssignVec::with(
                                NonEmptyVec::with(prev_assign.clone()),
                            )));
                        }
                    }
                } else {
                    status.add_failure(validation::Failure::NoPrevOut(opid, input));
                }
            }
            Some(TypedAssigns::Structured(prev_assignments)) => {
                if let Some(prev_assign) = prev_assignments.get(no) {
                    match assignments.entry(ty) {
                        Entry::Occupied(mut entry) => {
                            if let Some(typed_assigns) = entry.get_mut().as_structured_mut() {
                                typed_assigns.push(prev_assign.clone()).expect("same size");
                            }
                        }
                        Entry::Vacant(entry) => {
                            entry.insert(TypedAssigns::Structured(AssignVec::with(
                                NonEmptyVec::with(prev_assign.clone()),
                            )));
                        }
                    }
                } else {
                    status.add_failure(validation::Failure::NoPrevOut(opid, input));
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
            Assign::Revealed { state, .. } | Assign::SecretSeal { state, .. } => {
                match (self, state.state_data()) {
                    (OwnedStateSchema::Declarative, AnyState::Void) => {}
                    (OwnedStateSchema::Fungible, AnyState::Fungible(_)) => {}
                    (OwnedStateSchema::Structured(sem_id), AnyState::Structured(data)) => {
                        if type_system
                            .strict_deserialize_type(*sem_id, data.as_ref())
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

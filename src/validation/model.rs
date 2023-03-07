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

use std::collections::BTreeSet;

use amplify::confinement::{Confined, SmallBlob};
use amplify::Wrapper;

use crate::schema::{AssignmentSchema, GlobalSchema, ValencySchema};
use crate::validation::vm::VirtualMachine;
use crate::validation::HistoryApi;
use crate::{
    seal, validation, Assign, ExposedSeal, ExposedState, GlobalState, GlobalValues, OpFullType,
    OpId, OpRef, Operation, OwnedState, PrevOuts, Redeemed, Schema, SchemaRoot, TypedAssigns,
    Valencies,
};

impl<Root: SchemaRoot> Schema<Root> {
    pub fn validate<'script, C: HistoryApi>(
        &self,
        consignment: &C,
        op: OpRef,
        vm: &dyn VirtualMachine,
    ) -> validation::Status {
        let id = op.id();

        let empty_assign_schema = AssignmentSchema::default();
        let empty_valency_schema = ValencySchema::default();
        let (global_schema, owned_schema, redeem_schema, assign_schema, valency_schema) =
            match (op.transition_type(), op.extension_type()) {
                (None, None) => {
                    // Right now we do not have actions to implement; but later
                    // we may have embedded procedures which must be verified
                    // here
                    /*
                    if let Some(procedure) = self.genesis.abi.get(&GenesisAction::NoOp) {

                    }
                     */

                    (
                        &self.genesis.global_state,
                        &empty_assign_schema,
                        &empty_valency_schema,
                        &self.genesis.owned_state,
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

                    let transition_type = match self.transitions.get(&transition_type) {
                        None => {
                            return validation::Status::with_failure(
                                validation::Failure::SchemaUnknownTransitionType(
                                    id,
                                    transition_type,
                                ),
                            );
                        }
                        Some(transition_type) => transition_type,
                    };

                    (
                        &transition_type.global_state,
                        &transition_type.closes,
                        &empty_valency_schema,
                        &transition_type.owned_state,
                        &transition_type.valencies,
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

                    let extension_type = match self.extensions.get(&extension_type) {
                        None => {
                            return validation::Status::with_failure(
                                validation::Failure::SchemaUnknownExtensionType(id, extension_type),
                            );
                        }
                        Some(extension_type) => extension_type,
                    };

                    (
                        &extension_type.global_state,
                        &empty_assign_schema,
                        &extension_type.redeems,
                        &extension_type.owned_state,
                        &extension_type.redeems,
                    )
                }
                _ => unreachable!("Node can't be extension and state transition at the same time"),
            };

        let mut status = validation::Status::new();

        // Validate type system
        status += self.validate_type_system();
        status += self.validate_global_state(id, op.global_state(), global_schema);
        let prev_state = if let OpRef::Transition(ref transition) = op {
            let prev_state = extract_prev_state(consignment, &transition.prev_state, &mut status);
            status += self.validate_prev_state(id, &prev_state, owned_schema);
            prev_state
        } else {
            OwnedState::default()
        };
        let redeemed = if let OpRef::Extension(ref extension) = op {
            let redeemed =
                extract_redeemed_valencies(consignment, &extension.redeemed, &mut status);
            status += self.validate_redeemed(id, &redeemed, redeem_schema);
            redeemed
        } else {
            Valencies::default()
        };
        status += self.validate_owned_state(id, op.owned_state(), assign_schema);
        status += self.validate_valencies(id, op.valencies(), valency_schema);

        let op_info = OpInfo::with(id, self.subset_of.is_some(), &op, &prev_state, &redeemed);

        // We need to run scripts as the very last step, since before that
        // we need to make sure that the operation data match the schema, so
        // scripts are not required to validate the structure of the state
        status += self.validate_state_evolution(op_info, vm);
        status
    }

    fn validate_type_system(&self) -> validation::Status {
        validation::Status::new()
        // TODO: Validate type system
        /*if let Err(inconsistencies) = self.type_system.validate() {
            for _err in inconsistencies {
                status.add_failure(validation::Failure::SchemaTypeSystem(/*err*/));
            }
        }*/
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
                status.add_failure(validation::Failure::SchemaUnknownFieldType(opid, **field_id));
            });

        for (global_id, occ) in global_schema {
            let set = global
                .get(global_id)
                .cloned()
                .map(GlobalValues::into_inner)
                .map(Confined::unbox)
                .unwrap_or_default();

            // Checking number of field occurrences
            if let Err(err) = occ.check(set.len() as u16) {
                status.add_failure(validation::Failure::SchemaMetaOccurrencesError(
                    opid, *global_id, err,
                ));
            }

            let _field = self.global_types.get(global_id).expect(
                "If the field were absent, the schema would not be able to pass the internal \
                 validation and we would not reach this point",
            );
            for _data in set {
                // TODO: #137 Run strict type validation
                /*
                let schema_type = data.schema_type();

                status.add_failure(validation::Failure::SchemaMismatchedDataType(
                    *field_type_id,
                ));
                status += field.verify(&self.type_system, opid, *field_type_id, &data);
                 */
            }
        }

        status
    }

    fn validate_prev_state<Seal: ExposedSeal>(
        &self,
        id: OpId,
        owned_state: &OwnedState<Seal>,
        assign_schema: &AssignmentSchema,
    ) -> validation::Status {
        let mut status = validation::Status::new();

        owned_state
            .keys()
            .collect::<BTreeSet<_>>()
            .difference(&assign_schema.keys().collect())
            .for_each(|owned_type_id| {
                status.add_failure(validation::Failure::SchemaUnknownOwnedRightType(
                    id,
                    **owned_type_id,
                ));
            });

        for (owned_type_id, occ) in assign_schema {
            let len = owned_state
                .get(owned_type_id)
                .map(TypedAssigns::len)
                .unwrap_or(0);

            // Checking number of ancestor's assignment occurrences
            if let Err(err) = occ.check(len as u16) {
                status.add_failure(validation::Failure::SchemaParentOwnedRightOccurrencesError(
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
                status.add_failure(validation::Failure::SchemaUnknownPublicRightType(
                    id,
                    *public_type_id,
                ));
            });

        status
    }

    fn validate_owned_state<Seal: ExposedSeal>(
        &self,
        id: OpId,
        owned_state: &OwnedState<Seal>,
        assign_schema: &AssignmentSchema,
    ) -> validation::Status {
        let mut status = validation::Status::new();

        owned_state
            .keys()
            .collect::<BTreeSet<_>>()
            .difference(&assign_schema.keys().collect())
            .for_each(|assignment_type_id| {
                status.add_failure(validation::Failure::SchemaUnknownOwnedRightType(
                    id,
                    **assignment_type_id,
                ));
            });

        for (state_id, occ) in assign_schema {
            let len = owned_state
                .get(state_id)
                .map(TypedAssigns::len)
                .unwrap_or(0);

            // Checking number of assignment occurrences
            if let Err(err) = occ.check(len as u16) {
                status.add_failure(validation::Failure::SchemaOwnedRightOccurrencesError(
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
                    .for_each(|data| status += assignment.validate(&id, *state_id, data)),
                Some(TypedAssigns::Fungible(set)) => set
                    .iter()
                    .for_each(|data| status += assignment.validate(&id, *state_id, data)),
                Some(TypedAssigns::Structured(set)) => set
                    .iter()
                    .for_each(|data| status += assignment.validate(&id, *state_id, data)),
                Some(TypedAssigns::Attachment(set)) => set
                    .iter()
                    .for_each(|data| status += assignment.validate(&id, *state_id, data)),
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
                status.add_failure(validation::Failure::SchemaUnknownPublicRightType(
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
    pub id: OpId,
    pub ty: OpFullType,
    pub metadata: Option<&'op SmallBlob>,
    pub prev_state: &'op OwnedState<seal::Revealed>,
    pub owned_state: &'op OwnedState<seal::Revealed>,
    pub redeemed: &'op Valencies,
    pub valencies: &'op Valencies,
    pub global: &'op GlobalState,
}

impl<'op> OpInfo<'op> {
    pub fn with(
        id: OpId,
        subschema: bool,
        op: &'op OpRef<'op>,
        prev_state: &'op OwnedState<seal::Revealed>,
        redeemed: &'op Valencies,
    ) -> Self {
        OpInfo {
            id,
            subschema,
            ty: op.full_type(),
            metadata: op.metadata(),
            prev_state,
            owned_state: op.owned_state(),
            redeemed,
            valencies: op.valencies(),
            global: op.global_state(),
        }
    }
}

fn extract_prev_state<C: HistoryApi>(
    consignment: &C,
    prev_state: &PrevOuts,
    status: &mut validation::Status,
) -> OwnedState<seal::Revealed> {
    let mut owned_state = bmap! {};
    for (id, details) in prev_state.iter() {
        let prev_op = match consignment.operation(*id) {
            None => {
                status.add_failure(validation::Failure::OperationAbsent(*id));
                continue;
            }
            Some(op) => op,
        };

        fn filter<State: ExposedState, Seal: ExposedSeal>(
            set: &[Assign<State, Seal>],
            indexes: &[u16],
        ) -> Vec<Assign<State, Seal>> {
            set.iter()
                .enumerate()
                .filter_map(|(index, item)| {
                    if indexes.contains(&(index as u16)) {
                        Some(item.clone())
                    } else {
                        None
                    }
                })
                .collect()
        }

        for (state_id, indexes) in details {
            match prev_op.owned_state_by_type(*state_id) {
                Some(TypedAssigns::Declarative(set)) => {
                    let set = filter(set, indexes);
                    if let Some(state) = owned_state
                        .entry(*state_id)
                        .or_insert_with(|| TypedAssigns::Declarative(Default::default()))
                        .as_declarative_mut()
                    {
                        state.extend(set).expect("same size");
                    }
                }
                Some(TypedAssigns::Fungible(set)) => {
                    let set = filter(set, indexes);
                    if let Some(state) = owned_state
                        .entry(*state_id)
                        .or_insert_with(|| TypedAssigns::Fungible(Default::default()))
                        .as_fungible_mut()
                    {
                        state.extend(set).expect("same size");
                    }
                }
                Some(TypedAssigns::Structured(set)) => {
                    let set = filter(set, indexes);
                    if let Some(state) = owned_state
                        .entry(*state_id)
                        .or_insert_with(|| TypedAssigns::Structured(Default::default()))
                        .as_structured_mut()
                    {
                        state.extend(set).expect("same size");
                    }
                }
                Some(TypedAssigns::Attachment(set)) => {
                    let set = filter(set, indexes);
                    if let Some(state) = owned_state
                        .entry(*state_id)
                        .or_insert_with(|| TypedAssigns::Attachment(Default::default()))
                        .as_attachment_mut()
                    {
                        state.extend(set).expect("same size");
                    }
                }
                None => {
                    // Presence of the required owned rights type in the
                    // parent operation was already validated; we have nothing
                    // to report here
                }
            }
        }
    }
    Confined::try_from(owned_state)
        .expect("collections is assembled from another collection with the same size requirements")
        .into()
}

fn extract_redeemed_valencies<C: HistoryApi>(
    consignment: &C,
    redeemed: &Redeemed,
    status: &mut validation::Status,
) -> Valencies {
    let mut public_rights = Valencies::default();
    for (id, valencies) in redeemed.iter() {
        if consignment.has_operation(*id) {
            status.add_failure(validation::Failure::OperationAbsent(*id));
        } else {
            public_rights
                .extend(valencies.iter().copied())
                .expect("same size");
        }
    }
    public_rights
}

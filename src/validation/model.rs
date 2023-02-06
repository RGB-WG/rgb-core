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

use amplify::confinement::Confined;
use amplify::Wrapper;
use commit_verify::Conceal;

use crate::schema::{AssignmentSchema, GlobalSchema, ValencySchema};
use crate::validation::vm::VirtualMachine;
use crate::vm::AluRuntime;
use crate::{
    validation, AssignedState, GlobalState, GlobalValues, OpFullType, OpId, Operation, OwnedState,
    PrevState, Redeemed, Schema, Script, StatePair, TypedState, Valencies,
};

impl Schema {
    pub fn validate(
        &self,
        all_ops: &BTreeMap<OpId, &dyn Operation>,
        op: &dyn Operation,
        script: &Script,
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

        let prev_state = extract_prev_state(all_ops, op.prev_state(), &mut status);
        let redeemed = extract_redeemed_valencies(all_ops, op.redeemed(), &mut status);
        status += self.validate_global_state(id, op.global_state(), global_schema);
        status += self.validate_prev_state(id, &prev_state, owned_schema);
        status += self.validate_redeemed(id, &redeemed, redeem_schema);
        status += self.validate_owned_state(id, op.owned_state(), assign_schema);
        status += self.validate_valencies(id, op.valencies(), valency_schema);

        // We need to run scripts as the very last step, since before that
        // we need to make sure that the node data match the schema, so
        // scripts are not required to validate the structure of the state
        status += self.validate_state_evolution(
            id,
            op.full_type(),
            &prev_state,
            op.owned_state(),
            &redeemed,
            op.valencies(),
            op.global_state(),
            script,
        );
        status
    }

    fn validate_type_system(&self) -> validation::Status {
        let status = validation::Status::new();
        // TODO: Validate type system
        /*if let Err(inconsistencies) = self.type_system.validate() {
            for _err in inconsistencies {
                status.add_failure(validation::Failure::SchemaTypeSystem(/*err*/));
            }
        }*/
        status
    }

    fn validate_global_state(
        &self,
        op_id: OpId,
        global: &GlobalState,
        global_schema: &GlobalSchema,
    ) -> validation::Status {
        let mut status = validation::Status::new();

        global
            .keys()
            .collect::<BTreeSet<_>>()
            .difference(&global_schema.keys().collect())
            .for_each(|field_id| {
                status.add_failure(validation::Failure::SchemaUnknownFieldType(op_id, **field_id));
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
                    op_id, *global_id, err,
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
                status += field.verify(&self.type_system, node_id, *field_type_id, &data);
                 */
            }
        }

        status
    }

    fn validate_prev_state(
        &self,
        id: OpId,
        owned_state: &OwnedState,
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
                .map(TypedState::len)
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

    fn validate_owned_state(
        &self,
        id: OpId,
        owned_state: &OwnedState,
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
            let len = owned_state.get(state_id).map(TypedState::len).unwrap_or(0);

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
                Some(TypedState::Declarative(set)) => set
                    .iter()
                    .for_each(|data| status += assignment.validate(&id, *state_id, data)),
                Some(TypedState::Fungible(set)) => set
                    .iter()
                    .for_each(|data| status += assignment.validate(&id, *state_id, data)),
                Some(TypedState::Structured(set)) => set
                    .iter()
                    .for_each(|data| status += assignment.validate(&id, *state_id, data)),
                Some(TypedState::Attachment(set)) => set
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

    #[allow(clippy::too_many_arguments)]
    fn validate_state_evolution(
        &self,
        id: OpId,
        ty: OpFullType,
        prev_state: &OwnedState,
        owned_state: &OwnedState,
        redeemed: &Valencies,
        valencies: &Valencies,
        global: &GlobalState,
        script: &Script,
    ) -> validation::Status {
        let mut status = validation::Status::new();

        // We do not validate public rights, since they do not have an
        // associated state and there is nothing to validate beyond schema

        let vm = match script {
            Script::AluVM(lib) => Box::new(AluRuntime::new(lib)) as Box<dyn VirtualMachine>,
        };

        if let Err(err) = vm.validate(id, ty, prev_state, owned_state, redeemed, valencies, global)
        {
            status.add_failure(err);
        }

        status
    }
}

fn extract_prev_state(
    ops: &BTreeMap<OpId, &dyn Operation>,
    prev_state: &PrevState,
    status: &mut validation::Status,
) -> OwnedState {
    let mut owned_state = bmap! {};
    for (id, details) in prev_state.iter() {
        let prev_op = match ops.get(id) {
            None => {
                status.add_failure(validation::Failure::TransitionAbsent(*id));
                continue;
            }
            Some(node) => node,
        };

        fn filter<Pair>(set: &[AssignedState<Pair>], indexes: &[u16]) -> Vec<AssignedState<Pair>>
        where
            Pair: StatePair + Clone,
            Pair::Confidential: PartialEq + Eq,
            Pair::Confidential: From<<Pair::Revealed as Conceal>::Concealed>,
        {
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
                Some(TypedState::Declarative(set)) => {
                    let set = filter(set, indexes);
                    if let Some(state) = owned_state
                        .entry(*state_id)
                        .or_insert_with(|| TypedState::Declarative(Default::default()))
                        .as_declarative_mut()
                    {
                        state.extend(set).expect("same size");
                    }
                }
                Some(TypedState::Fungible(set)) => {
                    let set = filter(set, indexes);
                    if let Some(state) = owned_state
                        .entry(*state_id)
                        .or_insert_with(|| TypedState::Fungible(Default::default()))
                        .as_fungible_mut()
                    {
                        state.extend(set).expect("same size");
                    }
                }
                Some(TypedState::Structured(set)) => {
                    let set = filter(set, indexes);
                    if let Some(state) = owned_state
                        .entry(*state_id)
                        .or_insert_with(|| TypedState::Structured(Default::default()))
                        .as_structured_mut()
                    {
                        state.extend(set).expect("same size");
                    }
                }
                Some(TypedState::Attachment(set)) => {
                    let set = filter(set, indexes);
                    if let Some(state) = owned_state
                        .entry(*state_id)
                        .or_insert_with(|| TypedState::Attachment(Default::default()))
                        .as_attachment_mut()
                    {
                        state.extend(set).expect("same size");
                    }
                }
                None => {
                    // Presence of the required owned rights type in the
                    // parent node was already validated; we have nothing to
                    // report here
                }
            }
        }
    }
    Confined::try_from(owned_state)
        .expect("collections is assembled from another collection with the same size requirements")
        .into()
}

fn extract_redeemed_valencies(
    operations: &BTreeMap<OpId, &dyn Operation>,
    redeemed: &Redeemed,
    status: &mut validation::Status,
) -> Valencies {
    let mut public_rights = Valencies::default();
    for (id, valencies) in redeemed.iter() {
        if operations.get(id).is_none() {
            status.add_failure(validation::Failure::TransitionAbsent(*id));
        } else {
            public_rights
                .extend(valencies.iter().copied())
                .expect("same size");
        }
    }
    public_rights
}

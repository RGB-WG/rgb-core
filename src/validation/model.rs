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

use crate::schema::{MetadataStructure, OwnedRightsStructure, PublicRightsStructure};
use crate::validation::vm::VirtualMachine;
use crate::vm::AluRuntime;
use crate::{
    validation, Assignment, FieldValues, Metadata, Node, NodeId, NodeSubtype, OwnedRights,
    ParentOwnedRights, ParentPublicRights, PublicRights, Schema, Script, State, TypedAssignments,
};

impl Schema {
    pub fn validate(
        &self,
        all_nodes: &BTreeMap<NodeId, &dyn Node>,
        node: &dyn Node,
        script: &Script,
    ) -> validation::Status {
        let node_id = node.node_id();

        let empty_owned_structure = OwnedRightsStructure::default();
        let empty_public_structure = PublicRightsStructure::default();
        let (
            metadata_structure,
            parent_owned_structure,
            parent_public_structure,
            assignments_structure,
            valencies_structure,
        ) = match (node.transition_type(), node.extension_type()) {
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
                    &empty_owned_structure,
                    &empty_public_structure,
                    &self.genesis.owned_rights,
                    &self.genesis.public_rights,
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
                                node_id,
                                transition_type,
                            ),
                        );
                    }
                    Some(transition_type) => transition_type,
                };

                (
                    &transition_type.metadata,
                    &transition_type.closes,
                    &empty_public_structure,
                    &transition_type.owned_rights,
                    &transition_type.public_rights,
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
                            validation::Failure::SchemaUnknownExtensionType(
                                node_id,
                                extension_type,
                            ),
                        );
                    }
                    Some(extension_type) => extension_type,
                };

                (
                    &extension_type.metadata,
                    &empty_owned_structure,
                    &extension_type.extends,
                    &extension_type.owned_rights,
                    &extension_type.extends,
                )
            }
            _ => unreachable!("Node can't be extension and state transition at the same time"),
        };

        let mut status = validation::Status::new();

        // Validate type system
        status += self.validate_type_system();

        let parent_owned_rights =
            extract_parent_owned_rights(all_nodes, node.parent_owned_rights(), &mut status);
        let parent_public_rights =
            extract_parent_public_rights(all_nodes, node.parent_public_rights(), &mut status);
        status += self.validate_meta(node_id, node.metadata(), metadata_structure);
        status += self.validate_parent_owned_rights(
            node_id,
            &parent_owned_rights,
            parent_owned_structure,
        );
        status += self.validate_parent_public_rights(
            node_id,
            &parent_public_rights,
            parent_public_structure,
        );
        status += self.validate_owned_rights(node_id, node.owned_rights(), assignments_structure);
        status += self.validate_public_rights(node_id, node.public_rights(), valencies_structure);

        // We need to run scripts as the very last step, since before that
        // we need to make sure that the node data match the schema, so
        // scripts are not required to validate the structure of the state
        status += self.validate_state_evolution(
            node_id,
            node.subtype(),
            &parent_owned_rights,
            node.owned_rights(),
            &parent_public_rights,
            node.public_rights(),
            node.metadata(),
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

    fn validate_meta(
        &self,
        node_id: NodeId,
        metadata: &Metadata,
        metadata_structure: &MetadataStructure,
    ) -> validation::Status {
        let mut status = validation::Status::new();

        metadata
            .keys()
            .collect::<BTreeSet<_>>()
            .difference(&metadata_structure.keys().collect())
            .for_each(|field_id| {
                status
                    .add_failure(validation::Failure::SchemaUnknownFieldType(node_id, **field_id));
            });

        for (field_type_id, occ) in metadata_structure {
            let set = metadata
                .get(field_type_id)
                .cloned()
                .map(FieldValues::into_inner)
                .map(Confined::unbox)
                .unwrap_or_default();

            // Checking number of field occurrences
            if let Err(err) = occ.check(set.len() as u16) {
                status.add_failure(validation::Failure::SchemaMetaOccurrencesError(
                    node_id,
                    *field_type_id,
                    err,
                ));
            }

            let _field = self.field_types.get(field_type_id).expect(
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

    fn validate_parent_owned_rights(
        &self,
        node_id: NodeId,
        owned_rights: &OwnedRights,
        owned_rights_structure: &OwnedRightsStructure,
    ) -> validation::Status {
        let mut status = validation::Status::new();

        owned_rights
            .keys()
            .collect::<BTreeSet<_>>()
            .difference(&owned_rights_structure.keys().collect())
            .for_each(|owned_type_id| {
                status.add_failure(validation::Failure::SchemaUnknownOwnedRightType(
                    node_id,
                    **owned_type_id,
                ));
            });

        for (owned_type_id, occ) in owned_rights_structure {
            let len = owned_rights
                .get(owned_type_id)
                .map(TypedAssignments::len)
                .unwrap_or(0);

            // Checking number of ancestor's assignment occurrences
            if let Err(err) = occ.check(len as u16) {
                status.add_failure(validation::Failure::SchemaParentOwnedRightOccurrencesError(
                    node_id,
                    *owned_type_id,
                    err,
                ));
            }
        }

        status
    }

    fn validate_parent_public_rights(
        &self,
        node_id: NodeId,
        public_rights: &PublicRights,
        public_rights_structure: &PublicRightsStructure,
    ) -> validation::Status {
        let mut status = validation::Status::new();

        public_rights
            .difference(public_rights_structure)
            .for_each(|public_type_id| {
                status.add_failure(validation::Failure::SchemaUnknownPublicRightType(
                    node_id,
                    *public_type_id,
                ));
            });

        status
    }

    fn validate_owned_rights(
        &self,
        node_id: NodeId,
        owned_rights: &OwnedRights,
        owned_rights_structure: &OwnedRightsStructure,
    ) -> validation::Status {
        let mut status = validation::Status::new();

        owned_rights
            .keys()
            .collect::<BTreeSet<_>>()
            .difference(&owned_rights_structure.keys().collect())
            .for_each(|assignment_type_id| {
                status.add_failure(validation::Failure::SchemaUnknownOwnedRightType(
                    node_id,
                    **assignment_type_id,
                ));
            });

        for (owned_type_id, occ) in owned_rights_structure {
            let len = owned_rights
                .get(owned_type_id)
                .map(TypedAssignments::len)
                .unwrap_or(0);

            // Checking number of assignment occurrences
            if let Err(err) = occ.check(len as u16) {
                status.add_failure(validation::Failure::SchemaOwnedRightOccurrencesError(
                    node_id,
                    *owned_type_id,
                    err,
                ));
            }

            let assignment = &self.owned_right_types.get(owned_type_id).expect(
                "If the assignment were absent, the schema would not be able to pass the internal \
                 validation and we would not reach this point",
            );

            match owned_rights.get(owned_type_id) {
                None => {}
                Some(TypedAssignments::Void(set)) => set
                    .iter()
                    .for_each(|data| status += assignment.validate(&node_id, *owned_type_id, data)),
                Some(TypedAssignments::Value(set)) => set
                    .iter()
                    .for_each(|data| status += assignment.validate(&node_id, *owned_type_id, data)),
                Some(TypedAssignments::Data(set)) => set
                    .iter()
                    .for_each(|data| status += assignment.validate(&node_id, *owned_type_id, data)),
                Some(TypedAssignments::Attachment(set)) => set
                    .iter()
                    .for_each(|data| status += assignment.validate(&node_id, *owned_type_id, data)),
            };
        }

        status
    }

    fn validate_public_rights(
        &self,
        node_id: NodeId,
        public_rights: &PublicRights,
        public_rights_structure: &PublicRightsStructure,
    ) -> validation::Status {
        let mut status = validation::Status::new();

        public_rights
            .difference(public_rights_structure)
            .for_each(|public_type_id| {
                status.add_failure(validation::Failure::SchemaUnknownPublicRightType(
                    node_id,
                    *public_type_id,
                ));
            });

        status
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_state_evolution(
        &self,
        node_id: NodeId,
        node_subtype: NodeSubtype,
        parent_owned_rights: &OwnedRights,
        owned_rights: &OwnedRights,
        parent_public_rights: &PublicRights,
        public_rights: &PublicRights,
        metadata: &Metadata,
        script: &Script,
    ) -> validation::Status {
        let mut status = validation::Status::new();

        // We do not validate public rights, since they do not have an
        // associated state and there is nothing to validate beyond schema

        let vm = match script {
            Script::AluVM(lib) => Box::new(AluRuntime::new(lib)) as Box<dyn VirtualMachine>,
        };

        if let Err(err) = vm.validate(
            node_id,
            node_subtype,
            parent_owned_rights,
            owned_rights,
            parent_public_rights,
            public_rights,
            metadata,
        ) {
            status.add_failure(err);
        }

        status
    }
}

fn extract_parent_owned_rights(
    nodes: &BTreeMap<NodeId, &dyn Node>,
    parent_owned_rights: &ParentOwnedRights,
    status: &mut validation::Status,
) -> OwnedRights {
    let mut owned_rights = bmap! {};
    for (id, details) in parent_owned_rights.iter() {
        let parent_node = match nodes.get(id) {
            None => {
                status.add_failure(validation::Failure::TransitionAbsent(*id));
                continue;
            }
            Some(node) => node,
        };

        fn filter<STATE>(set: &[Assignment<STATE>], indexes: &[u16]) -> Vec<Assignment<STATE>>
        where
            STATE: State + Clone,
            STATE::Confidential: PartialEq + Eq,
            STATE::Confidential: From<<STATE::Revealed as Conceal>::Concealed>,
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

        for (type_id, indexes) in details {
            match parent_node.owned_rights_by_type(*type_id) {
                Some(TypedAssignments::Void(set)) => {
                    let set = filter(set, indexes);
                    if let Some(state) = owned_rights
                        .entry(*type_id)
                        .or_insert_with(|| TypedAssignments::Void(Default::default()))
                        .as_declarative_assignments_mut()
                    {
                        state.extend(set).expect("same size");
                    }
                }
                Some(TypedAssignments::Value(set)) => {
                    let set = filter(set, indexes);
                    if let Some(state) = owned_rights
                        .entry(*type_id)
                        .or_insert_with(|| TypedAssignments::Value(Default::default()))
                        .as_value_assignments_mut()
                    {
                        state.extend(set).expect("same size");
                    }
                }
                Some(TypedAssignments::Data(set)) => {
                    let set = filter(set, indexes);
                    if let Some(state) = owned_rights
                        .entry(*type_id)
                        .or_insert_with(|| TypedAssignments::Data(Default::default()))
                        .as_data_assignments_mut()
                    {
                        state.extend(set).expect("same size");
                    }
                }
                Some(TypedAssignments::Attachment(set)) => {
                    let set = filter(set, indexes);
                    if let Some(state) = owned_rights
                        .entry(*type_id)
                        .or_insert_with(|| TypedAssignments::Attachment(Default::default()))
                        .as_attachment_assignments_mut()
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
    Confined::try_from(owned_rights)
        .expect("collections is assembled from another collection with the same size requirements")
}

fn extract_parent_public_rights(
    nodes: &BTreeMap<NodeId, &dyn Node>,
    parent_public_rights: &ParentPublicRights,
    status: &mut validation::Status,
) -> PublicRights {
    let mut public_rights = PublicRights::default();
    for (id, public_right_types) in parent_public_rights.iter() {
        if nodes.get(id).is_none() {
            status.add_failure(validation::Failure::TransitionAbsent(*id));
        } else {
            public_rights
                .extend(public_right_types.iter().copied())
                .expect("same size");
        }
    }
    public_rights
}

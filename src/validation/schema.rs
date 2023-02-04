/// Trait used for internal schema validation against some root schema
pub trait SchemaVerify {
    fn schema_verify(&self, root: &Self) -> crate::validation::Status;
}

mod _verify {
    use super::*;
    use crate::schema::SchemaVerify;
    use crate::validation;

    impl<T> SchemaVerify for T
    where T: NodeSchema
    {
        fn schema_verify(&self, root: &Self) -> validation::Status {
            let mut status = validation::Status::new();
            let node_type = self.node_type();

            for (field_type, occ) in self.metadata() {
                match root.metadata().get(field_type) {
                    None => status.add_failure(validation::Failure::SchemaRootNoMetadataMatch(
                        node_type,
                        *field_type,
                    )),
                    Some(root_occ) if occ != root_occ => status.add_failure(
                        validation::Failure::SchemaRootNoMetadataMatch(node_type, *field_type),
                    ),
                    _ => &status,
                };
            }

            for (assignments_type, occ) in self.closes() {
                match root.closes().get(assignments_type) {
                    None => {
                        status.add_failure(validation::Failure::SchemaRootNoParentOwnedRightsMatch(
                            node_type,
                            *assignments_type,
                        ))
                    }
                    Some(root_occ) if occ != root_occ => {
                        status.add_failure(validation::Failure::SchemaRootNoParentOwnedRightsMatch(
                            node_type,
                            *assignments_type,
                        ))
                    }
                    _ => &status,
                };
            }

            for (assignments_type, occ) in self.owned_rights() {
                match root.owned_rights().get(assignments_type) {
                    None => status.add_failure(validation::Failure::SchemaRootNoOwnedRightsMatch(
                        node_type,
                        *assignments_type,
                    )),
                    Some(root_occ) if occ != root_occ => {
                        status.add_failure(validation::Failure::SchemaRootNoOwnedRightsMatch(
                            node_type,
                            *assignments_type,
                        ))
                    }
                    _ => &status,
                };
            }

            for valencies_type in self.extends() {
                if !root.extends().contains(valencies_type) {
                    status.add_failure(validation::Failure::SchemaRootNoParentPublicRightsMatch(
                        node_type,
                        *valencies_type,
                    ));
                }
            }

            for valencies_type in self.public_rights() {
                if !root.public_rights().contains(valencies_type) {
                    status.add_failure(validation::Failure::SchemaRootNoPublicRightsMatch(
                        node_type,
                        *valencies_type,
                    ));
                }
            }

            status
        }
    }
}

// TODO #73: Move to validation module and refactor that module into a directory
mod _validation {
    use std::collections::BTreeSet;

    use super::*;
    use crate::schema::{
        MetadataStructure, OwnedRightsStructure, PublicRightsStructure, SchemaVerify,
    };
    use crate::script::{OverrideRules, ValidationScript};
    use crate::vm::Validate;
    use crate::{
        validation, Assignment, Metadata, Node, NodeId, NodeSubtype, OwnedRights,
        ParentOwnedRights, ParentPublicRights, PublicRights, State, TypedAssignments,
    };

    impl SchemaVerify for Schema {
        fn schema_verify(&self, root: &Schema) -> validation::Status {
            let mut status = validation::Status::new();

            if root.root_id != SchemaId::default() {
                status.add_failure(validation::Failure::SchemaRootHierarchy(root.root_id));
            }

            for (field_type, data_format) in &self.field_types {
                match root.field_types.get(field_type) {
                    None => status
                        .add_failure(validation::Failure::SchemaRootNoFieldTypeMatch(*field_type)),
                    Some(root_data_format) if root_data_format != data_format => status
                        .add_failure(validation::Failure::SchemaRootNoFieldTypeMatch(*field_type)),
                    _ => &status,
                };
            }

            for (assignments_type, state_schema) in &self.owned_right_types {
                match root.owned_right_types.get(assignments_type) {
                    None => status.add_failure(
                        validation::Failure::SchemaRootNoOwnedRightTypeMatch(*assignments_type),
                    ),
                    Some(root_state_schema) if root_state_schema != state_schema => status
                        .add_failure(validation::Failure::SchemaRootNoOwnedRightTypeMatch(
                            *assignments_type,
                        )),
                    _ => &status,
                };
            }

            for valencies_type in &self.public_right_types {
                match root.public_right_types.contains(valencies_type) {
                    false => status.add_failure(
                        validation::Failure::SchemaRootNoPublicRightTypeMatch(*valencies_type),
                    ),
                    _ => &status,
                };
            }

            status += self.genesis.schema_verify(&root.genesis);

            for (transition_type, transition_schema) in &self.transitions {
                if let Some(root_transition_schema) = root.transitions.get(transition_type) {
                    status += transition_schema.schema_verify(root_transition_schema);
                } else {
                    status.add_failure(validation::Failure::SchemaRootNoTransitionTypeMatch(
                        *transition_type,
                    ));
                }
            }
            for (extension_type, extension_schema) in &self.extensions {
                if let Some(root_extension_schema) = root.extensions.get(extension_type) {
                    status += extension_schema.schema_verify(root_extension_schema);
                } else {
                    status.add_failure(validation::Failure::SchemaRootNoExtensionTypeMatch(
                        *extension_type,
                    ));
                }
            }

            match (root.override_rules, self.override_rules) {
                (OverrideRules::Deny, _) if root.script != self.script => {
                    status.add_failure(validation::Failure::SchemaScriptOverrideDenied);
                }
                (OverrideRules::AllowSameVm, _)
                    if root.script.vm_type() != self.script.vm_type() =>
                {
                    status.add_failure(validation::Failure::SchemaScriptVmChangeDenied);
                }
                _ => {} // We are fine here
            }

            status
        }
    }

    impl Schema {
        pub fn validate(
            &self,
            all_nodes: &BTreeMap<NodeId, &dyn Node>,
            node: &dyn Node,
            script: &ValidationScript,
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
                            )
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
                            )
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
            status +=
                self.validate_owned_rights(node_id, node.owned_rights(), assignments_structure);
            status +=
                self.validate_public_rights(node_id, node.public_rights(), valencies_structure);
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
                    status.add_failure(validation::Failure::SchemaUnknownFieldType(
                        node_id, **field_id,
                    ));
                });

            for (field_type_id, occ) in metadata_structure {
                let set = metadata.get(field_type_id).cloned().unwrap_or_default();

                // Checking number of field occurrences
                if let Err(err) = occ.check(set.len() as u16) {
                    status.add_failure(validation::Failure::SchemaMetaOccurrencesError(
                        node_id,
                        *field_type_id,
                        err,
                    ));
                }

                let _field = self.field_types.get(field_type_id)
                    .expect("If the field were absent, the schema would not be able to pass the internal validation and we would not reach this point");
                for _data in set {
                    // TODO: Run strict type validation
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
                    status.add_failure(
                        validation::Failure::SchemaParentOwnedRightOccurrencesError(
                            node_id,
                            *owned_type_id,
                            err,
                        ),
                    );
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

                let assignment = &self
                    .owned_right_types
                    .get(owned_type_id)
                    .expect("If the assignment were absent, the schema would not be able to pass the internal validation and we would not reach this point");

                match owned_rights.get(owned_type_id) {
                    None => {}
                    Some(TypedAssignments::Void(set)) => set.iter().for_each(|data| {
                        status += assignment.validate(&node_id, *owned_type_id, data)
                    }),
                    Some(TypedAssignments::Value(set)) => set.iter().for_each(|data| {
                        status += assignment.validate(&node_id, *owned_type_id, data)
                    }),
                    Some(TypedAssignments::Data(set)) => set.iter().for_each(|data| {
                        status += assignment.validate(&node_id, *owned_type_id, data)
                    }),
                    Some(TypedAssignments::Attachment(set)) => set.iter().for_each(|data| {
                        status += assignment.validate(&node_id, *owned_type_id, data)
                    }),
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
            script: &ValidationScript,
        ) -> validation::Status {
            let mut status = validation::Status::new();

            // We do not validate public rights, since they do not have an
            // associated state and there is nothing to validate beyond schema

            if let Err(err) = script.validate(
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
        let mut owned_rights = OwnedRights::default();
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
                STATE::Confidential: From<<STATE::Revealed as CommitConceal>::ConcealedCommitment>,
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
                            .declarative_assignments_mut()
                        {
                            state.extend(set);
                        }
                    }
                    Some(TypedAssignments::Value(set)) => {
                        let set = filter(set, indexes);
                        if let Some(state) = owned_rights
                            .entry(*type_id)
                            .or_insert_with(|| TypedAssignments::Value(Default::default()))
                            .value_assignments_mut()
                        {
                            state.extend(set);
                        }
                    }
                    Some(TypedAssignments::Data(set)) => {
                        let set = filter(set, indexes);
                        if let Some(state) = owned_rights
                            .entry(*type_id)
                            .or_insert_with(|| TypedAssignments::Data(Default::default()))
                            .data_assignments_mut()
                        {
                            state.extend(set);
                        }
                    }
                    Some(TypedAssignments::Attachment(set)) => {
                        let set = filter(set, indexes);
                        if let Some(state) = owned_rights
                            .entry(*type_id)
                            .or_insert_with(|| TypedAssignments::Attachment(Default::default()))
                            .attachment_assignments_mut()
                        {
                            state.extend(set);
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
        owned_rights
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
                public_rights.extend(public_right_types);
            }
        }
        public_rights
    }
}

mod _validation {
    use core::any::Any;

    use amplify::AsAny;

    use super::*;
    use crate::contract::AttachmentStrategy;
    use crate::schema::OwnedRightType;
    use crate::{
        validation, Assignment, DeclarativeStrategy, HashStrategy, NodeId, PedersenStrategy, State,
    };

    impl StateSchema {
        pub fn validate<STATE>(
            &self,
            // type_system: &TypeSystem,
            node_id: &NodeId,
            assignment_id: OwnedRightType,
            data: &Assignment<STATE>,
        ) -> validation::Status
        where
            STATE: State,
            STATE::Confidential: PartialEq + Eq,
            STATE::Confidential: From<<STATE::Revealed as CommitConceal>::ConcealedCommitment>,
        {
            let mut status = validation::Status::new();
            match data {
                Assignment::Confidential { state, .. }
                | Assignment::ConfidentialState { state, .. } => {
                    let a: &dyn Any = state.as_any();
                    match self {
                        StateSchema::Declarative => {
                            if a.downcast_ref::<<DeclarativeStrategy as State>::Confidential>()
                                .is_none()
                            {
                                status.add_failure(validation::Failure::SchemaMismatchedStateType(
                                    assignment_id,
                                ));
                            }
                        }
                        StateSchema::DiscreteFiniteField(_) => {
                            if let Some(value) =
                                a.downcast_ref::<<PedersenStrategy as State>::Confidential>()
                            {
                                // [SECURITY-CRITICAL]: Bulletproofs validation
                                if let Err(err) = value.verify_bullet_proof() {
                                    status.add_failure(validation::Failure::InvalidBulletproofs(
                                        *node_id,
                                        assignment_id,
                                        err.to_string(),
                                    ));
                                }
                            } else {
                                status.add_failure(validation::Failure::SchemaMismatchedStateType(
                                    assignment_id,
                                ));
                            }

                            // TODO: When other homomorphic formats will be added,
                            //       add information to the status like with
                            //       hashed data below
                        }
                        StateSchema::CustomData() => {
                            match a.downcast_ref::<<HashStrategy as State>::Confidential>() {
                                None => {
                                    status.add_failure(
                                        validation::Failure::SchemaMismatchedStateType(
                                            assignment_id,
                                        ),
                                    );
                                }
                                Some(_) => {
                                    status.add_info(
                                        validation::Info::UncheckableConfidentialStateData(
                                            *node_id,
                                            assignment_id,
                                        ),
                                    );
                                }
                            }
                        }
                        StateSchema::DataContainer => {
                            if a.downcast_ref::<<AttachmentStrategy as State>::Confidential>()
                                .is_none()
                            {
                                status.add_failure(validation::Failure::SchemaMismatchedStateType(
                                    assignment_id,
                                ));
                            }
                        }
                    }
                }
                Assignment::Revealed { state, .. } | Assignment::ConfidentialSeal { state, .. } => {
                    let a: &dyn Any = state.as_any();
                    match self {
                        StateSchema::Declarative => {
                            if a.downcast_ref::<<DeclarativeStrategy as State>::Revealed>()
                                .is_none()
                            {
                                status.add_failure(validation::Failure::SchemaMismatchedStateType(
                                    assignment_id,
                                ));
                            }
                        }
                        StateSchema::DiscreteFiniteField(_format) => {
                            if a.downcast_ref::<<PedersenStrategy as State>::Revealed>()
                                .is_none()
                            {
                                status.add_failure(validation::Failure::SchemaMismatchedStateType(
                                    assignment_id,
                                ));
                            }
                            // TODO #15: When other homomorphic formats will be added,
                            //       add type check like with hashed data below
                        }
                        StateSchema::CustomData(/*format*/) => {
                            match a.downcast_ref::<<HashStrategy as State>::Revealed>() {
                                None => {
                                    status.add_failure(
                                        validation::Failure::SchemaMismatchedStateType(
                                            assignment_id,
                                        ),
                                    );
                                }
                                Some(_data) => {
                                    // TODO: run strict type validation
                                }
                            }
                        }
                        StateSchema::DataContainer => {
                            if a.downcast_ref::<<AttachmentStrategy as State>::Revealed>()
                                .is_none()
                            {
                                status.add_failure(validation::Failure::SchemaMismatchedStateType(
                                    assignment_id,
                                ));
                            }
                        }
                    }
                }
            }
            status
        }
    }
}

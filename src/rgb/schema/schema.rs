// LNP/BP Rust Library
// Written in 2020 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the MIT License
// along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

use std::collections::BTreeMap;
use std::io;

use bitcoin::hashes::{sha256t, Hash};

use super::{AssignmentsType, DataFormat, GenesisSchema, StateSchema, TransitionSchema};
use crate::client_side_validation::{commit_strategy, CommitEncodeWithStrategy, ConsensusCommit};

pub type FieldType = usize; // Here we can use usize since encoding/decoding makes sure that it's u16
pub type TransitionType = usize; // Here we can use usize since encoding/decoding makes sure that it's u16

static MIDSTATE_SHEMA_ID: [u8; 32] = [
    25, 205, 224, 91, 171, 217, 131, 31, 140, 104, 5, 155, 127, 82, 14, 81, 58, 245, 79, 165, 114,
    243, 110, 60, 133, 174, 103, 187, 103, 230, 9, 106,
];

tagged_hash!(
    SchemaId,
    SchemaIdTag,
    MIDSTATE_SHEMA_ID,
    doc = "Commitment-based schema identifier used for committing to the schema type"
);

#[derive(Clone, Debug)]
pub struct Schema {
    pub field_types: BTreeMap<FieldType, DataFormat>,
    pub assignment_types: BTreeMap<AssignmentsType, StateSchema>,
    pub genesis: GenesisSchema,
    pub transitions: BTreeMap<TransitionType, TransitionSchema>,
}

impl Schema {
    #[inline]
    pub fn schema_id(&self) -> SchemaId {
        self.clone().consensus_commit()
    }
}

impl ConsensusCommit for Schema {
    type Commitment = SchemaId;
}
impl CommitEncodeWithStrategy for Schema {
    type Strategy = commit_strategy::UsingStrict;
}

mod strict_encoding {
    use super::*;
    use crate::strict_encoding::{Error, StrictDecode, StrictEncode};
    use bitcoin::hashes::Hash;

    // TODO: Use derive macros and generalized `tagged_hash!` in the future
    impl StrictEncode for SchemaId {
        type Error = Error;

        #[inline]
        fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Self::Error> {
            self.into_inner().to_vec().strict_encode(e)
        }
    }

    impl StrictDecode for SchemaId {
        type Error = Error;

        #[inline]
        fn strict_decode<D: io::Read>(d: D) -> Result<Self, Self::Error> {
            Ok(
                Self::from_slice(&Vec::<u8>::strict_decode(d)?).map_err(|_| {
                    Error::DataIntegrityError("Wrong SHA-256 hash data size".to_string())
                })?,
            )
        }
    }

    impl StrictEncode for Schema {
        type Error = Error;

        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
            Ok(strict_encode_list!(e;
                self.field_types,
                self.assignment_types,
                self.genesis,
                self.transitions,
                // We keep this parameter for future script extended info (like ABI)
                Vec::<u8>::new()
            ))
        }
    }

    impl StrictDecode for Schema {
        type Error = Error;

        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
            let me = Self {
                field_types: BTreeMap::strict_decode(&mut d)?,
                assignment_types: BTreeMap::strict_decode(&mut d)?,
                genesis: GenesisSchema::strict_decode(&mut d)?,
                transitions: BTreeMap::strict_decode(&mut d)?,
            };
            // We keep this parameter for future script extended info (like ABI)
            let script = Vec::<u8>::strict_decode(&mut d)?;
            if !script.is_empty() {
                Err(Error::UnsupportedDataStructure(
                    "Scripting information is not yet supported".to_string(),
                ))
            } else {
                Ok(me)
            }
        }
    }
}

mod _validation {
    use super::*;

    use core::convert::TryFrom;
    use std::collections::BTreeSet;

    use crate::rgb::schema::{MetadataStructure, SealsStructure};
    use crate::rgb::{
        validation, Ancestors, Assignments, AssignmentsVariant, Metadata, Node, NodeId,
    };

    impl Schema {
        pub fn validate(
            &self,
            nodes: &BTreeMap<NodeId, &dyn Node>,
            node: &dyn Node,
            ancestors: &Ancestors,
        ) -> validation::Status {
            let node_id = node.node_id();
            let type_id = node.type_id();

            let empty_seals_structure = SealsStructure::default();
            let (metadata_structure, ancestors_structure, assignments_structure) = match type_id {
                None => (
                    &self.genesis.metadata,
                    &empty_seals_structure,
                    &self.genesis.defines,
                ),
                Some(type_id) => {
                    let transition_type = match self.transitions.get(&type_id) {
                        None => {
                            return validation::Status::with_failure(
                                validation::Failure::SchemaUnknownTransitionType(node_id, type_id),
                            )
                        }
                        Some(transition_type) => transition_type,
                    };

                    (
                        &transition_type.metadata,
                        &transition_type.closes,
                        &transition_type.defines,
                    )
                }
            };

            let mut status = validation::Status::new();
            let ancestor_assignments =
                extract_ancestor_assignments(nodes, node_id, ancestors, &mut status);
            status += self.validate_meta(node_id, node.metadata(), metadata_structure);
            status += self.validate_ancestors(node_id, &ancestor_assignments, ancestors_structure);
            status += self.validate_assignments(node_id, node.assignments(), assignments_structure);
            //status += self.validate_scripts(node_id, node.script(), script_structure);
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
                let set = metadata.get(field_type_id).cloned().unwrap_or(bset!());

                // Checking number of field occurrences
                if let Err(err) = occ.check(set.len() as u128) {
                    status.add_failure(validation::Failure::SchemaMetaOccurencesError(
                        node_id,
                        *field_type_id,
                        err,
                    ));
                }

                let field = self.field_types.get(field_type_id)
                    .expect("If the field were absent, the schema would not be able to pass the internal validation and we would not reach this point");
                for data in set {
                    status += field.validate(*field_type_id, &data);
                }
            }

            status
        }

        fn validate_ancestors(
            &self,
            node_id: NodeId,
            assignments: &Assignments,
            assignments_structure: &SealsStructure,
        ) -> validation::Status {
            let mut status = validation::Status::new();

            assignments
                .keys()
                .collect::<BTreeSet<_>>()
                .difference(&assignments_structure.keys().collect())
                .for_each(|assignment_type_id| {
                    status.add_failure(validation::Failure::SchemaUnknownAssignmentType(
                        node_id,
                        **assignment_type_id,
                    ));
                });

            for (assignment_type_id, occ) in assignments_structure {
                let len = assignments
                    .get(assignment_type_id)
                    .map(AssignmentsVariant::len)
                    .unwrap_or(0);

                // Checking number of ancestor's assignment occurrences
                if let Err(err) = occ.check(len as u128) {
                    status.add_failure(validation::Failure::SchemaAncestorsOccurencesError(
                        node_id,
                        *assignment_type_id,
                        err,
                    ));
                }
            }

            status
        }

        fn validate_assignments(
            &self,
            node_id: NodeId,
            assignments: &Assignments,
            assignments_structure: &SealsStructure,
        ) -> validation::Status {
            let mut status = validation::Status::new();

            assignments
                .keys()
                .collect::<BTreeSet<_>>()
                .difference(&assignments_structure.keys().collect())
                .for_each(|assignment_type_id| {
                    status.add_failure(validation::Failure::SchemaUnknownAssignmentType(
                        node_id,
                        **assignment_type_id,
                    ));
                });

            for (assignment_type_id, occ) in assignments_structure {
                let len = assignments
                    .get(assignment_type_id)
                    .map(AssignmentsVariant::len)
                    .unwrap_or(0);

                // Checking number of assignment occurrences
                if let Err(err) = occ.check(len as u128) {
                    status.add_failure(validation::Failure::SchemaSealsOccurencesError(
                        node_id,
                        *assignment_type_id,
                        err,
                    ));
                }

                let assignment = &self
                    .assignment_types
                    .get(assignment_type_id)
                    .expect("If the assignment were absent, the schema would not be able to pass the internal validation and we would not reach this point")
                    .format;

                match assignments.get(assignment_type_id) {
                    None => {}
                    Some(AssignmentsVariant::Declarative(set)) => {
                        set.into_iter().for_each(|data| {
                            status += assignment.validate(&node_id, *assignment_type_id, data)
                        })
                    }
                    Some(AssignmentsVariant::Field(set)) => set.into_iter().for_each(|data| {
                        status += assignment.validate(&node_id, *assignment_type_id, data)
                    }),
                    Some(AssignmentsVariant::Data(set)) => set.into_iter().for_each(|data| {
                        status += assignment.validate(&node_id, *assignment_type_id, data)
                    }),
                };
            }

            status
        }

        /*
        fn validate_scripts(
            &self,
            node_id: NodeId,
            script: &SimplicityScript,
            _script_structure: &AssignmentAbi,
        ) -> validation::Status {
            let mut status = validation::Status::new();

            if self.script_extensions == script::Extensions::ScriptsDenied {
                if script.len() > 0 {
                    status.add_failure(validation::Failure::SchemaDeniedScriptExtension(node_id));
                }
            }

                // TODO: Add other types of script checks when Simplicity scripting
                //       will be ready

                status
            }
         */

        /*
        fn validate_state(
            &self,
            node_id: NodeId,
            previous_state: Assignments,
            current_state: Assignments,
            previous_meta: Metadata,
            current_meta: Metadata,
            code: SimplicityScript,
            procedure: u32,
        ) -> validation::Status {
            let assignment_types: BTreeSet<AssignmentsType> =
                previous_state.keys().chain(current_state.keys()).collect();

            let mut status = validation::Status::new();
            for assignment_type in assignment_types {
                let mut vm = VirtualMachine::new();
                vm.push_stack(previous_state.get(&assignment_type).cloned());
                vm.push_stack(current_state.get(&assignment_type).cloned());
                vm.push_stack(previous_meta.clone());
                vm.push_stack(current_meta.clone());
                match vm.execute(code.clone(), offset) {
                    Err(_) => {}
                    Ok => match vm.pop_stack() {
                        None => {}
                        Some(value) => {}
                    },
                }
            }

            status
        }
         */
    }

    fn extract_ancestor_assignments(
        nodes: &BTreeMap<NodeId, &dyn Node>,
        node_id: NodeId,
        ancestors: &Ancestors,
        status: &mut validation::Status,
    ) -> Assignments {
        let mut ancestors_assignments = Assignments::new();
        for (id, details) in ancestors {
            let node = match nodes.get(id) {
                None => {
                    status.add_failure(validation::Failure::TransitionAbsent(*id));
                    continue;
                }
                Some(node) => node,
            };

            for (type_id, assignment_indexes) in details {
                let variants: Vec<&AssignmentsVariant> = node
                    .assignments_by_type(*type_id)
                    .into_iter()
                    .enumerate()
                    .filter_map(|(index, v)| {
                        if assignment_indexes.contains(&u16::try_from(index).expect(
                            "All collection sizes in RGB are 160bit integers; \
                                so this can only fail if RGB consensus code is broken",
                        )) {
                            Some(v)
                        } else {
                            None
                        }
                    })
                    .collect();

                for variant in variants {
                    match variant {
                        AssignmentsVariant::Declarative(set) => {
                            match ancestors_assignments
                                .entry(*type_id)
                                .or_insert(AssignmentsVariant::Declarative(bset! {}))
                                .declarative_mut()
                            {
                                Some(base) => {
                                    base.extend(set.clone());
                                }
                                None => {
                                    status.add_warning(
                                        validation::Warning::AncestorsHeterogenousAssignments(
                                            node_id, *type_id,
                                        ),
                                    );
                                }
                            };
                        }
                        AssignmentsVariant::Field(set) => {
                            match ancestors_assignments
                                .entry(*type_id)
                                .or_insert(AssignmentsVariant::Field(bset! {}))
                                .field_mut()
                            {
                                Some(base) => {
                                    base.extend(set.clone());
                                }
                                None => {
                                    status.add_warning(
                                        validation::Warning::AncestorsHeterogenousAssignments(
                                            node_id, *type_id,
                                        ),
                                    );
                                }
                            };
                        }
                        AssignmentsVariant::Data(set) => {
                            match ancestors_assignments
                                .entry(*type_id)
                                .or_insert(AssignmentsVariant::Data(bset! {}))
                                .data_mut()
                            {
                                Some(base) => {
                                    base.extend(set.clone());
                                }
                                None => {
                                    status.add_warning(
                                        validation::Warning::AncestorsHeterogenousAssignments(
                                            node_id, *type_id,
                                        ),
                                    );
                                }
                            };
                        }
                    };
                }
            }
        }
        ancestors_assignments
    }
}

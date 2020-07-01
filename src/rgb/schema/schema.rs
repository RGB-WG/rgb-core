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

use super::{
    script, AssignmentsType, DataFormat, GenesisSchema, SimplicityScript, StateFormat,
    TransitionSchema,
};
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
    pub assignment_types: BTreeMap<AssignmentsType, StateFormat>,
    pub genesis: GenesisSchema,
    pub transitions: BTreeMap<TransitionType, TransitionSchema>,
    pub script_library: SimplicityScript,
    pub script_extensions: script::Extensions,
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
                self.script_library,
                self.script_extensions
            ))
        }
    }

    impl StrictDecode for Schema {
        type Error = Error;

        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
            Ok(Self {
                field_types: BTreeMap::strict_decode(&mut d)?,
                assignment_types: BTreeMap::strict_decode(&mut d)?,
                genesis: GenesisSchema::strict_decode(&mut d)?,
                transitions: BTreeMap::strict_decode(&mut d)?,
                script_library: Vec::strict_decode(&mut d)?,
                script_extensions: script::Extensions::strict_decode(&mut d)?,
            })
        }
    }
}

mod _validation {
    use super::*;

    use std::collections::BTreeSet;

    use crate::rgb::schema::{MetadataStructure, Scripting, SealsStructure};
    use crate::rgb::{validation, AssignmentsVariant};
    use crate::rgb::{Assignments, Metadata, Node, NodeId, SimplicityScript};

    impl Schema {
        pub fn validate(&self, node: &dyn Node) -> validation::Status {
            let node_id = node.node_id();
            let type_id = node.type_id();

            let (metadata_structure, assignments_structure, script_structure) = match node.type_id()
            {
                None => (
                    &self.genesis.metadata,
                    &self.genesis.defines,
                    &self.genesis.scripting,
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
                        &transition_type.defines,
                        &transition_type.scripting,
                    )
                }
            };

            let mut status =
                self.validate_meta(node_id, type_id, node.metadata(), metadata_structure);
            status += self.validate_assignments(
                node_id,
                type_id,
                node.assignments(),
                assignments_structure,
            );
            status += self.validate_scripts(node_id, node.script(), script_structure);
            status
        }

        // TODO: Improve this and the next function by putting shared parts
        //       into a separate fn
        fn validate_meta(
            &self,
            node_id: NodeId,
            type_id: Option<TransitionType>,
            metadata: &Metadata,
            metadata_structure: &MetadataStructure,
        ) -> validation::Status {
            let mut status = metadata
                .keys()
                .collect::<BTreeSet<_>>()
                .difference(&metadata_structure.keys().collect())
                .map(|field_id| {
                    validation::Failure::SchemaUnknownFieldType(node_id, type_id, **field_id)
                })
                .collect();

            metadata_structure.into_iter().for_each(|(field_id, occ)| {
                let set = metadata.get(field_id).cloned().unwrap_or(bset!());
                match (set.len(), occ.min_value() as usize, occ.max_value() as usize) {
                    (0, 0, _) => {}
                    (0, min, _) if min > 0 => {}
                    (len, min, _) if len < min => {}
                    (len, _, max) if len > max => {}
                    _ => {}
                };

                let field = self.field_types.get(field_id)
                    .expect("If the field were absent, the schema would not be able to pass the internal validation and we would not reach this point");
                for data in set {
                    status += field.validate(*field_id, &data);
                }
            });

            status
        }

        fn validate_assignments(
            &self,
            node_id: NodeId,
            type_id: Option<TransitionType>,
            assignments: &Assignments,
            assignments_structure: &SealsStructure,
        ) -> validation::Status {
            let mut status = assignments
                .keys()
                .collect::<BTreeSet<_>>()
                .difference(&assignments_structure.keys().collect())
                .map(|assignment_id| {
                    validation::Failure::SchemaUnknownAssignmentType(
                        node_id,
                        type_id,
                        **assignment_id,
                    )
                })
                .collect();

            assignments_structure.into_iter().for_each(|(assignment_id, occ)| {
                let len = match assignments.get(assignment_id) {
                    None => 0,
                    Some(AssignmentsVariant::Void(set)) => set.len(),
                    Some(AssignmentsVariant::PedersenBased(set)) => set.len(),
                    Some(AssignmentsVariant::HashBased(set)) => set.len(),
                };

                match (len, occ.min_value() as usize, occ.max_value() as usize) {
                    (0, 0, _) => {}
                    (0, min, _) if min > 0 => {}
                    (len, min, _) if len < min => {}
                    (len, _, max) if len > max => {}
                    _ => {}
                };

                let assignment = self.assignment_types.get(assignment_id)
                    .expect("If the assignment were absent, the schema would not be able to pass the internal validation and we would not reach this point");

                match assignments.get(assignment_id) {
                    None => {},
                    Some(AssignmentsVariant::Void(set)) =>
                        set.into_iter().for_each(|data| status += assignment.validate(&node_id, *assignment_id, data)),
                    Some(AssignmentsVariant::PedersenBased(set)) =>
                        set.into_iter().for_each(|data| status += assignment.validate(&node_id, *assignment_id, data)),
                    Some(AssignmentsVariant::HashBased(set)) =>
                        set.into_iter().for_each(|data| status += assignment.validate(&node_id, *assignment_id, data)),
                };
            });

            status
        }

        fn validate_scripts(
            &self,
            node_id: NodeId,
            script: &SimplicityScript,
            _script_structure: &Scripting,
        ) -> validation::Status {
            let mut status = validation::Status::default();

            if self.script_extensions == script::Extensions::ScriptsDenied {
                if script.len() > 0 {
                    status.add_failure(validation::Failure::SchemaDeniedScriptExtension(node_id));
                }
            }

            // TODO: Add other types of script checks when Simplicity scripting
            //       will be ready

            status
        }
    }
}

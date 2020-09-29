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

use std::collections::{BTreeMap, BTreeSet};
use std::io;

use bitcoin::hashes::{sha256, sha256t, Hash, HashEngine};

use super::{
    vm, AssignmentsType, DataFormat, ExtensionSchema, GenesisSchema, SimplicityScript, StateSchema,
    TransitionSchema,
};
use crate::client_side_validation::{commit_strategy, CommitEncodeWithStrategy, ConsensusCommit};
use crate::rgb::schema::ValenciesType;

// Here we can use usize since encoding/decoding makes sure that it's u16
pub type FieldType = usize;
pub type ExtensionType = usize;
pub type TransitionType = usize;

lazy_static! {
    static ref MIDSTATE_SHEMA_ID: [u8; 32] = {
        let hash = sha256::Hash::hash(b"rgb:schema");
        let mut engine = sha256::Hash::engine();
        engine.input(&hash[..]);
        engine.input(&hash[..]);
        engine.midstate().0
    };
}

tagged_hash!(
    SchemaId,
    SchemaIdTag,
    MIDSTATE_SHEMA_ID,
    doc = "Commitment-based schema identifier used for committing to the schema type"
);

#[derive(Clone, PartialEq, Debug)]
pub struct Schema {
    pub field_types: BTreeMap<FieldType, DataFormat>,
    pub assignment_types: BTreeMap<AssignmentsType, StateSchema>,
    pub valencies_types: BTreeSet<ValenciesType>,
    pub genesis: GenesisSchema,
    pub extensions: BTreeMap<ExtensionType, ExtensionSchema>,
    pub transitions: BTreeMap<TransitionType, TransitionSchema>,
}

impl Schema {
    #[inline]
    pub fn schema_id(&self) -> SchemaId {
        self.clone().consensus_commit()
    }

    // TODO: Change with the adoption of Simplicity
    #[inline]
    pub fn scripts(&self) -> SimplicityScript {
        vec![]
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
    use crate::strict_encoding::{strategies, Error, Strategy, StrictDecode, StrictEncode};

    // TODO: Use derive macros and generalized `tagged_hash!` in the future
    impl Strategy for SchemaId {
        type Strategy = strategies::HashFixedBytes;
    }

    impl StrictEncode for Schema {
        type Error = Error;

        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
            Ok(strict_encode_list!(e;
                self.field_types,
                self.assignment_types,
                self.valencies_types,
                self.genesis,
                self.extensions,
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
                valencies_types: BTreeSet::strict_decode(&mut d)?,
                genesis: GenesisSchema::strict_decode(&mut d)?,
                extensions: BTreeMap::strict_decode(&mut d)?,
                transitions: BTreeMap::strict_decode(&mut d)?,
            };
            // We keep this parameter for future script extended info (like ABI)
            let script = Vec::<u8>::strict_decode(&mut d)?;
            if !script.is_empty() {
                Err(Error::UnsupportedDataStructure(
                    "Scripting information is not yet supported",
                ))
            } else {
                Ok(me)
            }
        }
    }
}

/// TODO: (new) Add extension validation
mod _validation {
    use super::*;

    use core::convert::TryFrom;
    use std::collections::BTreeSet;

    use crate::rgb::schema::{script, MetadataStructure, SealsStructure};
    use crate::rgb::{
        validation, Ancestors, AssignmentAction, Assignments, AssignmentsVariant, Metadata, Node,
        NodeId, VirtualMachine,
    };

    impl Schema {
        pub fn validate(
            &self,
            all_nodes: &BTreeMap<NodeId, &dyn Node>,
            node: &dyn Node,
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
                extract_ancestor_assignments(all_nodes, node_id, node.ancestors(), &mut status);
            status += self.validate_meta(node_id, node.metadata(), metadata_structure);
            status += self.validate_ancestors(node_id, &ancestor_assignments, ancestors_structure);
            status += self.validate_assignments(node_id, node.assignments(), assignments_structure);
            status += self.validate_state_evolution(
                node_id,
                node.type_id(),
                &ancestor_assignments,
                node.assignments(),
                node.metadata(),
            );
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
                    Some(AssignmentsVariant::DiscreteFiniteField(set)) => {
                        set.into_iter().for_each(|data| {
                            status += assignment.validate(&node_id, *assignment_type_id, data)
                        })
                    }
                    Some(AssignmentsVariant::CustomData(set)) => set.into_iter().for_each(|data| {
                        status += assignment.validate(&node_id, *assignment_type_id, data)
                    }),
                };
            }

            status
        }

        fn validate_state_evolution(
            &self,
            node_id: NodeId,
            transition_type: Option<TransitionType>,
            previous_state: &Assignments,
            current_state: &Assignments,
            current_meta: &Metadata,
        ) -> validation::Status {
            let assignment_types: BTreeSet<&AssignmentsType> =
                previous_state.keys().chain(current_state.keys()).collect();

            let mut status = validation::Status::new();
            for assignment_type in assignment_types {
                let abi = &self
                    .assignment_types
                    .get(&assignment_type)
                    .expect("We already passed assignment type validation, so can be sure that the type exists")
                    .abi;

                // If the procedure is not defined, it means no validation should be performed
                if let Some(procedure) = abi.get(&AssignmentAction::Validate) {
                    match procedure {
                        script::Procedure::Standard(proc) => {
                            let mut vm = vm::Embedded::with(
                                transition_type,
                                previous_state.get(&assignment_type).cloned(),
                                current_state.get(&assignment_type).cloned(),
                                current_meta.clone(),
                            );
                            vm.execute(*proc);
                            match vm.pop_stack().and_then(|x| x.downcast_ref::<u8>().cloned()) {
                                None => panic!("LNP/BP core code is hacked: standard procedure must always return 8-bit value"),
                                Some(0) => {
                                    // Nothing to do here: 0 signifies successful script execution
                                },
                                Some(n) => {
                                    status.add_failure(validation::Failure::ScriptFailure(node_id, n));
                                }
                            }
                        }
                        script::Procedure::Simplicity { .. } => {
                            status.add_failure(validation::Failure::SimplicityIsNotSupportedYet);
                            /* Draft of how this could look like:

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
                             */
                        }
                    }
                }
            }

            status
        }
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
                        AssignmentsVariant::DiscreteFiniteField(set) => {
                            match ancestors_assignments
                                .entry(*type_id)
                                .or_insert(AssignmentsVariant::DiscreteFiniteField(bset! {}))
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
                        AssignmentsVariant::CustomData(set) => {
                            match ancestors_assignments
                                .entry(*type_id)
                                .or_insert(AssignmentsVariant::CustomData(bset! {}))
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

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::rgb::schema::*;
    use crate::strict_encoding::*;

    pub(crate) fn schema() -> Schema {
        const FIELD_TICKER: usize = 0;
        const FIELD_NAME: usize = 1;
        const FIELD_DESCRIPTION: usize = 2;
        const FIELD_TOTAL_SUPPLY: usize = 3;
        const FIELD_ISSUED_SUPPLY: usize = 4;
        const FIELD_DUST_LIMIT: usize = 5;
        const FIELD_PRECISION: usize = 6;
        const FIELD_PRUNE_PROOF: usize = 7;
        const FIELD_TIMESTAMP: usize = 8;

        const FIELD_PROOF_OF_BURN: usize = 0x10;

        const ASSIGNMENT_ISSUE: usize = 0;
        const ASSIGNMENT_ASSETS: usize = 1;
        const ASSIGNMENT_PRUNE: usize = 2;

        const TRANSITION_ISSUE: usize = 0;
        const TRANSITION_TRANSFER: usize = 1;
        const TRANSITION_PRUNE: usize = 2;

        const VALENCIES_DECENTRALIZED_ISSUE: usize = 0;

        const EXTENSION_DECENTRALIZED_ISSUE: usize = 0;

        Schema {
            field_types: bmap! {
                FIELD_TICKER => DataFormat::String(16),
                FIELD_NAME => DataFormat::String(256),
                FIELD_DESCRIPTION => DataFormat::String(1024),
                FIELD_TOTAL_SUPPLY => DataFormat::Unsigned(Bits::Bit64, 0, core::u64::MAX as u128),
                FIELD_PRECISION => DataFormat::Unsigned(Bits::Bit64, 0, 18u128),
                FIELD_ISSUED_SUPPLY => DataFormat::Unsigned(Bits::Bit64, 0, core::u64::MAX as u128),
                FIELD_DUST_LIMIT => DataFormat::Unsigned(Bits::Bit64, 0, core::u64::MAX as u128),
                FIELD_PRUNE_PROOF => DataFormat::Bytes(core::u16::MAX),
                FIELD_TIMESTAMP => DataFormat::Unsigned(Bits::Bit64, 0, core::u64::MAX as u128),
                // TODO: (new) Fix this with introduction of new data type
                FIELD_PROOF_OF_BURN => DataFormat::String(0)
            },
            assignment_types: bmap! {
                ASSIGNMENT_ISSUE => StateSchema {
                    format: StateFormat::Declarative,
                    abi: bmap! {
                        AssignmentAction::Validate => script::Procedure::Standard(script::StandardProcedure::IssueControl)
                    }
                },
                ASSIGNMENT_ASSETS => StateSchema {
                    format: StateFormat::DiscreteFiniteField(DiscreteFiniteFieldFormat::Unsigned64bit),
                    abi: bmap! {
                        AssignmentAction::Validate => script::Procedure::Standard(script::StandardProcedure::ConfidentialAmount)
                    }
                },
                ASSIGNMENT_PRUNE => StateSchema {
                    format: StateFormat::Declarative,
                    abi: bmap! {
                        AssignmentAction::Validate => script::Procedure::Standard(script::StandardProcedure::Prunning)
                    }
                }
            },
            valencies_types: bset! {
                VALENCIES_DECENTRALIZED_ISSUE
            },
            genesis: GenesisSchema {
                metadata: bmap! {
                    FIELD_TICKER => Occurences::Once,
                    FIELD_NAME => Occurences::Once,
                    FIELD_DESCRIPTION => Occurences::NoneOrOnce,
                    FIELD_TOTAL_SUPPLY => Occurences::Once,
                    FIELD_ISSUED_SUPPLY => Occurences::Once,
                    FIELD_DUST_LIMIT => Occurences::NoneOrOnce,
                    FIELD_PRECISION => Occurences::Once,
                    FIELD_TIMESTAMP => Occurences::Once
                },
                defines: bmap! {
                    ASSIGNMENT_ISSUE => Occurences::NoneOrOnce,
                    ASSIGNMENT_ASSETS => Occurences::NoneOrUpTo(None),
                    ASSIGNMENT_PRUNE => Occurences::NoneOrUpTo(None)
                },
                valencies: bset! { VALENCIES_DECENTRALIZED_ISSUE },
                abi: bmap! {},
            },
            extensions: bmap! {
                EXTENSION_DECENTRALIZED_ISSUE => ExtensionSchema {
                    metadata: bmap! {
                        FIELD_ISSUED_SUPPLY => Occurences::Once,
                        FIELD_PROOF_OF_BURN => Occurences::OnceOrUpTo(None)
                    },
                    defines: bmap! {
                        ASSIGNMENT_ASSETS => Occurences::NoneOrUpTo(None)
                    },
                    extends: bset! { VALENCIES_DECENTRALIZED_ISSUE },
                    valencies: bset! { },
                    abi: bmap! {},
                }
            },
            transitions: bmap! {
                TRANSITION_ISSUE => TransitionSchema {
                    metadata: bmap! {
                        FIELD_ISSUED_SUPPLY => Occurences::Once
                    },
                    closes: bmap! {
                        ASSIGNMENT_ISSUE => Occurences::Once
                    },
                    defines: bmap! {
                        ASSIGNMENT_ISSUE => Occurences::NoneOrOnce,
                        ASSIGNMENT_PRUNE => Occurences::NoneOrUpTo(None),
                        ASSIGNMENT_ASSETS => Occurences::NoneOrUpTo(None)
                    },
                    valencies: bset! {},
                    abi: bmap! {}
                },
                TRANSITION_TRANSFER => TransitionSchema {
                    metadata: bmap! {},
                    closes: bmap! {
                        ASSIGNMENT_ASSETS => Occurences::OnceOrUpTo(None)
                    },
                    defines: bmap! {
                        ASSIGNMENT_ASSETS => Occurences::NoneOrUpTo(None)
                    },
                    valencies: bset! {},
                    abi: bmap! {}
                },
                TRANSITION_PRUNE => TransitionSchema {
                    metadata: bmap! {
                        FIELD_PRUNE_PROOF => Occurences::NoneOrUpTo(None)
                    },
                    closes: bmap! {
                        ASSIGNMENT_PRUNE => Occurences::OnceOrUpTo(None),
                        ASSIGNMENT_ASSETS => Occurences::OnceOrUpTo(None)
                    },
                    defines: bmap! {
                        ASSIGNMENT_PRUNE => Occurences::NoneOrUpTo(None),
                        ASSIGNMENT_ASSETS => Occurences::NoneOrUpTo(None)
                    },
                    valencies: bset! {},
                    abi: bmap! {}
                }
            },
        }
    }

    #[test]
    fn test_rgb20_encoding_decoding() {
        let schema = schema();
        let encoded = strict_encode(&schema).unwrap();
        let encoded_standard: Vec<u8> = vec![
            9, 0, 0, 0, 4, 16, 0, 1, 0, 4, 0, 1, 2, 0, 4, 0, 4, 3, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0,
            255, 255, 255, 255, 255, 255, 255, 255, 4, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255,
            255, 255, 255, 255, 255, 255, 5, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255,
            255, 255, 255, 255, 6, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 18, 0, 0, 0, 0, 0, 0, 0, 7, 0,
            5, 255, 255, 8, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255,
            255, 3, 0, 0, 0, 0, 1, 0, 0, 255, 2, 1, 0, 1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255,
            255, 255, 255, 255, 255, 255, 1, 0, 0, 255, 1, 2, 0, 0, 1, 0, 0, 255, 3, 8, 0, 0, 0, 1,
            0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 3, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 6, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 254, 255, 255, 0, 0, 0, 0, 0, 0, 2, 0, 254, 255,
            255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 1, 0, 4, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
            1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0,
            254, 255, 255, 0, 0, 0, 0, 0, 0, 2, 0, 254, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            0, 0, 0, 1, 0, 1, 0, 255, 255, 255, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 254, 255, 255, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1, 0, 7, 0, 254, 255, 255, 0, 0, 0, 0, 0, 0, 2, 0, 1, 0,
            255, 255, 255, 0, 0, 0, 0, 0, 0, 2, 0, 255, 255, 255, 0, 0, 0, 0, 0, 0, 2, 0, 1, 0,
            254, 255, 255, 0, 0, 0, 0, 0, 0, 2, 0, 254, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0,
        ];
        assert_eq!(encoded, encoded_standard);

        let decoded = Schema::strict_decode(&encoded[..]).unwrap();
        assert_eq!(decoded, schema);
    }
}

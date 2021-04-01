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

use bitcoin::hashes::{sha256, sha256t};

use lnpbp::client_side_validation::{
    commit_strategy, CommitEncodeWithStrategy, ConsensusCommit,
};
use lnpbp::commit_verify::CommitVerify;
use lnpbp::TaggedHash;
use wallet::features;

use super::{
    DataFormat, ExecutableCode, ExtensionSchema, GenesisSchema, OwnedRightType,
    PublicRightType, StateSchema, TransitionSchema,
};
#[cfg(feature = "serde")]
use crate::Bech32;
use crate::ToBech32;

// Here we can use usize since encoding/decoding makes sure that it's u16
pub type FieldType = usize;
pub type ExtensionType = usize;
pub type TransitionType = usize;

static MIDSTATE_SHEMA_ID: [u8; 32] = [
    0x81, 0x73, 0x33, 0x7c, 0xcb, 0xc4, 0x8b, 0xd1, 0x24, 0x89, 0x65, 0xcd,
    0xd0, 0xcd, 0xb6, 0xc8, 0x7a, 0xa2, 0x14, 0x81, 0x7d, 0x57, 0x39, 0x22,
    0x28, 0x90, 0x74, 0x8f, 0x26, 0x75, 0x8e, 0xea,
];

/// Tag used for [`SchemaId`] hash type
pub struct SchemaIdTag;

impl sha256t::Tag for SchemaIdTag {
    #[inline]
    fn engine() -> sha256::HashEngine {
        let midstate = sha256::Midstate::from_inner(MIDSTATE_SHEMA_ID);
        sha256::HashEngine::from_midstate(midstate, 64)
    }
}

/// Commitment-based schema identifier used for committing to the schema type
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", try_from = "Bech32", into = "Bech32")
)]
#[derive(
    Wrapper,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    Display,
    From,
)]
#[wrapper(Debug, LowerHex, Index, IndexRange, IndexFrom, IndexTo, IndexFull)]
#[display(SchemaId::to_bech32_string)]
pub struct SchemaId(sha256t::Hash<SchemaIdTag>);

impl<MSG> CommitVerify<MSG> for SchemaId
where
    MSG: AsRef<[u8]>,
{
    #[inline]
    fn commit(msg: &MSG) -> SchemaId {
        SchemaId::hash(msg)
    }
}

#[derive(Clone, Debug, Default)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub struct Schema {
    /// Feature flags control which of the available RGB features are allowed
    /// for smart contracts created under this schema.
    ///
    /// RGBv1 defines that this structure must contain no flags set.
    ///
    /// NB: This is not the same as RGB protocol versioning: feature flag set
    /// is specific to a particular RGB protocol version. The only currently
    /// defined RGB version is RGBv1; future versions may change the whole
    /// structure of Schema data, use of feature flags, re-define their meaning
    /// or do other backward-incompatible changes (RGB protocol versions are
    /// not interoperable and backward-incompatible by definitions and the
    /// nature of client-side-validation which does not allow upgrades).
    #[cfg_attr(
        feature = "serde",
        serde(with = "serde_with::rust::display_fromstr")
    )]
    pub rgb_features: features::FlagVec,
    #[cfg_attr(
        feature = "serde",
        serde(with = "serde_with::rust::display_fromstr")
    )]
    pub root_id: SchemaId,
    pub field_types: BTreeMap<FieldType, DataFormat>,
    pub owned_right_types: BTreeMap<OwnedRightType, StateSchema>,
    pub public_right_types: BTreeSet<PublicRightType>,
    pub genesis: GenesisSchema,
    pub extensions: BTreeMap<ExtensionType, ExtensionSchema>,
    pub transitions: BTreeMap<TransitionType, TransitionSchema>,
    pub script: ExecutableCode,
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

impl PartialEq for Schema {
    fn eq(&self, other: &Self) -> bool {
        self.schema_id() == other.schema_id()
    }
}

impl Eq for Schema {}

mod strict_encoding {
    use super::*;
    use lnpbp::strict_encoding::{
        strategies, Error, Strategy, StrictDecode, StrictEncode,
    };

    // TODO #50: Use derive macros and generalized `tagged_hash!` in the future
    impl Strategy for SchemaId {
        type Strategy = strategies::Wrapped;
    }

    impl StrictEncode for Schema {
        fn strict_encode<E: io::Write>(
            &self,
            mut e: E,
        ) -> Result<usize, Error> {
            Ok(strict_encode_list!(e;
                self.rgb_features,
                self.root_id,
                self.field_types,
                self.owned_right_types,
                self.public_right_types,
                self.genesis,
                self.extensions,
                self.transitions,
                self.script
            ))
        }
    }

    impl StrictDecode for Schema {
        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
            Ok(Self {
                rgb_features: features::FlagVec::strict_decode(&mut d)?,
                root_id: SchemaId::strict_decode(&mut d)?,
                field_types: BTreeMap::strict_decode(&mut d)?,
                owned_right_types: BTreeMap::strict_decode(&mut d)?,
                public_right_types: BTreeSet::strict_decode(&mut d)?,
                genesis: GenesisSchema::strict_decode(&mut d)?,
                extensions: BTreeMap::strict_decode(&mut d)?,
                transitions: BTreeMap::strict_decode(&mut d)?,
                script: ExecutableCode::strict_decode(&mut d)?,
            })
        }
    }
}

// TODO #73: Move to validation module and refactor that module into a directory
mod _validation {
    use std::collections::BTreeSet;

    use lnpbp::client_side_validation::CommitConceal;

    use super::*;
    use crate::schema::{
        MetadataStructure, OwnedRightsStructure, PublicRightsStructure,
        SchemaVerify,
    };
    use crate::script::{Action, OverrideRules, VmType};
    use crate::vm::{EmbeddedVm, VmApi};
    use crate::{
        validation, Assignment, AssignmentVec, Metadata, Node, NodeId,
        NodeSubtype, OwnedRights, ParentOwnedRights, ParentPublicRights,
        PublicRights, State,
    };

    impl SchemaVerify for Schema {
        fn schema_verify(&self, root: &Schema) -> validation::Status {
            let mut status = validation::Status::new();

            if root.root_id != SchemaId::default() {
                status.add_failure(validation::Failure::SchemaRootHierarchy(
                    root.root_id,
                ));
            }

            for (field_type, data_format) in &self.field_types {
                match root.field_types.get(field_type) {
                    None => status.add_failure(
                        validation::Failure::SchemaRootNoFieldTypeMatch(
                            *field_type,
                        ),
                    ),
                    Some(root_data_format)
                        if root_data_format != data_format =>
                    {
                        status.add_failure(
                            validation::Failure::SchemaRootNoFieldTypeMatch(
                                *field_type,
                            ),
                        )
                    }
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
                        validation::Failure::SchemaRootNoPublicRightTypeMatch(
                            *valencies_type,
                        ),
                    ),
                    _ => &status,
                };
            }

            status += self.genesis.schema_verify(&root.genesis);

            for (transition_type, transition_schema) in &self.transitions {
                if let Some(root_transition_schema) =
                    root.transitions.get(transition_type)
                {
                    status +=
                        transition_schema.schema_verify(root_transition_schema);
                } else {
                    status.add_failure(
                        validation::Failure::SchemaRootNoTransitionTypeMatch(
                            *transition_type,
                        ),
                    );
                }
            }
            for (extension_type, extension_schema) in &self.extensions {
                if let Some(root_extension_schema) =
                    root.extensions.get(extension_type)
                {
                    status +=
                        extension_schema.schema_verify(root_extension_schema);
                } else {
                    status.add_failure(
                        validation::Failure::SchemaRootNoExtensionTypeMatch(
                            *extension_type,
                        ),
                    );
                }
            }

            match (root.script.override_rules, self.script.override_rules) {
                (OverrideRules::Deny, _)
                    if root.script.vm_type != self.script.vm_type
                        || !self.script.byte_code.is_empty() =>
                {
                    status.add_failure(
                        validation::Failure::SchemaScriptOverrideDenied,
                    );
                }
                (OverrideRules::AllowSameVm, _)
                    if root.script.vm_type != self.script.vm_type =>
                {
                    status.add_failure(
                        validation::Failure::SchemaScriptVmChangeDenied,
                    );
                }
                _ => {} // We are fine here
            }

            if root.script.vm_type == VmType::Embedded
                && !root.script.byte_code.is_empty()
            {
                status.add_failure(validation::Failure::ScriptCodeMustBeEmpty);
            }

            if self.script.vm_type == VmType::Embedded
                && !self.script.byte_code.is_empty()
            {
                status.add_failure(validation::Failure::ScriptCodeMustBeEmpty);
            }

            status
        }
    }

    impl Schema {
        pub fn validate(
            &self,
            all_nodes: &BTreeMap<NodeId, &dyn Node>,
            node: &dyn Node,
            byte_code: &[u8],
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
                        &self.genesis.public_rights
                    )
                },
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

            let parent_owned_rights = extract_parent_owned_rights(
                all_nodes,
                node.parent_owned_rights(),
                &mut status,
            );
            let parent_public_rights = extract_parent_public_rights(
                all_nodes,
                node.parent_public_rights(),
                &mut status,
            );
            status += self.validate_meta(
                node_id,
                node.metadata(),
                metadata_structure,
            );
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
            status += self.validate_owned_rights(
                node_id,
                node.owned_rights(),
                assignments_structure,
            );
            status += self.validate_public_rights(
                node_id,
                node.public_rights(),
                valencies_structure,
            );
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
                &byte_code,
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
                    status.add_failure(
                        validation::Failure::SchemaUnknownFieldType(
                            node_id, **field_id,
                        ),
                    );
                });

            for (field_type_id, occ) in metadata_structure {
                let set =
                    metadata.get(field_type_id).cloned().unwrap_or(bset!());

                // Checking number of field occurrences
                if let Err(err) = occ.check(set.len() as u16) {
                    status.add_failure(
                        validation::Failure::SchemaMetaOccurencesError(
                            node_id,
                            *field_type_id,
                            err,
                        ),
                    );
                }

                let field = self.field_types.get(field_type_id)
                    .expect("If the field were absent, the schema would not be able to pass the internal validation and we would not reach this point");
                for data in set {
                    status += field.validate(*field_type_id, &data);
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
                    status.add_failure(
                        validation::Failure::SchemaUnknownOwnedRightType(
                            node_id,
                            **owned_type_id,
                        ),
                    );
                });

            for (owned_type_id, occ) in owned_rights_structure {
                let len = owned_rights
                    .get(owned_type_id)
                    .map(AssignmentVec::len)
                    .unwrap_or(0);

                // Checking number of ancestor's assignment occurrences
                if let Err(err) = occ.check(len as u16) {
                    status.add_failure(
                        validation::Failure::SchemaParentOwnedRightOccurencesError(
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

            public_rights.difference(&public_rights_structure).for_each(
                |public_type_id| {
                    status.add_failure(
                        validation::Failure::SchemaUnknownPublicRightType(
                            node_id,
                            *public_type_id,
                        ),
                    );
                },
            );

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
                    status.add_failure(
                        validation::Failure::SchemaUnknownOwnedRightType(
                            node_id,
                            **assignment_type_id,
                        ),
                    );
                });

            for (owned_type_id, occ) in owned_rights_structure {
                let len = owned_rights
                    .get(owned_type_id)
                    .map(AssignmentVec::len)
                    .unwrap_or(0);

                // Checking number of assignment occurrences
                if let Err(err) = occ.check(len as u16) {
                    status.add_failure(
                        validation::Failure::SchemaOwnedRightOccurencesError(
                            node_id,
                            *owned_type_id,
                            err,
                        ),
                    );
                }

                let assignment = &self
                    .owned_right_types
                    .get(owned_type_id)
                    .expect("If the assignment were absent, the schema would not be able to pass the internal validation and we would not reach this point")
                    .format;

                match owned_rights.get(owned_type_id) {
                    None => {}
                    Some(AssignmentVec::Declarative(set)) => {
                        set.into_iter().for_each(|data| {
                            status += assignment.validate(
                                &node_id,
                                *owned_type_id,
                                data,
                            )
                        })
                    }
                    Some(AssignmentVec::DiscreteFiniteField(set)) => {
                        set.into_iter().for_each(|data| {
                            status += assignment.validate(
                                &node_id,
                                *owned_type_id,
                                data,
                            )
                        })
                    }
                    Some(AssignmentVec::CustomData(set)) => {
                        set.into_iter().for_each(|data| {
                            status += assignment.validate(
                                &node_id,
                                *owned_type_id,
                                data,
                            )
                        })
                    }
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

            public_rights.difference(&public_rights_structure).for_each(
                |public_type_id| {
                    status.add_failure(
                        validation::Failure::SchemaUnknownPublicRightType(
                            node_id,
                            *public_type_id,
                        ),
                    );
                },
            );

            status
        }

        fn validate_state_evolution(
            &self,
            node_id: NodeId,
            node_subtype: NodeSubtype,
            parent_owned_rights: &OwnedRights,
            owned_rights: &OwnedRights,
            parent_public_rights: &PublicRights,
            public_rights: &PublicRights,
            metadata: &Metadata,
            byte_code: &[u8],
        ) -> validation::Status {
            let mut status = validation::Status::new();

            macro_rules! vm {
                ($abi:expr) => {{
                    // This code is actually unreachable, since we check VM type
                    // at the start of schema validation in
                    // `Validator::validate_schema` and return if it's
                    // wrong, however it is here as an additional safety
                    // placeholder
                    if self.script.vm_type != VmType::Embedded {
                        status.add_failure(
                            validation::Failure::VirtualMachinesNotSupportedYet,
                        );
                        return status;
                    }

                    let vm = match EmbeddedVm::with(byte_code, $abi) {
                        Ok(vm) => vm,
                        Err(failure) => {
                            status.add_failure(failure);
                            return status;
                        }
                    };

                    Box::new(vm) as Box<dyn VmApi>
                }};
            }

            let abi = match node_subtype {
                NodeSubtype::Genesis => self
                    .genesis
                    .abi
                    .iter()
                    .map(|(action, entry_point)| {
                        (Action::from(*action), *entry_point)
                    })
                    .collect(),
                NodeSubtype::StateTransition(type_id) => self
                    .transitions
                    .get(&type_id)
                    .expect(
                        "node structure must be validated against schema \
                        requirements before any scripts is executed",
                    )
                    .abi
                    .iter()
                    .map(|(action, entry_point)| {
                        (Action::from(*action), *entry_point)
                    })
                    .collect(),
                NodeSubtype::StateExtension(type_id) => self
                    .extensions
                    .get(&type_id)
                    .expect(
                        "node structure must be validated against schema \
                        requirements before any scripts is executed",
                    )
                    .abi
                    .iter()
                    .map(|(action, entry_point)| {
                        (Action::from(*action), *entry_point)
                    })
                    .collect(),
            };

            let vm = vm!(&abi);
            if let Err(err) = vm.validate_node(
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

            let owned_right_types: BTreeSet<&OwnedRightType> =
                parent_owned_rights
                    .keys()
                    .chain(owned_rights.keys())
                    .collect();

            for owned_type_id in owned_right_types {
                let abi = &self
                    .owned_right_types
                    .get(&owned_type_id)
                    .expect(
                        "node structure must be validated against schema \
                        requirements before any scripts is executed",
                    )
                    .abi;

                let vm = vm!(abi);

                if let Err(err) = vm.validate_assignment(
                    node_id,
                    node_subtype,
                    *owned_type_id,
                    parent_owned_rights.assignments_by_type(*owned_type_id),
                    owned_rights.assignments_by_type(*owned_type_id),
                    metadata,
                ) {
                    status.add_failure(err);
                    continue;
                }
            }

            // We do not validate public rights, since they do not have an
            // associated state and there is nothing to validate beyond schema

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
                    status.add_failure(validation::Failure::TransitionAbsent(
                        *id,
                    ));
                    continue;
                }
                Some(node) => node,
            };

            fn filter<STATE>(
                set: &Vec<Assignment<STATE>>,
                indexes: &Vec<u16>,
            ) -> Vec<Assignment<STATE>>
            where
                STATE: State + Clone,
                STATE::Confidential: PartialEq + Eq,
                STATE::Confidential: From<
                    <STATE::Revealed as CommitConceal>::ConcealedCommitment,
                >,
            {
                set.into_iter()
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
                    Some(AssignmentVec::Declarative(set)) => {
                        let set = filter(set, indexes);
                        owned_rights
                            .entry(*type_id)
                            .or_insert(AssignmentVec::Declarative(
                                Default::default(),
                            ))
                            .declarative_assignment_vec_mut()
                            .map(|state| state.extend(set));
                    }
                    Some(AssignmentVec::DiscreteFiniteField(set)) => {
                        let set = filter(set, indexes);
                        owned_rights
                            .entry(*type_id)
                            .or_insert(AssignmentVec::DiscreteFiniteField(
                                Default::default(),
                            ))
                            .value_assignment_vec_mut()
                            .map(|state| state.extend(set));
                    }
                    Some(AssignmentVec::CustomData(set)) => {
                        let set = filter(set, indexes);
                        owned_rights
                            .entry(*type_id)
                            .or_insert(AssignmentVec::CustomData(
                                Default::default(),
                            ))
                            .data_assignment_vec_mut()
                            .map(|state| state.extend(set));
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

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::schema::*;
    use crate::script::EntryPoint;
    use crate::vm::embedded::NodeValidator;
    use lnpbp::strict_encoding::*;
    use lnpbp::tagged_hash;

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
            rgb_features: features::FlagVec::default(),
            root_id: Default::default(),
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
                FIELD_PROOF_OF_BURN => DataFormat::TxOutPoint
            },
            owned_right_types: bmap! {
                ASSIGNMENT_ISSUE => StateSchema {
                    format: StateFormat::Declarative,
                    abi: bmap! {
                        AssignmentAction::Validate => NodeValidator::FungibleIssue as EntryPoint
                    }
                },
                ASSIGNMENT_ASSETS => StateSchema {
                    format: StateFormat::DiscreteFiniteField(DiscreteFiniteFieldFormat::Unsigned64bit),
                    abi: bmap! {
                        AssignmentAction::Validate => NodeValidator::IdentityTransfer as EntryPoint
                    }
                },
                ASSIGNMENT_PRUNE => StateSchema {
                    format: StateFormat::Declarative,
                    abi: bmap! {
                        AssignmentAction::Validate => NodeValidator::ProofOfBurn as EntryPoint
                    }
                }
            },
            public_right_types: bset! {
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
                owned_rights: bmap! {
                    ASSIGNMENT_ISSUE => Occurences::NoneOrOnce,
                    ASSIGNMENT_ASSETS => Occurences::NoneOrMore,
                    ASSIGNMENT_PRUNE => Occurences::NoneOrMore
                },
                public_rights: bset! { VALENCIES_DECENTRALIZED_ISSUE },
                abi: bmap! {},
            },
            extensions: bmap! {
                EXTENSION_DECENTRALIZED_ISSUE => ExtensionSchema {
                    extends: bset! { VALENCIES_DECENTRALIZED_ISSUE },
                    metadata: bmap! {
                        FIELD_ISSUED_SUPPLY => Occurences::Once,
                        FIELD_PROOF_OF_BURN => Occurences::OnceOrMore
                    },
                    owned_rights: bmap! {
                        ASSIGNMENT_ASSETS => Occurences::NoneOrMore
                    },
                    public_rights: bset! { },
                    abi: bmap! {},
                }
            },
            transitions: bmap! {
                TRANSITION_ISSUE => TransitionSchema {
                    closes: bmap! {
                        ASSIGNMENT_ISSUE => Occurences::Once
                    },
                    metadata: bmap! {
                        FIELD_ISSUED_SUPPLY => Occurences::Once
                    },
                    owned_rights: bmap! {
                        ASSIGNMENT_ISSUE => Occurences::NoneOrOnce,
                        ASSIGNMENT_PRUNE => Occurences::NoneOrMore,
                        ASSIGNMENT_ASSETS => Occurences::NoneOrMore
                    },
                    public_rights: bset! {},
                    abi: bmap! {}
                },
                TRANSITION_TRANSFER => TransitionSchema {
                    closes: bmap! {
                        ASSIGNMENT_ASSETS => Occurences::OnceOrMore
                    },
                    metadata: bmap! {},
                    owned_rights: bmap! {
                        ASSIGNMENT_ASSETS => Occurences::NoneOrMore
                    },
                    public_rights: bset! {},
                    abi: bmap! {}
                },
                TRANSITION_PRUNE => TransitionSchema {
                    closes: bmap! {
                        ASSIGNMENT_PRUNE => Occurences::OnceOrMore,
                        ASSIGNMENT_ASSETS => Occurences::OnceOrMore
                    },
                    metadata: bmap! {
                        FIELD_PRUNE_PROOF => Occurences::NoneOrMore
                    },
                    owned_rights: bmap! {
                        ASSIGNMENT_PRUNE => Occurences::NoneOrMore,
                        ASSIGNMENT_ASSETS => Occurences::NoneOrMore
                    },
                    public_rights: bset! {},
                    abi: bmap! {}
                }
            },
            script: Default::default(),
        }
    }

    #[test]
    fn test_schema_id_midstate() {
        let midstate = tagged_hash::Midstate::with(b"rgb:schema");
        assert_eq!(**midstate, MIDSTATE_SHEMA_ID);
    }

    #[test]
    fn test_schema_encoding_decoding() {
        let schema = schema();
        let encoded = strict_serialize(&schema).unwrap();
        let encoded_standard: Vec<u8> = vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 4, 16, 0, 1, 0, 4,
            0, 1, 2, 0, 4, 0, 4, 3, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255,
            255, 255, 255, 255, 255, 255, 4, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0,
            255, 255, 255, 255, 255, 255, 255, 255, 5, 0, 0, 8, 0, 0, 0, 0, 0,
            0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 6, 0, 0, 8, 0, 0,
            0, 0, 0, 0, 0, 0, 18, 0, 0, 0, 0, 0, 0, 0, 7, 0, 5, 255, 255, 8, 0,
            0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255,
            255, 16, 0, 32, 3, 0, 0, 0, 0, 1, 0, 0, 2, 0, 0, 0, 1, 0, 1, 0, 8,
            0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 1,
            0, 0, 17, 0, 0, 0, 2, 0, 0, 1, 0, 0, 32, 0, 0, 0, 1, 0, 0, 0, 8, 0,
            0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 0, 0, 1, 0, 3, 0, 1, 0,
            1, 0, 4, 0, 1, 0, 1, 0, 5, 0, 0, 0, 1, 0, 6, 0, 1, 0, 1, 0, 8, 0,
            1, 0, 1, 0, 3, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 255, 255, 2, 0, 0,
            0, 255, 255, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 4, 0, 1, 0,
            1, 0, 16, 0, 1, 0, 255, 255, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 255,
            255, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 1, 0, 4, 0, 1, 0, 1, 0, 1, 0, 0,
            0, 1, 0, 1, 0, 3, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 255, 255, 2, 0,
            0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0,
            255, 255, 1, 0, 1, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 2, 0, 1, 0,
            7, 0, 0, 0, 255, 255, 2, 0, 1, 0, 1, 0, 255, 255, 2, 0, 1, 0, 255,
            255, 2, 0, 1, 0, 0, 0, 255, 255, 2, 0, 0, 0, 255, 255, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(encoded, encoded_standard);

        let decoded = Schema::strict_decode(&encoded[..]).unwrap();
        assert_eq!(decoded, schema);
    }
}

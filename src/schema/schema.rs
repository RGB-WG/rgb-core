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

use lnpbp::bp::TaggedHash;
use lnpbp::client_side_validation::{
    commit_strategy, CommitEncodeWithStrategy, ConsensusCommit,
};
use lnpbp::commit_verify::CommitVerify;
use lnpbp::features;

use super::{
    vm, DataFormat, ExtensionSchema, GenesisSchema, OwnedRightType,
    PublicRightType, SimplicityScript, StateSchema, TransitionSchema,
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

    // TODO: Use derive macros and generalized `tagged_hash!` in the future
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
                // We keep this parameter for future script extended info (like ABI)
                Vec::<u8>::new()
            ))
        }
    }

    impl StrictDecode for Schema {
        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
            let me = Self {
                rgb_features: features::FlagVec::strict_decode(&mut d)?,
                root_id: SchemaId::strict_decode(&mut d)?,
                field_types: BTreeMap::strict_decode(&mut d)?,
                owned_right_types: BTreeMap::strict_decode(&mut d)?,
                public_right_types: BTreeSet::strict_decode(&mut d)?,
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

mod _validation {
    use std::collections::BTreeSet;

    use lnpbp::client_side_validation::Conceal;

    use super::*;
    use crate::contract::nodes::PublicRights;
    use crate::schema::{
        script, MetadataStructure, OwnedRightsStructure, PublicRightsStructure,
        SchemaVerify,
    };
    use crate::{
        validation, AssignmentAction, Assignments, Metadata, Node, NodeId,
        OwnedRights, OwnedState, ParentOwnedRights, ParentPublicRights,
        StateTypes, VirtualMachine,
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

            status
        }
    }

    impl Schema {
        pub fn validate(
            &self,
            all_nodes: &BTreeMap<NodeId, &dyn Node>,
            node: &dyn Node,
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
            status += self.validate_state_evolution(
                node_id,
                node.transition_type(),
                &parent_owned_rights,
                node.owned_rights(),
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
                    .map(Assignments::len)
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
                    .map(Assignments::len)
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
                    Some(Assignments::Declarative(set)) => {
                        set.into_iter().for_each(|data| {
                            status += assignment.validate(
                                &node_id,
                                *owned_type_id,
                                data,
                            )
                        })
                    }
                    Some(Assignments::DiscreteFiniteField(set)) => {
                        set.into_iter().for_each(|data| {
                            status += assignment.validate(
                                &node_id,
                                *owned_type_id,
                                data,
                            )
                        })
                    }
                    Some(Assignments::CustomData(set)) => {
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
            transition_type: Option<TransitionType>,
            parent_owned_rights: &OwnedRights,
            owned_rights: &OwnedRights,
            metadata: &Metadata,
        ) -> validation::Status {
            let mut status = validation::Status::new();

            let owned_right_types: BTreeSet<&OwnedRightType> =
                parent_owned_rights
                    .keys()
                    .chain(owned_rights.keys())
                    .collect();

            for owned_type_id in owned_right_types {
                let abi = &self
                    .owned_right_types
                    .get(&owned_type_id)
                    .expect("We already passed owned rights type validation, so can be sure that the type exists")
                    .abi;

                // If the procedure is not defined, it means no validation
                // should be performed
                if let Some(procedure) = abi.get(&AssignmentAction::Validate) {
                    match procedure {
                        script::Procedure::Embedded(proc) => {
                            let mut vm = vm::Embedded::with(
                                transition_type,
                                parent_owned_rights
                                    .get(&owned_type_id)
                                    .cloned(),
                                owned_rights.get(&owned_type_id).cloned(),
                                metadata.clone(),
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
        let mut owned_rights = OwnedRights::new();
        for (id, details) in parent_owned_rights {
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
                set: &Vec<OwnedState<STATE>>,
                indexes: &Vec<u16>,
            ) -> Vec<OwnedState<STATE>>
            where
                STATE: StateTypes + Clone,
                STATE::Confidential: PartialEq + Eq,
                STATE::Confidential:
                    From<<STATE::Revealed as Conceal>::Confidential>,
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
                    Some(Assignments::Declarative(set)) => {
                        let set = filter(set, indexes);
                        owned_rights
                            .entry(*type_id)
                            .or_insert(Assignments::Declarative(
                                Default::default(),
                            ))
                            .declarative_state_mut()
                            .map(|state| state.extend(set));
                    }
                    Some(Assignments::DiscreteFiniteField(set)) => {
                        let set = filter(set, indexes);
                        owned_rights
                            .entry(*type_id)
                            .or_insert(Assignments::DiscreteFiniteField(
                                Default::default(),
                            ))
                            .discrete_state_mut()
                            .map(|state| state.extend(set));
                    }
                    Some(Assignments::CustomData(set)) => {
                        let set = filter(set, indexes);
                        owned_rights
                            .entry(*type_id)
                            .or_insert(Assignments::CustomData(
                                Default::default(),
                            ))
                            .custom_state_mut()
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
        let mut public_rights = PublicRights::new();
        for (id, public_right_types) in parent_public_rights {
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
    use amplify::Wrapper;

    use super::*;
    use crate::schema::*;
    use lnpbp::bp::tagged_hash;
    use lnpbp::strict_encoding::*;

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
                        AssignmentAction::Validate => script::Procedure::Embedded(script::StandardProcedure::FungibleInflation)
                    }
                },
                ASSIGNMENT_ASSETS => StateSchema {
                    format: StateFormat::DiscreteFiniteField(DiscreteFiniteFieldFormat::Unsigned64bit),
                    abi: bmap! {
                        AssignmentAction::Validate => script::Procedure::Embedded(script::StandardProcedure::NoInflationBySum)
                    }
                },
                ASSIGNMENT_PRUNE => StateSchema {
                    format: StateFormat::Declarative,
                    abi: bmap! {
                        AssignmentAction::Validate => script::Procedure::Embedded(script::StandardProcedure::ProofOfBurn)
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
        }
    }

    #[test]
    fn test_schema_id_midstate() {
        let midstate = tagged_hash::Midstate::with(b"rgb:schema");
        assert_eq!(midstate.into_inner(), MIDSTATE_SHEMA_ID);
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
            255, 16, 0, 32, 3, 0, 0, 0, 0, 1, 0, 0, 255, 2, 1, 0, 1, 0, 8, 0,
            0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 1, 0,
            0, 255, 1, 2, 0, 0, 1, 0, 0, 255, 16, 1, 0, 0, 0, 8, 0, 0, 0, 1, 0,
            1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 0, 0, 1, 0, 3, 0, 1, 0, 1, 0, 4, 0,
            1, 0, 1, 0, 5, 0, 0, 0, 1, 0, 6, 0, 1, 0, 1, 0, 8, 0, 1, 0, 1, 0,
            3, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 255, 255, 2, 0, 0, 0, 255, 255,
            1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 4, 0, 1, 0, 1, 0, 16, 0,
            1, 0, 255, 255, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 255, 255, 0, 0, 0, 0,
            0, 0, 3, 0, 0, 0, 1, 0, 4, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0,
            3, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 255, 255, 2, 0, 0, 0, 255, 255,
            0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 255, 255, 1, 0, 1,
            0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 2, 0, 1, 0, 7, 0, 0, 0, 255,
            255, 2, 0, 1, 0, 1, 0, 255, 255, 2, 0, 1, 0, 255, 255, 2, 0, 1, 0,
            0, 0, 255, 255, 2, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(encoded, encoded_standard);

        let decoded = Schema::strict_decode(&encoded[..]).unwrap();
        assert_eq!(decoded, schema);
    }
}

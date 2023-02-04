// RGB Core Library: a reference implementation of RGB smart contract standards.
// Written in 2019-2022 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the MIT License along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use amplify::flags::FlagVec;
use bitcoin_hashes::{sha256, sha256t};
use commit_verify::{commit_encode, CommitVerify, ConsensusCommit, PrehashedProtocol, TaggedHash};
use lnpbp::bech32::{FromBech32Str, ToBech32String};
use stens::{TypeRef, TypeSystem};

use super::{ExtensionSchema, GenesisSchema, OwnedRightType, PublicRightType, TransitionSchema};
use crate::schema::StateSchema;
use crate::script::OverrideRules;
use crate::ValidationScript;

// Here we can use usize since encoding/decoding makes sure that it's u16
pub type FieldType = u16;
pub type ExtensionType = u16;
pub type TransitionType = u16;

pub const RGB_SCHEMA_ID_HRP: &str = "rgbsh";

static MIDSTATE_SHEMA_ID: [u8; 32] = [
    0x81, 0x73, 0x33, 0x7c, 0xcb, 0xc4, 0x8b, 0xd1, 0x24, 0x89, 0x65, 0xcd, 0xd0, 0xcd, 0xb6, 0xc8,
    0x7a, 0xa2, 0x14, 0x81, 0x7d, 0x57, 0x39, 0x22, 0x28, 0x90, 0x74, 0x8f, 0x26, 0x75, 0x8e, 0xea,
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

impl lnpbp::bech32::Strategy for SchemaIdTag {
    const HRP: &'static str = RGB_SCHEMA_ID_HRP;
    type Strategy = lnpbp::bech32::strategies::UsingStrictEncoding;
}

/// Commitment-based schema identifier used for committing to the schema type
#[derive(Wrapper, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Display, From)]
#[derive(StrictEncode, StrictDecode)]
#[wrapper(Debug, BorrowSlice)]
#[display(SchemaId::to_bech32_string)]
pub struct SchemaId(sha256t::Hash<SchemaIdTag>);

impl<Msg> CommitVerify<Msg, PrehashedProtocol> for SchemaId
where Msg: AsRef<[u8]>
{
    #[inline]
    fn commit(msg: &Msg) -> SchemaId { SchemaId::hash(msg) }
}

impl lnpbp::bech32::Strategy for SchemaId {
    const HRP: &'static str = RGB_SCHEMA_ID_HRP;
    type Strategy = lnpbp::bech32::strategies::UsingStrictEncoding;
}

// TODO: Make this part of `lnpbp::bech32`
#[cfg(feature = "serde")]
impl serde::Serialize for SchemaId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: serde::Serializer {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_bech32_string())
        } else {
            serializer.serialize_bytes(&self[..])
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for SchemaId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: serde::Deserializer<'de> {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = SchemaId;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "Bech32 string with `{}` HRP", RGB_SCHEMA_ID_HRP)
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where E: serde::de::Error {
                SchemaId::from_str(v).map_err(serde::de::Error::custom)
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where E: serde::de::Error {
                self.visit_str(&v)
            }

            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
            where E: serde::de::Error {
                SchemaId::from_bytes(&v)
                    .map_err(|_| serde::de::Error::invalid_length(v.len(), &"32 bytes"))
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(Visitor)
        } else {
            deserializer.deserialize_byte_buf(Visitor)
        }
    }
}

impl FromStr for SchemaId {
    type Err = lnpbp::bech32::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> { SchemaId::from_bech32_str(s) }
}

#[derive(Clone, Debug, Default)]
#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct Schema {
    /// Feature flags control which of the available RGB features are allowed
    /// for smart contracts created under this schema.
    ///
    /// NB: This is not the same as RGB protocol versioning: feature flag set
    /// is specific to a particular RGB protocol version. The only currently
    /// defined RGB version is RGBv1; future versions may change the whole
    /// structure of Schema data, use of feature flags, re-define their meaning
    /// or do other backward-incompatible changes (RGB protocol versions are
    /// not interoperable and backward-incompatible by definitions and the
    /// nature of client-side-validation which does not allow upgrades).
    #[cfg_attr(feature = "serde", serde(with = "serde_with::rust::display_fromstr"))]
    pub rgb_features: FlagVec,
    pub root_id: SchemaId,

    pub type_system: TypeSystem,
    pub field_types: BTreeMap<FieldType, TypeRef>,
    pub owned_right_types: BTreeMap<OwnedRightType, StateSchema>,
    pub public_right_types: BTreeSet<PublicRightType>,
    pub genesis: GenesisSchema,
    pub extensions: BTreeMap<ExtensionType, ExtensionSchema>,
    pub transitions: BTreeMap<TransitionType, TransitionSchema>,

    /// Validation code.
    pub script: ValidationScript,

    /// Defines whether subschemata are allowed to replace (override) the code
    ///
    /// Subschemata not overriding the main schema code MUST set the virtual
    /// machine type to the same as in the parent schema and set byte code
    /// to be empty (zero-length)
    pub override_rules: OverrideRules,
}

impl Schema {
    #[inline]
    pub fn schema_id(&self) -> SchemaId { self.clone().consensus_commit() }
}

impl ConsensusCommit for Schema {
    type Commitment = SchemaId;
}
impl commit_encode::Strategy for Schema {
    type Strategy = commit_encode::strategies::UsingStrict;
}

impl PartialEq for Schema {
    fn eq(&self, other: &Self) -> bool { self.schema_id() == other.schema_id() }
}

impl Eq for Schema {}

// TODO #73: Move to validation module and refactor that module into a directory
mod _validation {
    use std::collections::BTreeSet;

    use commit_verify::CommitConceal;

    use super::*;
    use crate::schema::state::StenVerify;
    use crate::schema::{
        MetadataStructure, OwnedRightsStructure, PublicRightsStructure, SchemaVerify,
    };
    use crate::script::{OverrideRules, ValidationScript};
    use crate::vm::Validate;
    use crate::{
        data, validation, Assignment, Metadata, Node, NodeId, NodeSubtype, OwnedRights,
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
            let mut status = validation::Status::new();
            if let Err(inconsistencies) = self.type_system.validate() {
                for err in inconsistencies {
                    status.add_failure(validation::Failure::SchemaTypeSystem(err));
                }
            }
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

                let field = self.field_types.get(field_type_id)
                    .expect("If the field were absent, the schema would not be able to pass the internal validation and we would not reach this point");
                for data in set {
                    let schema_type = data.schema_type();
                    if &schema_type != field
                        && !matches!(
                            (&data, field),
                            (data::Revealed::Bytes(_), TypeRef::NameRef(_))
                        )
                    {
                        status.add_failure(validation::Failure::SchemaMismatchedDataType(
                            *field_type_id,
                        ));
                    }
                    status += field.verify(&self.type_system, node_id, *field_type_id, &data);
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
                        status +=
                            assignment.validate(&self.type_system, &node_id, *owned_type_id, data)
                    }),
                    Some(TypedAssignments::Value(set)) => set.iter().for_each(|data| {
                        status +=
                            assignment.validate(&self.type_system, &node_id, *owned_type_id, data)
                    }),
                    Some(TypedAssignments::Data(set)) => set.iter().for_each(|data| {
                        status +=
                            assignment.validate(&self.type_system, &node_id, *owned_type_id, data)
                    }),
                    Some(TypedAssignments::Attachment(set)) => set.iter().for_each(|data| {
                        status +=
                            assignment.validate(&self.type_system, &node_id, *owned_type_id, data)
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

#[cfg(test)]
pub(crate) mod test {
    use amplify::Wrapper;
    use commit_verify::tagged_hash;
    use strict_encoding::*;

    use super::*;
    use crate::schema::*;

    pub(crate) fn schema() -> Schema {
        const FIELD_TICKER: u16 = 0;
        const FIELD_NAME: u16 = 1;
        const FIELD_DESCRIPTION: u16 = 2;
        const FIELD_TOTAL_SUPPLY: u16 = 3;
        const FIELD_ISSUED_SUPPLY: u16 = 4;
        const FIELD_DUST_LIMIT: u16 = 5;
        const FIELD_PRECISION: u16 = 6;
        const FIELD_PRUNE_PROOF: u16 = 7;
        const FIELD_TIMESTAMP: u16 = 8;

        const FIELD_PROOF_OF_BURN: u16 = 0x10;

        const ASSIGNMENT_ISSUE: u16 = 0;
        const ASSIGNMENT_ASSETS: u16 = 1;
        const ASSIGNMENT_PRUNE: u16 = 2;

        const TRANSITION_ISSUE: u16 = 0;
        const TRANSITION_TRANSFER: u16 = 1;
        const TRANSITION_PRUNE: u16 = 2;

        const VALENCIES_DECENTRALIZED_ISSUE: u16 = 0;

        const EXTENSION_DECENTRALIZED_ISSUE: u16 = 0;

        Schema {
            rgb_features: FlagVec::default(),
            root_id: Default::default(),
            type_system: Default::default(),
            field_types: bmap! {
                FIELD_TICKER => TypeRef::ascii_string(),
                FIELD_NAME => TypeRef::ascii_string(),
                FIELD_DESCRIPTION => TypeRef::unicode_string(),
                FIELD_TOTAL_SUPPLY => TypeRef::u64(),
                FIELD_PRECISION => TypeRef::u8(),
                FIELD_ISSUED_SUPPLY => TypeRef::u64(),
                FIELD_DUST_LIMIT => TypeRef::u64(),
                FIELD_PRUNE_PROOF => TypeRef::bytes(),
                FIELD_TIMESTAMP => TypeRef::i64()
            },
            owned_right_types: bmap! {
                ASSIGNMENT_ISSUE => StateSchema::Declarative,
                ASSIGNMENT_ASSETS => StateSchema::DiscreteFiniteField(DiscreteFiniteFieldFormat::Unsigned64bit),
                ASSIGNMENT_PRUNE => StateSchema::Declarative
            },
            public_right_types: bset! {
                VALENCIES_DECENTRALIZED_ISSUE
            },
            genesis: GenesisSchema {
                metadata: bmap! {
                    FIELD_TICKER => Occurrences::Once,
                    FIELD_NAME => Occurrences::Once,
                    FIELD_DESCRIPTION => Occurrences::NoneOrOnce,
                    FIELD_TOTAL_SUPPLY => Occurrences::Once,
                    FIELD_ISSUED_SUPPLY => Occurrences::Once,
                    FIELD_DUST_LIMIT => Occurrences::NoneOrOnce,
                    FIELD_PRECISION => Occurrences::Once,
                    FIELD_TIMESTAMP => Occurrences::Once
                },
                owned_rights: bmap! {
                    ASSIGNMENT_ISSUE => Occurrences::NoneOrOnce,
                    ASSIGNMENT_ASSETS => Occurrences::NoneOrMore,
                    ASSIGNMENT_PRUNE => Occurrences::NoneOrMore
                },
                public_rights: bset! { VALENCIES_DECENTRALIZED_ISSUE },
            },
            extensions: bmap! {
                EXTENSION_DECENTRALIZED_ISSUE => ExtensionSchema {
                    extends: bset! { VALENCIES_DECENTRALIZED_ISSUE },
                    metadata: bmap! {
                        FIELD_ISSUED_SUPPLY => Occurrences::Once,
                        FIELD_PROOF_OF_BURN => Occurrences::OnceOrMore
                    },
                    owned_rights: bmap! {
                        ASSIGNMENT_ASSETS => Occurrences::NoneOrMore
                    },
                    public_rights: bset! { },
                }
            },
            transitions: bmap! {
                TRANSITION_ISSUE => TransitionSchema {
                    closes: bmap! {
                        ASSIGNMENT_ISSUE => Occurrences::Once
                    },
                    metadata: bmap! {
                        FIELD_ISSUED_SUPPLY => Occurrences::Once
                    },
                    owned_rights: bmap! {
                        ASSIGNMENT_ISSUE => Occurrences::NoneOrOnce,
                        ASSIGNMENT_PRUNE => Occurrences::NoneOrMore,
                        ASSIGNMENT_ASSETS => Occurrences::NoneOrMore
                    },
                    public_rights: bset! {},
                },
                TRANSITION_TRANSFER => TransitionSchema {
                    closes: bmap! {
                        ASSIGNMENT_ASSETS => Occurrences::OnceOrMore
                    },
                    metadata: bmap! {},
                    owned_rights: bmap! {
                        ASSIGNMENT_ASSETS => Occurrences::NoneOrMore
                    },
                    public_rights: bset! {},
                },
                TRANSITION_PRUNE => TransitionSchema {
                    closes: bmap! {
                        ASSIGNMENT_PRUNE => Occurrences::OnceOrMore,
                        ASSIGNMENT_ASSETS => Occurrences::OnceOrMore
                    },
                    metadata: bmap! {
                        FIELD_PRUNE_PROOF => Occurrences::NoneOrMore
                    },
                    owned_rights: bmap! {
                        ASSIGNMENT_PRUNE => Occurrences::NoneOrMore,
                        ASSIGNMENT_ASSETS => Occurrences::NoneOrMore
                    },
                    public_rights: bset! {},
                }
            },
            script: Default::default(),
            override_rules: Default::default(),
        }
    }

    #[test]
    fn test_schema_id_midstate() {
        let midstate = tagged_hash::Midstate::with(b"rgb:schema");
        assert_eq!(midstate.into_inner().into_inner(), MIDSTATE_SHEMA_ID);
    }

    #[test]
    fn test_schema_encoding_decoding() {
        let schema = schema();
        let encoded = strict_serialize(&schema).unwrap();
        let encoded_standard: Vec<u8> = vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 17, 254, 1, 0, 0, 17, 254, 2, 0, 0, 17, 255, 3, 0,
            0, 0, 3, 4, 0, 0, 0, 3, 5, 0, 0, 0, 3, 6, 0, 0, 0, 0, 7, 0, 0, 17, 0, 8, 0, 0, 0, 19,
            3, 0, 0, 0, 0, 1, 0, 1, 0, 2, 0, 0, 1, 0, 0, 0, 8, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
            0, 2, 0, 0, 0, 1, 0, 3, 0, 1, 0, 1, 0, 4, 0, 1, 0, 1, 0, 5, 0, 0, 0, 1, 0, 6, 0, 1, 0,
            1, 0, 8, 0, 1, 0, 1, 0, 3, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 255, 255, 2, 0, 0, 0, 255,
            255, 1, 0, 0, 0, 1, 0, 0, 0, 2, 0, 4, 0, 1, 0, 1, 0, 16, 0, 1, 0, 255, 255, 1, 0, 0, 0,
            1, 0, 1, 0, 0, 0, 255, 255, 0, 0, 3, 0, 0, 0, 1, 0, 4, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0,
            1, 0, 3, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 255, 255, 2, 0, 0, 0, 255, 255, 0, 0, 1, 0,
            0, 0, 1, 0, 1, 0, 1, 0, 255, 255, 1, 0, 1, 0, 0, 0, 255, 255, 0, 0, 2, 0, 1, 0, 7, 0,
            0, 0, 255, 255, 2, 0, 1, 0, 1, 0, 255, 255, 2, 0, 1, 0, 255, 255, 2, 0, 1, 0, 0, 0,
            255, 255, 2, 0, 0, 0, 255, 255, 0, 0, 0, 0,
        ];
        assert_eq!(encoded, encoded_standard);

        let decoded = Schema::strict_decode(&encoded[..]).unwrap();
        assert_eq!(decoded, schema);
    }
}

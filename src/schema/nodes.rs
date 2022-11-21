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

use once_cell::sync::Lazy;

use super::{ExtensionType, FieldType, Occurrences, TransitionType};

// Here we can use usize since encoding/decoding makes sure that it's u16
pub type OwnedRightType = u16;
pub type PublicRightType = u16;
pub type MetadataStructure = BTreeMap<FieldType, Occurrences>;
pub type PublicRightsStructure = BTreeSet<PublicRightType>;
pub type OwnedRightsStructure = BTreeMap<OwnedRightType, Occurrences>;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "snake_case")
)]
#[derive(StrictEncode, StrictDecode)]
#[strict_encoding(by_value)]
#[repr(u8)]
/// Node type: genesis, extensions and state transitions
pub enum NodeType {
    /// Genesis node: single node per contract, defining contract and
    /// committing to a specific schema and underlying chain hash
    #[display("genesis")]
    Genesis = 0,

    /// Multiple points for decentralized & unowned contract extension,
    /// committing either to a genesis or some state transition via their
    /// valencies
    #[display("extension")]
    StateExtension = 1,

    /// State transition performing owned change to the state data and
    /// committing to (potentially multiple) ancestors (i.e. genesis,
    /// extensions and/or  other state transitions) via spending
    /// corresponding transaction outputs assigned some state by ancestors
    #[display("transition")]
    StateTransition = 2,
}

/// Aggregated type used to supply full contract node type and transition/state
/// extension type information
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub enum NodeSubtype {
    /// Genesis node (no subtypes)
    Genesis,

    /// State transition contract node, subtyped by transition type
    StateTransition(TransitionType),

    /// State extension contract node, subtyped by extension type
    StateExtension(ExtensionType),
}

/// Trait defining common API for all node type schemata
pub trait NodeSchema {
    fn node_type(&self) -> NodeType;
    fn metadata(&self) -> &MetadataStructure;
    fn closes(&self) -> &OwnedRightsStructure;
    fn extends(&self) -> &PublicRightsStructure;
    fn owned_rights(&self) -> &OwnedRightsStructure;
    fn public_rights(&self) -> &PublicRightsStructure;
}

#[derive(Clone, PartialEq, Debug, Default, AsAny)]
#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct GenesisSchema {
    pub metadata: MetadataStructure,
    pub owned_rights: OwnedRightsStructure,
    pub public_rights: PublicRightsStructure,
}

#[derive(Clone, PartialEq, Debug, Default, AsAny)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
#[derive(StrictEncode, StrictDecode)]
pub struct ExtensionSchema {
    pub metadata: MetadataStructure,
    pub extends: PublicRightsStructure,
    pub owned_rights: OwnedRightsStructure,
    pub public_rights: PublicRightsStructure,
}

#[derive(Clone, PartialEq, Debug, Default, AsAny)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
#[derive(StrictEncode, StrictDecode)]
pub struct TransitionSchema {
    pub metadata: MetadataStructure,
    pub closes: OwnedRightsStructure,
    pub owned_rights: OwnedRightsStructure,
    pub public_rights: PublicRightsStructure,
}

static EMPTY_OWNED_RIGHTS: Lazy<OwnedRightsStructure> = Lazy::new(OwnedRightsStructure::new);
static EMPTY_PUBLIC_RIGHTS: Lazy<PublicRightsStructure> = Lazy::new(PublicRightsStructure::new);

impl NodeSchema for GenesisSchema {
    #[inline]
    fn node_type(&self) -> NodeType { NodeType::Genesis }
    #[inline]
    fn metadata(&self) -> &MetadataStructure { &self.metadata }
    #[inline]
    fn closes(&self) -> &OwnedRightsStructure { &EMPTY_OWNED_RIGHTS }
    #[inline]
    fn extends(&self) -> &PublicRightsStructure { &EMPTY_PUBLIC_RIGHTS }
    #[inline]
    fn owned_rights(&self) -> &OwnedRightsStructure { &self.owned_rights }
    #[inline]
    fn public_rights(&self) -> &PublicRightsStructure { &self.public_rights }
}

impl NodeSchema for ExtensionSchema {
    #[inline]
    fn node_type(&self) -> NodeType { NodeType::StateExtension }
    #[inline]
    fn metadata(&self) -> &MetadataStructure { &self.metadata }
    #[inline]
    fn closes(&self) -> &OwnedRightsStructure { &EMPTY_OWNED_RIGHTS }
    #[inline]
    fn extends(&self) -> &PublicRightsStructure { &self.extends }
    #[inline]
    fn owned_rights(&self) -> &OwnedRightsStructure { &self.owned_rights }
    #[inline]
    fn public_rights(&self) -> &PublicRightsStructure { &self.public_rights }
}

impl NodeSchema for TransitionSchema {
    #[inline]
    fn node_type(&self) -> NodeType { NodeType::StateTransition }
    #[inline]
    fn metadata(&self) -> &MetadataStructure { &self.metadata }
    #[inline]
    fn closes(&self) -> &OwnedRightsStructure { &self.closes }
    #[inline]
    fn extends(&self) -> &PublicRightsStructure { &EMPTY_PUBLIC_RIGHTS }
    #[inline]
    fn owned_rights(&self) -> &OwnedRightsStructure { &self.owned_rights }
    #[inline]
    fn public_rights(&self) -> &PublicRightsStructure { &self.public_rights }
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

#[cfg(test)]
mod test {
    use confined_encoding_test::test_vec_decoding_roundtrip;
    use strict_encoding::StrictDecode;

    use super::*;
    use crate::schema::SchemaVerify;
    use crate::validation::Failure;

    static GENESIS_SCHEMA: [u8; 62] = [
        4, 0, 1, 0, 1, 0, 1, 0, 2, 0, 0, 0, 1, 0, 3, 0, 1, 0, 13, 0, 4, 0, 0, 0, 17, 0, 4, 0, 1, 0,
        1, 0, 1, 0, 3, 0, 1, 0, 25, 0, 4, 0, 0, 0, 12, 0, 2, 1, 0, 0, 1, 0, 4, 0, 1, 0, 2, 0, 3, 0,
        4, 0,
    ];

    static TRANSITION_SCHEMA: [u8; 88] = [
        4, 0, 1, 0, 1, 0, 1, 0, 2, 0, 0, 0, 1, 0, 3, 0, 1, 0, 13, 0, 4, 0, 0, 0, 17, 0, 4, 0, 1, 0,
        1, 0, 1, 0, 2, 0, 0, 0, 1, 0, 3, 0, 1, 0, 25, 0, 4, 0, 0, 0, 12, 0, 4, 0, 1, 0, 1, 0, 1, 0,
        2, 0, 0, 0, 1, 0, 3, 0, 1, 0, 25, 0, 4, 0, 0, 0, 12, 0, 4, 0, 1, 0, 2, 0, 3, 0, 4, 0,
    ];

    static EXTENSION_SCHEMA: [u8; 72] = [
        4, 0, 1, 0, 1, 0, 1, 0, 2, 0, 0, 0, 1, 0, 3, 0, 1, 0, 13, 0, 4, 0, 0, 0, 17, 0, 4, 0, 1, 0,
        2, 0, 3, 0, 4, 0, 4, 0, 1, 0, 1, 0, 1, 0, 2, 0, 0, 0, 1, 0, 3, 0, 1, 0, 25, 0, 4, 0, 0, 0,
        12, 0, 4, 0, 1, 0, 2, 0, 3, 0, 4, 0,
    ];

    #[test]
    fn test_genesis_schema_encoding() {
        let _: GenesisSchema = test_vec_decoding_roundtrip(GENESIS_SCHEMA).unwrap();
    }

    #[test]
    fn test_transition_schema_encoding() {
        let _: TransitionSchema = test_vec_decoding_roundtrip(TRANSITION_SCHEMA).unwrap();
    }

    #[test]
    fn test_extension_schema_encoding() {
        let _: ExtensionSchema = test_vec_decoding_roundtrip(EXTENSION_SCHEMA).unwrap();
    }

    #[test]
    fn test_node_for_genesis() {
        let genesis_schema = GenesisSchema::strict_decode(&GENESIS_SCHEMA[..]).unwrap();

        let mut valencies = PublicRightsStructure::new();
        valencies.insert(1u16);
        valencies.insert(2u16);
        valencies.insert(3u16);
        valencies.insert(4u16);

        assert_eq!(genesis_schema.node_type(), NodeType::Genesis);
        assert_eq!(
            genesis_schema.metadata().get(&2u16).unwrap(),
            &Occurrences::NoneOrOnce
        );
        assert_eq!(genesis_schema.closes(), &OwnedRightsStructure::new());
        assert_eq!(genesis_schema.extends(), &PublicRightsStructure::new());
        assert_eq!(
            genesis_schema.owned_rights().get(&3u16).unwrap(),
            &Occurrences::OnceOrUpTo(25u16)
        );
        assert_eq!(genesis_schema.public_rights(), &valencies);
    }

    #[test]
    fn test_node_for_transition() {
        let transition_schema = TransitionSchema::strict_decode(&TRANSITION_SCHEMA[..]).unwrap();

        let mut valencies = PublicRightsStructure::new();
        valencies.insert(1u16);
        valencies.insert(2u16);
        valencies.insert(3u16);
        valencies.insert(4u16);

        assert_eq!(transition_schema.node_type(), NodeType::StateTransition);
        assert_eq!(
            transition_schema.metadata().get(&2u16).unwrap(),
            &Occurrences::NoneOrOnce
        );
        assert_eq!(
            transition_schema.closes().get(&3u16).unwrap(),
            &Occurrences::OnceOrUpTo(25u16)
        );
        assert_eq!(transition_schema.extends(), &PublicRightsStructure::new());
        assert_eq!(
            transition_schema.owned_rights().get(&3u16).unwrap(),
            &Occurrences::OnceOrUpTo(25u16)
        );
        assert_eq!(transition_schema.public_rights(), &valencies);
    }

    #[test]
    fn test_node_for_extension() {
        let extension_schema = ExtensionSchema::strict_decode(&EXTENSION_SCHEMA[..]).unwrap();

        let mut valencies = PublicRightsStructure::new();
        valencies.insert(1u16);
        valencies.insert(2u16);
        valencies.insert(3u16);
        valencies.insert(4u16);

        assert_eq!(extension_schema.node_type(), NodeType::StateExtension);
        assert_eq!(
            extension_schema.metadata().get(&2u16).unwrap(),
            &Occurrences::NoneOrOnce
        );
        assert_eq!(extension_schema.closes(), &OwnedRightsStructure::new());
        assert_eq!(extension_schema.extends(), &valencies);
        assert_eq!(
            extension_schema.owned_rights().get(&3u16).unwrap(),
            &Occurrences::OnceOrUpTo(25u16)
        );
        assert_eq!(extension_schema.public_rights(), &valencies);
    }

    #[test]
    fn test_validation() {
        // Create Two Metadata Structures
        let mut metadata_structures = MetadataStructure::new();
        metadata_structures.insert(1 as FieldType, Occurrences::Once);
        metadata_structures.insert(2 as FieldType, Occurrences::NoneOrOnce);
        metadata_structures.insert(3 as FieldType, Occurrences::OnceOrUpTo(13u16));
        metadata_structures.insert(4 as FieldType, Occurrences::NoneOrUpTo(17u16));

        let mut metadata_structures2 = MetadataStructure::new();
        metadata_structures2.insert(1 as FieldType, Occurrences::Once);
        metadata_structures2.insert(2 as FieldType, Occurrences::NoneOrOnce);
        metadata_structures2.insert(3 as FieldType, Occurrences::OnceOrMore);
        metadata_structures2.insert(4 as FieldType, Occurrences::NoneOrUpTo(15u16));

        // Create Two Seal Structures
        let mut seal_structures = OwnedRightsStructure::new();
        seal_structures.insert(1 as OwnedRightType, Occurrences::Once);
        seal_structures.insert(2 as OwnedRightType, Occurrences::NoneOrOnce);
        seal_structures.insert(3 as OwnedRightType, Occurrences::OnceOrUpTo(25u16));
        seal_structures.insert(4 as OwnedRightType, Occurrences::NoneOrUpTo(12u16));

        let mut seal_structures2 = OwnedRightsStructure::new();
        seal_structures2.insert(1 as OwnedRightType, Occurrences::Once);
        seal_structures2.insert(2 as OwnedRightType, Occurrences::NoneOrOnce);
        seal_structures2.insert(3 as OwnedRightType, Occurrences::OnceOrMore);
        seal_structures2.insert(4 as OwnedRightType, Occurrences::NoneOrUpTo(30u16));

        // Create Two Valency structure
        let mut valency_structure = PublicRightsStructure::new();
        valency_structure.insert(1 as PublicRightType);
        valency_structure.insert(2 as PublicRightType);
        valency_structure.insert(3 as PublicRightType);
        valency_structure.insert(4 as PublicRightType);

        let mut valency_structure2 = PublicRightsStructure::new();
        valency_structure2.insert(1 as PublicRightType);
        valency_structure2.insert(5 as PublicRightType);
        valency_structure2.insert(3 as PublicRightType);
        valency_structure2.insert(4 as PublicRightType);

        // Create Four Unequal Transition and Extension Structures
        let transtion_schema = TransitionSchema {
            metadata: metadata_structures.clone(),
            closes: seal_structures.clone(),
            owned_rights: seal_structures.clone(),
            public_rights: valency_structure.clone(),
        };

        let transtion_schema2 = TransitionSchema {
            metadata: metadata_structures2.clone(),
            closes: seal_structures2.clone(),
            owned_rights: seal_structures2.clone(),
            public_rights: valency_structure2.clone(),
        };

        let extension_schema = ExtensionSchema {
            metadata: metadata_structures.clone(),
            extends: valency_structure.clone(),
            owned_rights: seal_structures.clone(),
            public_rights: valency_structure.clone(),
        };

        let extension_schema2 = ExtensionSchema {
            metadata: metadata_structures.clone(),
            extends: valency_structure2.clone(),
            owned_rights: seal_structures.clone(),
            public_rights: valency_structure2.clone(),
        };

        // Create the expected failure results
        let transition_failures = vec![
            Failure::SchemaRootNoMetadataMatch(NodeType::StateTransition, 3),
            Failure::SchemaRootNoMetadataMatch(NodeType::StateTransition, 4),
            Failure::SchemaRootNoParentOwnedRightsMatch(NodeType::StateTransition, 3),
            Failure::SchemaRootNoParentOwnedRightsMatch(NodeType::StateTransition, 4),
            Failure::SchemaRootNoOwnedRightsMatch(NodeType::StateTransition, 3),
            Failure::SchemaRootNoOwnedRightsMatch(NodeType::StateTransition, 4),
            Failure::SchemaRootNoPublicRightsMatch(NodeType::StateTransition, 2),
        ];

        let extension_failures = vec![
            Failure::SchemaRootNoParentPublicRightsMatch(NodeType::StateExtension, 2),
            Failure::SchemaRootNoPublicRightsMatch(NodeType::StateExtension, 2),
        ];

        // Assert failures matches with expectation
        assert_eq!(
            transtion_schema.schema_verify(&transtion_schema2).failures,
            transition_failures
        );
        assert_eq!(
            extension_schema.schema_verify(&extension_schema2).failures,
            extension_failures
        );
    }
}

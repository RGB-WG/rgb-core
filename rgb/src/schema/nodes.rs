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

use super::{
    ExtensionAbi, ExtensionAction, FieldType, GenesisAbi, GenesisAction,
    NodeAction, Occurences, Procedure, TransitionAbi, TransitionAction,
};

// Here we can use usize since encoding/decoding makes sure that it's u16
pub type OwnedRightType = usize;
pub type PublicRightType = usize;
pub type MetadataStructure = BTreeMap<FieldType, Occurences>;
pub type PublicRightsStructure = BTreeSet<PublicRightType>;
pub type OwnedRightsStructure = BTreeMap<OwnedRightType, Occurences>;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
/// Node type: genesis, extensions and state transitions
pub enum NodeType {
    /// Genesis node: single node per contract, defining contract and
    /// committing to a specific schema and underlying chain hash
    #[display("genesis")]
    Genesis,

    /// Multiple points for decentralized & unowned contract extension,
    /// committing either to a genesis or some state transition via their
    /// valencies
    #[display("extension")]
    Extension,

    /// State transition performing owned change to the state data and
    /// committing to (potentially multiple) ancestors (i.e. genesis,
    /// extensions and/or  other state transitions) via spending
    /// corresponding transaction outputs assigned some state by ancestors
    #[display("transition")]
    StateTransition,
}

/// Trait defining common API for all node type schemata
pub trait NodeSchema {
    type Action: NodeAction;

    fn node_type(&self) -> NodeType;
    fn metadata(&self) -> &MetadataStructure;
    fn closes(&self) -> &OwnedRightsStructure;
    fn extends(&self) -> &PublicRightsStructure;
    fn owned_rights(&self) -> &OwnedRightsStructure;
    fn public_rights(&self) -> &PublicRightsStructure;
    fn abi(&self) -> &BTreeMap<Self::Action, Procedure>;
}

#[derive(Clone, PartialEq, Debug, Display, Default, AsAny)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[display(Debug)]
pub struct GenesisSchema {
    pub metadata: MetadataStructure,
    pub owned_rights: OwnedRightsStructure,
    pub public_rights: PublicRightsStructure,
    pub abi: GenesisAbi,
}

#[derive(Clone, PartialEq, Debug, Display, Default, AsAny)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[display(Debug)]
pub struct ExtensionSchema {
    pub metadata: MetadataStructure,
    pub extends: PublicRightsStructure,
    pub owned_rights: OwnedRightsStructure,
    pub public_rights: PublicRightsStructure,
    pub abi: ExtensionAbi,
}

#[derive(Clone, PartialEq, Debug, Display, Default, AsAny)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[display(Debug)]
pub struct TransitionSchema {
    pub metadata: MetadataStructure,
    pub closes: OwnedRightsStructure,
    pub owned_rights: OwnedRightsStructure,
    pub public_rights: PublicRightsStructure,
    pub abi: TransitionAbi,
}

lazy_static! {
    static ref EMPTY_SEALS: OwnedRightsStructure = OwnedRightsStructure::new();
    static ref EMPTY_VALENCIES: PublicRightsStructure =
        PublicRightsStructure::new();
}

impl NodeSchema for GenesisSchema {
    type Action = GenesisAction;

    #[inline]
    fn node_type(&self) -> NodeType {
        NodeType::Genesis
    }
    #[inline]
    fn metadata(&self) -> &MetadataStructure {
        &self.metadata
    }
    #[inline]
    fn closes(&self) -> &OwnedRightsStructure {
        &EMPTY_SEALS
    }
    #[inline]
    fn extends(&self) -> &PublicRightsStructure {
        &EMPTY_VALENCIES
    }
    #[inline]
    fn owned_rights(&self) -> &OwnedRightsStructure {
        &self.owned_rights
    }
    #[inline]
    fn public_rights(&self) -> &PublicRightsStructure {
        &self.public_rights
    }
    #[inline]
    fn abi(&self) -> &BTreeMap<Self::Action, Procedure> {
        &self.abi
    }
}

impl NodeSchema for ExtensionSchema {
    type Action = ExtensionAction;

    #[inline]
    fn node_type(&self) -> NodeType {
        NodeType::Extension
    }
    #[inline]
    fn metadata(&self) -> &MetadataStructure {
        &self.metadata
    }
    #[inline]
    fn closes(&self) -> &OwnedRightsStructure {
        &EMPTY_SEALS
    }
    #[inline]
    fn extends(&self) -> &PublicRightsStructure {
        &self.extends
    }
    #[inline]
    fn owned_rights(&self) -> &OwnedRightsStructure {
        &self.owned_rights
    }
    #[inline]
    fn public_rights(&self) -> &PublicRightsStructure {
        &self.public_rights
    }
    #[inline]
    fn abi(&self) -> &BTreeMap<Self::Action, Procedure> {
        &self.abi
    }
}

impl NodeSchema for TransitionSchema {
    type Action = TransitionAction;

    #[inline]
    fn node_type(&self) -> NodeType {
        NodeType::StateTransition
    }
    #[inline]
    fn metadata(&self) -> &MetadataStructure {
        &self.metadata
    }
    #[inline]
    fn closes(&self) -> &OwnedRightsStructure {
        &self.closes
    }
    #[inline]
    fn extends(&self) -> &PublicRightsStructure {
        &EMPTY_VALENCIES
    }
    #[inline]
    fn owned_rights(&self) -> &OwnedRightsStructure {
        &self.owned_rights
    }
    #[inline]
    fn public_rights(&self) -> &PublicRightsStructure {
        &self.public_rights
    }
    #[inline]
    fn abi(&self) -> &BTreeMap<Self::Action, Procedure> {
        &self.abi
    }
}

mod strict_encoding {
    use super::*;
    use lnpbp::strict_encoding::{Error, StrictDecode, StrictEncode};

    impl StrictEncode for GenesisSchema {
        fn strict_encode<E: io::Write>(
            &self,
            mut e: E,
        ) -> Result<usize, Error> {
            let mut len = 0usize;
            len += self.metadata.strict_encode(&mut e)?;
            len += self.owned_rights.strict_encode(&mut e)?;
            len += self.public_rights.strict_encode(&mut e)?;
            len += self.abi.strict_encode(&mut e)?;
            // We keep this parameter for future script extended info (like ABI)
            len += Vec::<u8>::new().strict_encode(&mut e)?;
            Ok(len)
        }
    }

    impl StrictDecode for GenesisSchema {
        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
            let me = Self {
                metadata: MetadataStructure::strict_decode(&mut d)?,
                owned_rights: OwnedRightsStructure::strict_decode(&mut d)?,
                public_rights: PublicRightsStructure::strict_decode(&mut d)?,
                abi: GenesisAbi::strict_decode(&mut d)?,
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

    impl StrictEncode for ExtensionSchema {
        fn strict_encode<E: io::Write>(
            &self,
            mut e: E,
        ) -> Result<usize, Error> {
            let mut len = 0usize;
            len += self.metadata.strict_encode(&mut e)?;
            len += self.extends.strict_encode(&mut e)?;
            len += self.owned_rights.strict_encode(&mut e)?;
            len += self.public_rights.strict_encode(&mut e)?;
            len += self.abi.strict_encode(&mut e)?;
            // We keep this parameter for future script extended info (like ABI)
            len += Vec::<u8>::new().strict_encode(&mut e)?;
            Ok(len)
        }
    }

    impl StrictDecode for ExtensionSchema {
        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
            let me = Self {
                metadata: MetadataStructure::strict_decode(&mut d)?,
                extends: PublicRightsStructure::strict_decode(&mut d)?,
                owned_rights: OwnedRightsStructure::strict_decode(&mut d)?,
                public_rights: PublicRightsStructure::strict_decode(&mut d)?,
                abi: ExtensionAbi::strict_decode(&mut d)?,
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

    impl StrictEncode for TransitionSchema {
        fn strict_encode<E: io::Write>(
            &self,
            mut e: E,
        ) -> Result<usize, Error> {
            let mut len = 0usize;
            len += self.metadata.strict_encode(&mut e)?;
            len += self.closes.strict_encode(&mut e)?;
            len += self.owned_rights.strict_encode(&mut e)?;
            len += self.public_rights.strict_encode(&mut e)?;
            len += self.abi.strict_encode(&mut e)?;
            // We keep this parameter for future script extended info (like ABI)
            len += Vec::<u8>::new().strict_encode(&mut e)?;
            Ok(len)
        }
    }

    impl StrictDecode for TransitionSchema {
        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
            let me = Self {
                metadata: MetadataStructure::strict_decode(&mut d)?,
                closes: OwnedRightsStructure::strict_decode(&mut d)?,
                owned_rights: OwnedRightsStructure::strict_decode(&mut d)?,
                public_rights: PublicRightsStructure::strict_decode(&mut d)?,
                abi: TransitionAbi::strict_decode(&mut d)?,
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

mod _verify {
    use super::*;
    use crate::schema::SchemaVerify;
    use crate::validation;
    use num_traits::ToPrimitive;

    impl<T> SchemaVerify for T
    where
        T: NodeSchema,
    {
        fn schema_verify(&self, root: &Self) -> validation::Status {
            let mut status = validation::Status::new();
            let node_type = self.node_type();

            for (field_type, occ) in self.metadata() {
                match root.metadata().get(field_type) {
                    None => status.add_failure(
                        validation::Failure::SchemaRootNoMetadataMatch(
                            node_type,
                            *field_type,
                        ),
                    ),
                    Some(root_occ) if occ != root_occ => status.add_failure(
                        validation::Failure::SchemaRootNoMetadataMatch(
                            node_type,
                            *field_type,
                        ),
                    ),
                    _ => &status,
                };
            }

            for (assignments_type, occ) in self.closes() {
                match root.closes().get(assignments_type) {
                    None => status.add_failure(
                        validation::Failure::SchemaRootNoParentOwnedRightsMatch(
                            node_type,
                            *assignments_type,
                        ),
                    ),
                    Some(root_occ) if occ != root_occ => status.add_failure(
                        validation::Failure::SchemaRootNoParentOwnedRightsMatch(
                            node_type,
                            *assignments_type,
                        ),
                    ),
                    _ => &status,
                };
            }

            for (assignments_type, occ) in self.owned_rights() {
                match root.owned_rights().get(assignments_type) {
                    None => status.add_failure(
                        validation::Failure::SchemaRootNoOwnedRightsMatch(
                            node_type,
                            *assignments_type,
                        ),
                    ),
                    Some(root_occ) if occ != root_occ => status.add_failure(
                        validation::Failure::SchemaRootNoOwnedRightsMatch(
                            node_type,
                            *assignments_type,
                        ),
                    ),
                    _ => &status,
                };
            }

            for valencies_type in self.extends() {
                if !root.extends().contains(valencies_type) {
                    status.add_failure(
                        validation::Failure::SchemaRootNoParentPublicRightsMatch(
                            node_type,
                            *valencies_type,
                        ),
                    );
                }
            }

            for valencies_type in self.public_rights() {
                if !root.public_rights().contains(valencies_type) {
                    status.add_failure(
                        validation::Failure::SchemaRootNoPublicRightsMatch(
                            node_type,
                            *valencies_type,
                        ),
                    );
                }
            }

            for (action, proc) in self.abi() {
                match root.abi().get(action) {
                    None => status.add_failure(
                        validation::Failure::SchemaRootNoAbiMatch {
                            node_type,
                            action_id: action.to_u16().expect(
                                "Action type can't exceed 16-bit integer",
                            ),
                        },
                    ),
                    Some(root_proc) if root_proc != proc => status.add_failure(
                        validation::Failure::SchemaRootNoAbiMatch {
                            node_type,
                            action_id: action.to_u16().expect(
                                "Action type can't exceed 16-bit integer",
                            ),
                        },
                    ),
                    _ => &status,
                };
            }

            status
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::schema::script::StandardProcedure;
    use crate::schema::SchemaVerify;
    use crate::validation::Failure;
    use lnpbp::strict_encoding::StrictDecode;
    use lnpbp::test_helpers::*;

    static GENESIS_SCHEMA: [u8; 69] = [
        4, 0, 1, 0, 1, 0, 1, 0, 2, 0, 0, 0, 1, 0, 3, 0, 1, 0, 13, 0, 4, 0, 0,
        0, 17, 0, 4, 0, 1, 0, 1, 0, 1, 0, 3, 0, 1, 0, 25, 0, 4, 0, 0, 0, 12, 0,
        2, 1, 0, 0, 1, 0, 4, 0, 1, 0, 2, 0, 3, 0, 4, 0, 1, 0, 0, 255, 1, 0, 0,
    ];

    static TRANSITION_SCHEMA: [u8; 95] = [
        4, 0, 1, 0, 1, 0, 1, 0, 2, 0, 0, 0, 1, 0, 3, 0, 1, 0, 13, 0, 4, 0, 0,
        0, 17, 0, 4, 0, 1, 0, 1, 0, 1, 0, 2, 0, 0, 0, 1, 0, 3, 0, 1, 0, 25, 0,
        4, 0, 0, 0, 12, 0, 4, 0, 1, 0, 1, 0, 1, 0, 2, 0, 0, 0, 1, 0, 3, 0, 1,
        0, 25, 0, 4, 0, 0, 0, 12, 0, 4, 0, 1, 0, 2, 0, 3, 0, 4, 0, 1, 0, 0,
        255, 1, 0, 0,
    ];

    static EXTENSION_SCHEMA: [u8; 79] = [
        4, 0, 1, 0, 1, 0, 1, 0, 2, 0, 0, 0, 1, 0, 3, 0, 1, 0, 13, 0, 4, 0, 0,
        0, 17, 0, 4, 0, 1, 0, 2, 0, 3, 0, 4, 0, 4, 0, 1, 0, 1, 0, 1, 0, 2, 0,
        0, 0, 1, 0, 3, 0, 1, 0, 25, 0, 4, 0, 0, 0, 12, 0, 4, 0, 1, 0, 2, 0, 3,
        0, 4, 0, 1, 0, 0, 255, 1, 0, 0,
    ];

    #[test]
    fn test_genesis_schema_encoding() {
        test_encode!((GENESIS_SCHEMA, GenesisSchema));
    }

    #[test]
    fn test_transition_schema_encoding() {
        test_encode!((TRANSITION_SCHEMA, TransitionSchema));
    }

    #[test]
    fn test_extension_schema_encoding() {
        test_encode!((EXTENSION_SCHEMA, ExtensionSchema));
    }

    #[test]
    fn test_node_for_genesis() {
        let genesis_schema =
            GenesisSchema::strict_decode(&GENESIS_SCHEMA[..]).unwrap();

        let mut valencies = PublicRightsStructure::new();
        valencies.insert(1usize);
        valencies.insert(2usize);
        valencies.insert(3usize);
        valencies.insert(4usize);

        let mut genesis_abi = GenesisAbi::new();
        genesis_abi.insert(
            GenesisAction::Validate,
            Procedure::Embedded(StandardProcedure::NoInflationBySum),
        );

        assert_eq!(genesis_schema.node_type(), NodeType::Genesis);
        assert_eq!(
            genesis_schema.metadata().get(&2usize).unwrap(),
            &Occurences::NoneOrOnce
        );
        assert_eq!(genesis_schema.closes(), &OwnedRightsStructure::new());
        assert_eq!(genesis_schema.extends(), &PublicRightsStructure::new());
        assert_eq!(
            genesis_schema.owned_rights().get(&3usize).unwrap(),
            &Occurences::OnceOrUpTo(25u16)
        );
        assert_eq!(genesis_schema.public_rights(), &valencies);
        assert_eq!(genesis_schema.abi(), &genesis_abi);
    }

    #[test]
    fn test_node_for_transition() {
        let transition_schema =
            TransitionSchema::strict_decode(&TRANSITION_SCHEMA[..]).unwrap();

        let mut valencies = PublicRightsStructure::new();
        valencies.insert(1usize);
        valencies.insert(2usize);
        valencies.insert(3usize);
        valencies.insert(4usize);

        let mut transition_abi = TransitionAbi::new();
        transition_abi.insert(
            TransitionAction::Validate,
            Procedure::Embedded(StandardProcedure::NoInflationBySum),
        );

        assert_eq!(transition_schema.node_type(), NodeType::StateTransition);
        assert_eq!(
            transition_schema.metadata().get(&2usize).unwrap(),
            &Occurences::NoneOrOnce
        );
        assert_eq!(
            transition_schema.closes().get(&3usize).unwrap(),
            &Occurences::OnceOrUpTo(25u16)
        );
        assert_eq!(transition_schema.extends(), &PublicRightsStructure::new());
        assert_eq!(
            transition_schema.owned_rights().get(&3usize).unwrap(),
            &Occurences::OnceOrUpTo(25u16)
        );
        assert_eq!(transition_schema.public_rights(), &valencies);
        assert_eq!(transition_schema.abi(), &transition_abi);
    }

    #[test]
    fn test_node_for_extension() {
        let extension_schema =
            ExtensionSchema::strict_decode(&EXTENSION_SCHEMA[..]).unwrap();

        let mut valencies = PublicRightsStructure::new();
        valencies.insert(1usize);
        valencies.insert(2usize);
        valencies.insert(3usize);
        valencies.insert(4usize);

        let mut extension_abi = ExtensionAbi::new();
        extension_abi.insert(
            ExtensionAction::Validate,
            Procedure::Embedded(StandardProcedure::NoInflationBySum),
        );

        assert_eq!(extension_schema.node_type(), NodeType::Extension);
        assert_eq!(
            extension_schema.metadata().get(&2usize).unwrap(),
            &Occurences::NoneOrOnce
        );
        assert_eq!(extension_schema.closes(), &OwnedRightsStructure::new());
        assert_eq!(extension_schema.extends(), &valencies);
        assert_eq!(
            extension_schema.owned_rights().get(&3usize).unwrap(),
            &Occurences::OnceOrUpTo(25u16)
        );
        assert_eq!(extension_schema.public_rights(), &valencies);
        assert_eq!(extension_schema.abi(), &extension_abi);
    }

    #[test]
    fn test_validation() {
        // Create Two Metadata Structures
        let mut metadata_structures = MetadataStructure::new();
        metadata_structures.insert(1 as FieldType, Occurences::Once);
        metadata_structures.insert(2 as FieldType, Occurences::NoneOrOnce);
        metadata_structures
            .insert(3 as FieldType, Occurences::OnceOrUpTo(13u16));
        metadata_structures
            .insert(4 as FieldType, Occurences::NoneOrUpTo(17u16));

        let mut metadata_structures2 = MetadataStructure::new();
        metadata_structures2.insert(1 as FieldType, Occurences::Once);
        metadata_structures2.insert(2 as FieldType, Occurences::NoneOrOnce);
        metadata_structures2.insert(3 as FieldType, Occurences::OnceOrMore);
        metadata_structures2
            .insert(4 as FieldType, Occurences::NoneOrUpTo(15u16));

        // Create Two Seal Structures
        let mut seal_structures = OwnedRightsStructure::new();
        seal_structures.insert(1 as OwnedRightType, Occurences::Once);
        seal_structures.insert(2 as OwnedRightType, Occurences::NoneOrOnce);
        seal_structures
            .insert(3 as OwnedRightType, Occurences::OnceOrUpTo(25u16));
        seal_structures
            .insert(4 as OwnedRightType, Occurences::NoneOrUpTo(12u16));

        let mut seal_structures2 = OwnedRightsStructure::new();
        seal_structures2.insert(1 as OwnedRightType, Occurences::Once);
        seal_structures2.insert(2 as OwnedRightType, Occurences::NoneOrOnce);
        seal_structures2.insert(3 as OwnedRightType, Occurences::OnceOrMore);
        seal_structures2
            .insert(4 as OwnedRightType, Occurences::NoneOrUpTo(30u16));

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

        // Create the required ABIs
        let mut transition_abi = TransitionAbi::new();
        transition_abi.insert(
            TransitionAction::Validate,
            Procedure::Embedded(StandardProcedure::NoInflationBySum),
        );

        let mut transition_abi2 = TransitionAbi::new();
        transition_abi2.insert(
            TransitionAction::Validate,
            Procedure::Embedded(StandardProcedure::ProofOfBurn),
        );

        let mut extension_abi = ExtensionAbi::new();
        extension_abi.insert(
            ExtensionAction::Validate,
            Procedure::Embedded(StandardProcedure::NoInflationBySum),
        );

        // Create Four Unequal Transition and Extension Structures
        let transtion_schema = TransitionSchema {
            metadata: metadata_structures.clone(),
            closes: seal_structures.clone(),
            owned_rights: seal_structures.clone(),
            public_rights: valency_structure.clone(),
            abi: transition_abi.clone(),
        };

        let transtion_schema2 = TransitionSchema {
            metadata: metadata_structures2.clone(),
            closes: seal_structures2.clone(),
            owned_rights: seal_structures2.clone(),
            public_rights: valency_structure2.clone(),
            abi: transition_abi2.clone(),
        };

        let extension_schema = ExtensionSchema {
            metadata: metadata_structures.clone(),
            extends: valency_structure.clone(),
            owned_rights: seal_structures.clone(),
            public_rights: valency_structure.clone(),
            abi: extension_abi.clone(),
        };

        let extension_schema2 = ExtensionSchema {
            metadata: metadata_structures.clone(),
            extends: valency_structure2.clone(),
            owned_rights: seal_structures.clone(),
            public_rights: valency_structure2.clone(),
            abi: extension_abi.clone(),
        };

        // Create the expected failure results
        let transition_failures = vec![
            Failure::SchemaRootNoMetadataMatch(NodeType::StateTransition, 3),
            Failure::SchemaRootNoMetadataMatch(NodeType::StateTransition, 4),
            Failure::SchemaRootNoParentOwnedRightsMatch(
                NodeType::StateTransition,
                3,
            ),
            Failure::SchemaRootNoParentOwnedRightsMatch(
                NodeType::StateTransition,
                4,
            ),
            Failure::SchemaRootNoOwnedRightsMatch(NodeType::StateTransition, 3),
            Failure::SchemaRootNoOwnedRightsMatch(NodeType::StateTransition, 4),
            Failure::SchemaRootNoPublicRightsMatch(
                NodeType::StateTransition,
                2,
            ),
            Failure::SchemaRootNoAbiMatch {
                node_type: NodeType::StateTransition,
                action_id: 0,
            },
        ];

        let extension_failures = vec![
            Failure::SchemaRootNoParentPublicRightsMatch(
                NodeType::Extension,
                2,
            ),
            Failure::SchemaRootNoPublicRightsMatch(NodeType::Extension, 2),
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

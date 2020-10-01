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
    ExtensionAbi, ExtensionAction, FieldType, GenesisAbi, GenesisAction, NodeAction, Occurences,
    Procedure, TransitionAbi, TransitionAction,
};

// Here we can use usize since encoding/decoding makes sure that it's u16
pub type AssignmentsType = usize;
pub type ValenciesType = usize;
pub type MetadataStructure = BTreeMap<FieldType, Occurences<u16>>;
pub type ValenciesStructure = BTreeSet<ValenciesType>;
pub type SealsStructure = BTreeMap<AssignmentsType, Occurences<u16>>;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
/// Node type: genesis, extensions and state transitions
pub enum NodeType {
    /// Genesis node: single node per contract, defining contract and committing
    /// to a specific schema and underlying chain hash
    #[display("genesis")]
    Genesis,

    /// Multiple points for decentralized & unowned contract extension,
    /// committing either to a genesis or some state transition via their
    /// valencies
    #[display("extension")]
    Extension,

    /// State transition performing owned change to the state data and
    /// committing to (potentially multiple) ancestors (i.e. genesis, extensions
    /// and/or  other state transitions) via spending corresponding transaction
    /// outputs assigned some state by ancestors
    #[display("transition")]
    StateTransition,
}

/// Trait defining common API for all node type schemata
pub trait NodeSchema {
    type Action: NodeAction;

    fn node_type(&self) -> NodeType;
    fn metadata(&self) -> &MetadataStructure;
    fn closes(&self) -> &SealsStructure;
    fn extends(&self) -> &ValenciesStructure;
    fn defines(&self) -> &SealsStructure;
    fn valencies(&self) -> &ValenciesStructure;
    fn abi(&self) -> &BTreeMap<Self::Action, Procedure>;
}

#[derive(Clone, PartialEq, Debug, Display, AsAny)]
#[display(Debug)]
pub struct GenesisSchema {
    pub metadata: MetadataStructure,
    pub defines: SealsStructure,
    pub valencies: ValenciesStructure,
    pub abi: GenesisAbi,
}

#[derive(Clone, PartialEq, Debug, Display, AsAny)]
#[display(Debug)]
pub struct ExtensionSchema {
    pub metadata: MetadataStructure,
    pub extends: ValenciesStructure,
    pub defines: SealsStructure,
    pub valencies: ValenciesStructure,
    pub abi: ExtensionAbi,
}

#[derive(Clone, PartialEq, Debug, Display, AsAny)]
#[display(Debug)]
pub struct TransitionSchema {
    pub metadata: MetadataStructure,
    pub closes: SealsStructure,
    pub defines: SealsStructure,
    pub valencies: ValenciesStructure,
    pub abi: TransitionAbi,
}

lazy_static! {
    static ref EMPTY_SEALS: SealsStructure = SealsStructure::new();
    static ref EMPTY_VALENCIES: ValenciesStructure = ValenciesStructure::new();
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
    fn closes(&self) -> &SealsStructure {
        &EMPTY_SEALS
    }
    #[inline]
    fn extends(&self) -> &ValenciesStructure {
        &EMPTY_VALENCIES
    }
    #[inline]
    fn defines(&self) -> &SealsStructure {
        &self.defines
    }
    #[inline]
    fn valencies(&self) -> &ValenciesStructure {
        &self.valencies
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
    fn closes(&self) -> &SealsStructure {
        &EMPTY_SEALS
    }
    #[inline]
    fn extends(&self) -> &ValenciesStructure {
        &self.extends
    }
    #[inline]
    fn defines(&self) -> &SealsStructure {
        &self.defines
    }
    #[inline]
    fn valencies(&self) -> &ValenciesStructure {
        &self.valencies
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
    fn closes(&self) -> &SealsStructure {
        &self.closes
    }
    #[inline]
    fn extends(&self) -> &ValenciesStructure {
        &EMPTY_VALENCIES
    }
    #[inline]
    fn defines(&self) -> &SealsStructure {
        &self.defines
    }
    #[inline]
    fn valencies(&self) -> &ValenciesStructure {
        &self.valencies
    }
    #[inline]
    fn abi(&self) -> &BTreeMap<Self::Action, Procedure> {
        &self.abi
    }
}

mod strict_encoding {
    use super::*;
    use crate::strict_encoding::{Error, StrictDecode, StrictEncode};

    impl StrictEncode for GenesisSchema {
        type Error = Error;

        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
            self.metadata.strict_encode(&mut e)?;
            self.defines.strict_encode(&mut e)?;
            self.valencies.strict_encode(&mut e)?;
            self.abi.strict_encode(&mut e)?;
            // We keep this parameter for future script extended info (like ABI)
            Vec::<u8>::new().strict_encode(&mut e)
        }
    }

    impl StrictDecode for GenesisSchema {
        type Error = Error;

        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
            let me = Self {
                metadata: MetadataStructure::strict_decode(&mut d)?,
                defines: SealsStructure::strict_decode(&mut d)?,
                valencies: ValenciesStructure::strict_decode(&mut d)?,
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
        type Error = Error;

        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
            self.metadata.strict_encode(&mut e)?;
            self.extends.strict_encode(&mut e)?;
            self.defines.strict_encode(&mut e)?;
            self.valencies.strict_encode(&mut e)?;
            self.abi.strict_encode(&mut e)?;
            // We keep this parameter for future script extended info (like ABI)
            Vec::<u8>::new().strict_encode(&mut e)
        }
    }

    impl StrictDecode for ExtensionSchema {
        type Error = Error;

        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
            let me = Self {
                metadata: MetadataStructure::strict_decode(&mut d)?,
                extends: ValenciesStructure::strict_decode(&mut d)?,
                defines: SealsStructure::strict_decode(&mut d)?,
                valencies: ValenciesStructure::strict_decode(&mut d)?,
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
        type Error = Error;

        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
            self.metadata.strict_encode(&mut e)?;
            self.closes.strict_encode(&mut e)?;
            self.defines.strict_encode(&mut e)?;
            self.valencies.strict_encode(&mut e)?;
            self.abi.strict_encode(&mut e)?;
            // We keep this parameter for future script extended info (like ABI)
            Vec::<u8>::new().strict_encode(&mut e)
        }
    }

    impl StrictDecode for TransitionSchema {
        type Error = Error;

        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
            let me = Self {
                metadata: MetadataStructure::strict_decode(&mut d)?,
                closes: SealsStructure::strict_decode(&mut d)?,
                defines: SealsStructure::strict_decode(&mut d)?,
                valencies: ValenciesStructure::strict_decode(&mut d)?,
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
    use crate::rgb::schema::SchemaVerify;
    use crate::rgb::validation;
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
                        status.add_failure(validation::Failure::SchemaRootNoClosedAssignmentsMatch(
                            node_type,
                            *assignments_type,
                        ))
                    }
                    Some(root_occ) if occ != root_occ => {
                        status.add_failure(validation::Failure::SchemaRootNoClosedAssignmentsMatch(
                            node_type,
                            *assignments_type,
                        ))
                    }
                    _ => &status,
                };
            }

            for (assignments_type, occ) in self.defines() {
                match root.defines().get(assignments_type) {
                    None => status.add_failure(
                        validation::Failure::SchemaRootNoDefinedAssignmentsMatch(
                            node_type,
                            *assignments_type,
                        ),
                    ),
                    Some(root_occ) if occ != root_occ => status.add_failure(
                        validation::Failure::SchemaRootNoDefinedAssignmentsMatch(
                            node_type,
                            *assignments_type,
                        ),
                    ),
                    _ => &status,
                };
            }

            for valencies_type in self.extends() {
                if !root.extends().contains(valencies_type) {
                    status.add_failure(validation::Failure::SchemaRootNoExtendedValenciesMatch(
                        node_type,
                        *valencies_type,
                    ));
                }
            }

            for valencies_type in self.valencies() {
                if !root.valencies().contains(valencies_type) {
                    status.add_failure(validation::Failure::SchemaRootNoDefinedValenciesMatch(
                        node_type,
                        *valencies_type,
                    ));
                }
            }

            for (action, proc) in self.abi() {
                match root.abi().get(action) {
                    None => status.add_failure(validation::Failure::SchemaRootNoAbiMatch {
                        node_type,
                        action_id: action
                            .to_u16()
                            .expect("Action type can't exceed 16-bit integer"),
                    }),
                    Some(root_proc) if root_proc != proc => {
                        status.add_failure(validation::Failure::SchemaRootNoAbiMatch {
                            node_type,
                            action_id: action
                                .to_u16()
                                .expect("Action type can't exceed 16-bit integer"),
                        })
                    }
                    _ => &status,
                };
            }

            status
        }
    }
}

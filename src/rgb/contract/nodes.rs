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

use super::{data, AssignmentsVariant, SealDefinition};
use crate::bp;
use crate::client_side_validation::{commit_strategy, CommitEncodeWithStrategy, ConsensusCommit};
use crate::rgb::{
    schema, Assignment, ContractId, FieldData, Metadata, SchemaId, SimplicityScript, TransitionId,
};

pub type Assignments = BTreeMap<schema::AssignmentsType, AssignmentsVariant>;
impl CommitEncodeWithStrategy for Assignments {
    type Strategy = commit_strategy::Merklization;
}

pub trait Node {
    fn metadata(&self) -> &Metadata;
    fn assignments(&self) -> &Assignments;
    fn script(&self) -> &SimplicityScript;

    #[inline]
    fn field_types(&self) -> Vec<schema::FieldType> {
        self.metadata().keys().cloned().collect()
    }

    #[inline]
    fn assignment_types(&self) -> Vec<schema::AssignmentsType> {
        self.assignments().keys().cloned().collect()
    }

    #[inline]
    fn assignments_by_type(&self, t: schema::AssignmentsType) -> Vec<&AssignmentsVariant> {
        self.assignments()
            .into_iter()
            .filter_map(|(t2, a)| if *t2 == t { Some(a) } else { None })
            .collect()
    }

    fn defined_seals(
        &self,
        assignments_type: schema::AssignmentsType,
    ) -> Option<Vec<SealDefinition>> {
        self.assignments()
            .get(&assignments_type)
            .map(|item| match item {
                AssignmentsVariant::Void(set) => set
                    .iter()
                    .filter_map(|assign| match assign {
                        Assignment::Revealed {
                            seal_definition, ..
                        } => Some(seal_definition),
                        _ => None,
                    })
                    .cloned()
                    .collect(),
                AssignmentsVariant::Homomorphic(set) => set
                    .iter()
                    .filter_map(|assign| match assign {
                        Assignment::Revealed {
                            seal_definition, ..
                        } => Some(seal_definition),
                        _ => None,
                    })
                    .cloned()
                    .collect(),
                AssignmentsVariant::Hashed(set) => set
                    .iter()
                    .filter_map(|assign| match assign {
                        Assignment::Revealed {
                            seal_definition, ..
                        } => Some(seal_definition),
                        _ => None,
                    })
                    .cloned()
                    .collect(),
            })
    }

    fn u8(&self, field_type: schema::FieldType) -> FieldData<u8> {
        field_extract!(self, field_type, U8)
    }
    fn u16(&self, field_type: schema::FieldType) -> FieldData<u16> {
        field_extract!(self, field_type, U16)
    }
    fn u32(&self, field_type: schema::FieldType) -> FieldData<u32> {
        field_extract!(self, field_type, U32)
    }
    fn u64(&self, field_type: schema::FieldType) -> FieldData<u64> {
        field_extract!(self, field_type, U64)
    }
    fn i8(&self, field_type: schema::FieldType) -> FieldData<i8> {
        field_extract!(self, field_type, I8)
    }
    fn i16(&self, field_type: schema::FieldType) -> FieldData<i16> {
        field_extract!(self, field_type, I16)
    }
    fn i32(&self, field_type: schema::FieldType) -> FieldData<i32> {
        field_extract!(self, field_type, I32)
    }
    fn i64(&self, field_type: schema::FieldType) -> FieldData<i64> {
        field_extract!(self, field_type, I64)
    }
    fn f32(&self, field_type: schema::FieldType) -> FieldData<f32> {
        field_extract!(self, field_type, F32)
    }
    fn f64(&self, field_type: schema::FieldType) -> FieldData<f64> {
        field_extract!(self, field_type, F64)
    }
    fn bytes(&self, field_type: schema::FieldType) -> FieldData<Vec<u8>> {
        field_extract!(self, field_type, Bytes)
    }
    fn string(&self, field_type: schema::FieldType) -> FieldData<String> {
        field_extract!(self, field_type, String)
    }
}

#[derive(Clone, Debug)]
pub struct Genesis {
    schema_id: SchemaId,
    network: bp::Network,
    metadata: Metadata,
    // Since genesis relies on the same data structure as Transition, it uses
    // `homorphic_factor` value for homomorphic state data; which does not make
    // any sense in the case of the Genesis. The value of the factor thus MAY
    // be ignored during the verification
    assignments: Assignments,
    script: SimplicityScript,
}

#[derive(Clone, Debug, Default)]
pub struct Transition {
    type_id: schema::TransitionType,
    metadata: Metadata,
    assignments: Assignments,
    script: SimplicityScript,
}

impl Genesis {
    #[inline]
    pub fn contract_id(&self) -> ContractId {
        self.clone().consensus_commit()
    }
}

impl CommitEncodeWithStrategy for Genesis {
    type Strategy = commit_strategy::UsingStrict;
}

impl ConsensusCommit for Genesis {
    type Commitment = ContractId;
}

impl Transition {
    #[inline]
    pub fn transition_id(&self) -> TransitionId {
        self.clone().consensus_commit()
    }
}

impl CommitEncodeWithStrategy for Transition {
    type Strategy = commit_strategy::UsingStrict;
}

impl ConsensusCommit for Transition {
    type Commitment = TransitionId;
}

impl Node for Genesis {
    #[inline]
    fn metadata(&self) -> &Metadata {
        &self.metadata
    }
    #[inline]
    fn assignments(&self) -> &Assignments {
        &self.assignments
    }
    #[inline]
    fn script(&self) -> &SimplicityScript {
        &self.script
    }
}

impl Node for Transition {
    #[inline]
    fn metadata(&self) -> &Metadata {
        &self.metadata
    }
    #[inline]
    fn assignments(&self) -> &Assignments {
        &self.assignments
    }
    #[inline]
    fn script(&self) -> &SimplicityScript {
        &self.script
    }
}

impl Genesis {
    pub fn with(
        schema_id: SchemaId,
        network: bp::Network,
        metadata: Metadata,
        assignments: Assignments,
        script: SimplicityScript,
    ) -> Self {
        Self {
            schema_id,
            network,
            metadata,
            assignments,
            script,
        }
    }

    #[inline]
    #[allow(dead_code)]
    pub fn schema_id(&self) -> SchemaId {
        self.schema_id
    }

    #[inline]
    #[allow(dead_code)]
    pub fn network(&self) -> bp::Network {
        self.network
    }
}

impl Transition {
    pub fn with(
        type_id: schema::TransitionType,
        metadata: Metadata,
        assignments: Assignments,
        script: SimplicityScript,
    ) -> Self {
        Self {
            type_id,
            metadata,
            assignments,
            script,
        }
    }

    #[inline]
    #[allow(dead_code)]
    pub fn type_id(&self) -> schema::TransitionType {
        self.type_id
    }
}

mod strict_encoding {
    use super::*;
    use crate::strict_encoding::{Error, StrictDecode, StrictEncode};
    use std::io;

    impl StrictEncode for Genesis {
        type Error = Error;

        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
            Ok(strict_encode_list!(e;
                    self.schema_id,
                    self.network,
                    self.metadata,
                    self.assignments,
                    self.script))
        }
    }

    impl StrictDecode for Genesis {
        type Error = Error;

        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
            Ok(Self {
                schema_id: SchemaId::strict_decode(&mut d)?,
                network: bp::Network::strict_decode(&mut d)?,
                metadata: Metadata::strict_decode(&mut d)?,
                assignments: Assignments::strict_decode(&mut d)?,
                script: SimplicityScript::strict_decode(&mut d)?,
            })
        }
    }

    impl StrictEncode for Transition {
        type Error = Error;

        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
            Ok(strict_encode_list!(e;
                    self.type_id,
                    self.metadata,
                    self.assignments,
                    self.script))
        }
    }

    impl StrictDecode for Transition {
        type Error = Error;

        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
            Ok(Self {
                type_id: schema::TransitionType::strict_decode(&mut d)?,
                metadata: Metadata::strict_decode(&mut d)?,
                assignments: Assignments::strict_decode(&mut d)?,
                script: SimplicityScript::strict_decode(&mut d)?,
            })
        }
    }
}

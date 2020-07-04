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

use bitcoin::hashes::{sha256t, Hash};

use super::{Ancestors, Assignments, AssignmentsVariant, AutoConceal};
use crate::bp;
use crate::client_side_validation::{commit_strategy, CommitEncodeWithStrategy, ConsensusCommit};
use crate::rgb::schema::AssignmentsType;
use crate::rgb::{schema, seal, Metadata, SchemaId, SimplicityScript};

// TODO: Check the data
static MIDSTATE_NODE_ID: [u8; 32] = [
    25, 205, 224, 91, 171, 217, 131, 31, 140, 104, 5, 155, 127, 82, 14, 81, 58, 245, 79, 165, 114,
    243, 110, 60, 133, 174, 103, 187, 103, 230, 9, 106,
];

tagged_hash!(
    NodeId,
    NodeIdTag,
    MIDSTATE_NODE_ID,
    doc = "Unique node (genesis and state transition) identifier equivalent to the commitment hash"
);

tagged_hash!(
    ContractId,
    ContractIdTag,
    MIDSTATE_NODE_ID,
    doc = "Unique contract identifier equivalent to the contract genesis commitment hash"
);

impl From<NodeId> for ContractId {
    fn from(node_id: NodeId) -> Self {
        ContractId::from_inner(node_id.into_inner())
    }
}

pub trait Node {
    fn node_id(&self) -> NodeId;

    /// Returns `Some([schema::TransitionType])` for Transitions or None for
    /// Genesis node
    fn type_id(&self) -> Option<schema::TransitionType>;

    fn ancestors(&self) -> &Ancestors;
    fn metadata(&self) -> &Metadata;
    fn assignments(&self) -> &Assignments;
    fn assignments_mut(&mut self) -> &mut Assignments;
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
    fn assignments_by_type(&self, t: schema::AssignmentsType) -> Option<&AssignmentsVariant> {
        self.assignments()
            .into_iter()
            .find_map(|(t2, a)| if *t2 == t { Some(a) } else { None })
    }

    fn all_seal_definitions(&self) -> Vec<seal::Confidential> {
        self.assignments()
            .into_iter()
            .flat_map(|(_, assignment)| assignment.all_seals())
            .collect()
    }

    fn known_seal_definitions(&self) -> Vec<&seal::Revealed> {
        self.assignments()
            .into_iter()
            .flat_map(|(_, assignment)| assignment.known_seals())
            .collect()
    }

    fn known_seal_definitions_by_type(
        &self,
        assignment_type: AssignmentsType,
    ) -> Vec<&seal::Revealed> {
        self.assignments_by_type(assignment_type)
            .map(AssignmentsVariant::known_seals)
            .unwrap_or(vec![])
    }
}

impl AutoConceal for &mut dyn Node {
    fn conceal_except(&mut self, seals: &Vec<seal::Confidential>) -> usize {
        let mut count = 0;
        for (_, assignment) in self.assignments_mut() {
            count += assignment.conceal_except(seals);
        }
        count
    }
}

#[derive(Clone, Debug)]
pub struct Genesis {
    schema_id: SchemaId,
    network: bp::Network,
    metadata: Metadata,
    assignments: Assignments,
    script: SimplicityScript,
}

#[derive(Clone, Debug, Default)]
pub struct Transition {
    type_id: schema::TransitionType,
    metadata: Metadata,
    ancestors: Ancestors,
    assignments: Assignments,
    script: SimplicityScript,
}

impl CommitEncodeWithStrategy for Genesis {
    type Strategy = commit_strategy::UsingStrict;
}

impl ConsensusCommit for Genesis {
    type Commitment = NodeId;
}

impl CommitEncodeWithStrategy for Transition {
    type Strategy = commit_strategy::UsingStrict;
}

impl ConsensusCommit for Transition {
    type Commitment = NodeId;
}

impl Node for Genesis {
    #[inline]

    fn node_id(&self) -> NodeId {
        self.clone().consensus_commit()
    }

    #[inline]
    fn type_id(&self) -> Option<schema::TransitionType> {
        None
    }

    #[inline]
    fn ancestors(&self) -> &Ancestors {
        lazy_static! {
            static ref ANCESTORS: Ancestors = Ancestors::new();
        }
        &ANCESTORS
    }

    #[inline]
    fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    #[inline]
    fn assignments(&self) -> &Assignments {
        &self.assignments
    }

    #[inline]
    fn assignments_mut(&mut self) -> &mut Assignments {
        &mut self.assignments
    }

    #[inline]
    fn script(&self) -> &SimplicityScript {
        &self.script
    }
}

impl Node for Transition {
    #[inline]
    fn node_id(&self) -> NodeId {
        self.clone().consensus_commit()
    }

    #[inline]
    fn type_id(&self) -> Option<schema::TransitionType> {
        Some(self.type_id)
    }

    #[inline]
    fn ancestors(&self) -> &Ancestors {
        &self.ancestors
    }

    #[inline]
    fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    #[inline]
    fn assignments(&self) -> &Assignments {
        &self.assignments
    }

    #[inline]
    fn assignments_mut(&mut self) -> &mut Assignments {
        &mut self.assignments
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
    pub fn contract_id(&self) -> ContractId {
        ContractId::from(self.node_id())
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
        ancestors: Ancestors,
        assignments: Assignments,
        script: SimplicityScript,
    ) -> Self {
        Self {
            type_id,
            metadata,
            ancestors,
            assignments,
            script,
        }
    }
}

mod strict_encoding {
    use super::*;
    use crate::strict_encoding::{strategies, Error, Strategy, StrictDecode, StrictEncode};
    use std::io;

    impl Strategy for NodeId {
        type Strategy = strategies::HashFixedBytes;
    }

    impl Strategy for ContractId {
        type Strategy = strategies::HashFixedBytes;
    }

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
                    self.ancestors,
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
                ancestors: Ancestors::strict_decode(&mut d)?,
                assignments: Assignments::strict_decode(&mut d)?,
                script: SimplicityScript::strict_decode(&mut d)?,
            })
        }
    }
}

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

use bitcoin::hashes::{sha256, sha256t, Hash, HashEngine};

use super::{Ancestors, Assignments, AssignmentsVariant, AutoConceal};
use crate::bp;
use crate::client_side_validation::{commit_strategy, CommitEncodeWithStrategy, ConsensusCommit};
use crate::paradigms::client_side_validation::CommitEncode;
use crate::rgb::schema::AssignmentsType;
use crate::rgb::{schema, seal, Metadata, SchemaId, SimplicityScript};

lazy_static! {
    static ref MIDSTATE_NODE_ID: [u8; 32] = {
        let hash = sha256::Hash::hash(b"rgb:node");
        let mut engine = sha256::Hash::engine();
        engine.input(&hash[..]);
        engine.input(&hash[..]);
        engine.midstate().0
    };
}

tagged_hash!(
    NodeId,
    NodeIdTag,
    MIDSTATE_NODE_ID,
    doc = "Unique node (genesis and state transition) identifier equivalent to the commitment hash"
);

impl CommitEncodeWithStrategy for NodeId {
    type Strategy = commit_strategy::UsingStrict;
}

tagged_hash!(
    ContractId,
    ContractIdTag,
    MIDSTATE_NODE_ID,
    doc = "Unique contract identifier equivalent to the contract genesis commitment hash"
);

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
    network: bp::Chains,
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
        network: bp::Chains,
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
        ContractId::from_inner(self.node_id().into_inner())
    }

    #[inline]
    #[allow(dead_code)]
    pub fn schema_id(&self) -> SchemaId {
        self.schema_id
    }

    #[inline]
    #[allow(dead_code)]
    pub fn network(&self) -> &bp::Chains {
        &self.network
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

    // ![CONSENSUS-CRITICAL]: Commit encode is different for genesis from strict
    //                        encode since we only commit to chain genesis block
    //                        hash and not all chain parameters.
    // See <https://github.com/LNP-BP/LNPBPs/issues/58> for details.
    impl CommitEncode for Genesis {
        fn commit_encode<E: io::Write>(self, mut e: E) -> usize {
            let mut encoder = || -> Result<_, Error> {
                let mut len = self.schema_id.strict_encode(&mut e)?;
                len += self.network.as_genesis_hash().strict_encode(&mut e)?;
                Ok(strict_encode_list!(e; len;
                    self.metadata,
                    self.assignments,
                    self.script
                ))
            };
            encoder().expect("Strict encoding of genesis data must not fail")
        }
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
                network: bp::Chains::strict_decode(&mut d)?,
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

    #[cfg(test)]
    mod test {
        use super::*;
        use crate::bp::chain::{Chains, GENESIS_HASH_MAINNET};
        use crate::commit_verify::CommitVerify;
        use crate::strict_encoding::strict_encode;
        use std::io::Write;

        // Making sure that <https://github.com/LNP-BP/LNPBPs/issues/58>
        // is fulfilled and we do not occasionally commit to all chain
        // parameters (which may vary and change with time) in RGB contract id
        #[test]
        fn test_genesis_commit_ne_strict() {
            let genesis = Genesis {
                schema_id: Default::default(),
                network: Chains::Mainnet,
                metadata: Default::default(),
                assignments: Default::default(),
                script: vec![],
            };
            assert_ne!(
                strict_encode(&genesis).unwrap(),
                genesis.clone().consensus_commit().to_vec()
            );

            let mut encoder = io::Cursor::new(vec![]);
            genesis.schema_id.strict_encode(&mut encoder).unwrap();
            encoder.write_all(GENESIS_HASH_MAINNET).unwrap();
            genesis.metadata.strict_encode(&mut encoder).unwrap();
            genesis.assignments.strict_encode(&mut encoder).unwrap();
            genesis.script.strict_encode(&mut encoder).unwrap();
            assert_eq!(
                genesis.consensus_commit(),
                NodeId::commit(&encoder.into_inner())
            );
        }
    }
}

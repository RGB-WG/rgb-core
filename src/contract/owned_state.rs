// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2023 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2019-2023 Dr Maxim Orlovsky. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use core::cmp::Ordering;
use core::fmt::Debug;
use std::collections::HashMap;
use std::io;

use commit_verify::{CommitEncode, Conceal};
use strict_encoding::{StrictEncode, StrictWriter};

use super::{
    attachment, data, seal, value, ConcealSeals, ConcealState, ConfidentialState, RevealSeals,
    RevealedState,
};
use crate::LIB_NAME_RGB;

/// Categories of the state
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub enum StateType {
    /// No state data
    Void,

    /// Value-based state, i.e. which can be committed to with a Pedersen
    /// commitment
    Value,

    /// State defined with custom data
    Data,

    /// Attached data container
    Attachment,
}
pub trait State: Debug {
    type Confidential: ConfidentialState;
    type Revealed: RevealedState;
}

#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct DeclarativeStrategy;
impl State for DeclarativeStrategy {
    type Confidential = data::Void;
    type Revealed = data::Void;
}

#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct PedersenStrategy;
impl State for PedersenStrategy {
    type Confidential = value::Confidential;
    type Revealed = value::Revealed;
}

#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct HashStrategy;
impl State for HashStrategy {
    type Confidential = data::Confidential;
    type Revealed = data::Revealed;
}

#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct AttachmentStrategy;
impl State for AttachmentStrategy {
    type Confidential = attachment::Confidential;
    type Revealed = attachment::Revealed;
}

/// State data are assigned to a seal definition, which means that they are
/// owned by a person controlling spending of the seal UTXO, unless the seal
/// is closed, indicating that a transfer of ownership had taken place
#[derive(Clone, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(
    lib = LIB_NAME_RGB,
    tags = custom,
    dumb = { Self::Confidential { seal: strict_dumb!(), state: strict_dumb!() } }
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "snake_case")
)]
pub enum Assignment<StateType>
where
    StateType: State,
    // Deterministic ordering requires Eq operation, so the confidential
    // state must have it
    StateType::Confidential: PartialEq + Eq,
    StateType::Confidential: From<<StateType::Revealed as Conceal>::Concealed>,
{
    #[strict_type(tag = 0x00)]
    Confidential {
        seal: seal::Confidential,
        state: StateType::Confidential,
    },
    #[strict_type(tag = 0x04)]
    Revealed {
        seal: seal::Revealed,
        state: StateType::Revealed,
    },
    #[strict_type(tag = 0x02)]
    ConfidentialSeal {
        seal: seal::Confidential,
        state: StateType::Revealed,
    },
    #[strict_type(tag = 0x01)]
    ConfidentialState {
        seal: seal::Revealed,
        state: StateType::Confidential,
    },
}

// Consensus-critical!
// Assignment indexes are part of the transition ancestor's commitment, so
// here we use deterministic ordering based on hash values of the concealed
// seal data contained within the assignment
impl<StateType> PartialOrd for Assignment<StateType>
where
    StateType: State,
    StateType::Confidential: PartialEq + Eq,
    StateType::Confidential: From<<StateType::Revealed as Conceal>::Concealed>,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.to_confidential_seal()
            .partial_cmp(&other.to_confidential_seal())
    }
}

impl<StateType> Ord for Assignment<StateType>
where
    StateType: State,
    StateType::Confidential: PartialEq + Eq,
    StateType::Confidential: From<<StateType::Revealed as Conceal>::Concealed>,
{
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_confidential_seal()
            .cmp(&other.to_confidential_seal())
    }
}

impl<StateType> PartialEq for Assignment<StateType>
where
    StateType: State,
    StateType::Confidential: PartialEq + Eq,
    StateType::Confidential: From<<StateType::Revealed as Conceal>::Concealed>,
{
    fn eq(&self, other: &Self) -> bool {
        self.to_confidential_seal() == other.to_confidential_seal() &&
            self.to_confidential_state() == other.to_confidential_state()
    }
}

impl<StateType> Eq for Assignment<StateType>
where
    StateType: State,
    StateType::Confidential: PartialEq + Eq,
    StateType::Confidential: From<<StateType::Revealed as Conceal>::Concealed>,
{
}

impl<StateType> Assignment<StateType>
where
    StateType: State,
    StateType::Confidential: PartialEq + Eq,
    StateType::Confidential: From<<StateType::Revealed as Conceal>::Concealed>,
{
    pub fn revealed(seal: seal::Revealed, state: StateType::Revealed) -> Self {
        Assignment::Revealed { seal, state }
    }

    pub fn with_seal_replaced(assignment: &Self, seal: seal::Revealed) -> Self {
        match assignment {
            Assignment::Confidential { seal: _, state } |
            Assignment::ConfidentialState { seal: _, state } => Assignment::ConfidentialState {
                seal,
                state: state.clone(),
            },
            Assignment::ConfidentialSeal { seal: _, state } |
            Assignment::Revealed { seal: _, state } => Assignment::Revealed {
                seal,
                state: state.clone(),
            },
        }
    }

    pub fn to_confidential_seal(&self) -> seal::Confidential {
        match self {
            Assignment::Revealed { seal, .. } | Assignment::ConfidentialState { seal, .. } => {
                seal.conceal()
            }
            Assignment::Confidential { seal, .. } | Assignment::ConfidentialSeal { seal, .. } => {
                *seal
            }
        }
    }

    pub fn revealed_seal(&self) -> Option<seal::Revealed> {
        match self {
            Assignment::Revealed { seal, .. } | Assignment::ConfidentialState { seal, .. } => {
                Some(*seal)
            }
            Assignment::Confidential { .. } | Assignment::ConfidentialSeal { .. } => None,
        }
    }

    pub fn to_confidential_state(&self) -> StateType::Confidential {
        match self {
            Assignment::Revealed { state, .. } | Assignment::ConfidentialSeal { state, .. } => {
                state.conceal().into()
            }
            Assignment::Confidential { state, .. } |
            Assignment::ConfidentialState { state, .. } => state.clone(),
        }
    }

    pub fn as_revealed_state(&self) -> Option<&StateType::Revealed> {
        match self {
            Assignment::Revealed { state, .. } | Assignment::ConfidentialSeal { state, .. } => {
                Some(state)
            }
            Assignment::Confidential { .. } | Assignment::ConfidentialState { .. } => None,
        }
    }

    pub fn as_revealed(&self) -> Option<(&seal::Revealed, &StateType::Revealed)> {
        match self {
            Assignment::Revealed { seal, state } => Some((seal, state)),
            _ => None,
        }
    }

    pub fn to_revealed(&self) -> Option<(seal::Revealed, StateType::Revealed)> {
        match self {
            Assignment::Revealed { seal, state } => Some((*seal, state.clone())),
            _ => None,
        }
    }

    pub fn into_revealed(self) -> Option<(seal::Revealed, StateType::Revealed)> {
        match self {
            Assignment::Revealed { seal, state } => Some((seal, state)),
            _ => None,
        }
    }
}

impl<StateType> Conceal for Assignment<StateType>
where
    Self: Clone,
    StateType: State,
    StateType::Confidential: PartialEq + Eq,
    StateType::Confidential: From<<StateType::Revealed as Conceal>::Concealed>,
{
    type Concealed = Self;

    fn conceal(&self) -> Self::Concealed {
        match self {
            Assignment::Confidential { .. } => self.clone(),
            Assignment::ConfidentialState { seal, state } => Self::Confidential {
                seal: seal.conceal(),
                state: state.clone(),
            },
            Assignment::Revealed { seal, state } => Self::Confidential {
                seal: seal.conceal(),
                state: state.conceal().into(),
            },
            Assignment::ConfidentialSeal { seal, state } => Self::Confidential {
                seal: *seal,
                state: state.conceal().into(),
            },
        }
    }
}

impl<StateType> RevealSeals for Assignment<StateType>
where
    StateType: State,
    StateType::Revealed: Conceal,
    StateType::Confidential: PartialEq + Eq,
    <StateType as State>::Confidential: From<<StateType::Revealed as Conceal>::Concealed>,
{
    fn reveal_seals(&mut self, known_seals: &[seal::Revealed]) -> usize {
        let known_seals: HashMap<seal::Confidential, seal::Revealed> = known_seals
            .iter()
            .map(|rev| (rev.conceal(), *rev))
            .collect();

        let mut counter = 0;
        match self {
            Assignment::Confidential { seal, state } => {
                if let Some(reveal) = known_seals.get(seal) {
                    *self = Assignment::ConfidentialState {
                        seal: *reveal,
                        state: state.clone(),
                    };
                    counter += 1;
                };
            }
            Assignment::ConfidentialSeal { seal, state } => {
                if let Some(reveal) = known_seals.get(seal) {
                    *self = Assignment::Revealed {
                        seal: *reveal,
                        state: state.clone(),
                    };
                    counter += 1;
                };
            }
            _ => {}
        }
        counter
    }
}

impl<StateType> ConcealSeals for Assignment<StateType>
where
    StateType: State,
    StateType::Revealed: Conceal,
    StateType::Confidential: PartialEq + Eq,
    <StateType as State>::Confidential: From<<StateType::Revealed as Conceal>::Concealed>,
{
    fn conceal_seals(&mut self, seals: &[seal::Confidential]) -> usize {
        match self {
            Assignment::Confidential { .. } | Assignment::ConfidentialSeal { .. } => 0,
            Assignment::ConfidentialState { seal, state } => {
                if seals.contains(&seal.conceal()) {
                    *self = Assignment::<StateType>::Confidential {
                        state: state.clone(),
                        seal: seal.conceal(),
                    };
                    1
                } else {
                    0
                }
            }
            Assignment::Revealed { seal, state } => {
                if seals.contains(&seal.conceal()) {
                    *self = Assignment::<StateType>::ConfidentialSeal {
                        state: state.clone(),
                        seal: seal.conceal(),
                    };
                    1
                } else {
                    0
                }
            }
        }
    }
}

impl<StateType> ConcealState for Assignment<StateType>
where
    StateType: State,
    StateType::Revealed: Conceal,
    StateType::Confidential: PartialEq + Eq,
    <StateType as State>::Confidential: From<<StateType::Revealed as Conceal>::Concealed>,
{
    fn conceal_state_except(&mut self, seals: &[seal::Confidential]) -> usize {
        match self {
            Assignment::Confidential { .. } | Assignment::ConfidentialState { .. } => 0,
            Assignment::ConfidentialSeal { seal, state } => {
                if seals.contains(seal) {
                    0
                } else {
                    *self = Assignment::<StateType>::Confidential {
                        state: state.conceal().into(),
                        seal: *seal,
                    };
                    1
                }
            }
            Assignment::Revealed { seal, state } => {
                if seals.contains(&seal.conceal()) {
                    0
                } else {
                    *self = Assignment::<StateType>::ConfidentialState {
                        state: state.conceal().into(),
                        seal: *seal,
                    };
                    1
                }
            }
        }
    }
}

// We can't use `UsingConceal` strategy here since it relies on the
// `commit_encode` of the concealed type, and here the concealed type is again
// `OwnedState`, leading to a recurrency. So we use `strict_encode` of the
// concealed data.
impl<StateType> CommitEncode for Assignment<StateType>
where
    Self: Clone,
    StateType: State,
    StateType::Confidential: PartialEq + Eq,
    StateType::Confidential: From<<StateType::Revealed as Conceal>::Concealed>,
{
    fn commit_encode(&self, e: &mut impl io::Write) {
        let w = StrictWriter::with(u32::MAX as usize, e);
        self.conceal().strict_encode(w).ok();
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn test_encoding_ancestor() {
        let _: ParentOwnedRights = test_vec_decoding_roundtrip(PARENT_RIGHTS).unwrap();
    }

    #[test]
    #[should_panic(expected = "UnexpectedEof")]
    fn test_garbage_ancestor() {
        let mut data = PARENT_RIGHTS.clone();
        data[0] = 0x36 as u8;
        ParentOwnedRights::strict_decode(&data[..]).unwrap();
    }

    // This doesn't use the merkelize() function
    // And constructs the flow by hand for a single element
    // merkelization process
    #[test]
    fn test_parent_rights_encoding_simple() {
        // Create the simplest possible ancestor structure
        // Parent Rights = Map<NodeId::default(), Map<2, [0u16]>>
        let mut assignment = BTreeMap::new();
        let data = 0u16;
        let ty = 2 as schema::OwnedRightType;
        assignment.insert(ty, vec![data]);

        let nodeid = NodeId::default();
        let mut parent_rights = ParentOwnedRights::default();
        parent_rights.as_mut().insert(nodeid, assignment);

        let mut original_commit = vec![];
        parent_rights
            .to_merkle_source()
            .commit_encode(&mut original_commit); // Merkelizes the structure into buf

        // Perform encoding by hand
        // We only have one leaf tupple
        // leaf = (NodqeId::default(), ty, 0u16);

        // Encode the leaf via strict encoding
        let mut encoded_leaf = vec![];
        NodeId::default().strict_encode(&mut encoded_leaf).unwrap();
        ty.strict_encode(&mut encoded_leaf).unwrap();
        0u16.strict_encode(&mut encoded_leaf).unwrap();

        // take the hash of the encoded data as a MerkleNode
        let merkle_node = MerkleNode::hash(&encoded_leaf[..]);

        // merkelize the node with correct tag
        let (root, _) = merklize("parent_owned_right", [merkle_node]);

        // Commit encode the resulting merkle root
        let handmade_commit = root.commit_serialize();

        // This should match with original encoding
        assert_eq!(original_commit, handmade_commit);
    }

    /*
    // Helper to create merkleroot from single merklenode
    fn merkle_single(m: MerkleNode) -> MerkleNode {
        let mut engine2 = MerkleNode::engine();
        let tag = format!("{}:merkle:{}", "", 0);
        let tag_hash = sha256::Hash::hash(tag.as_bytes());
        engine2.input(&tag_hash[..]);
        engine2.input(&tag_hash[..]);
        m.strict_encode(&mut engine2).unwrap();
        0u8.strict_encode(&mut engine2).unwrap();
        MerkleNode::from_engine(engine2)
    }
    */

    // This uses merkelize() function handle multiple values
    #[test]
    fn test_ancestor_encoding_complex() {
        // Create three random vector as assignment variants
        let mut vec1 = vec![];
        let mut rng = thread_rng();
        for i in 0..6 {
            vec1.insert(i, rng.next_u64() as u16);
        }

        let mut vec2 = vec![];
        let mut rng = thread_rng();
        for i in 0..17 {
            vec2.insert(i, rng.next_u64() as u16);
        }

        let mut vec3 = vec![];
        let mut rng = thread_rng();
        for i in 0..11 {
            vec3.insert(i, rng.next_u64() as u16);
        }

        // Create 3 assignment type
        let type1 = 1 as schema::OwnedRightType;
        let type2 = 2 as schema::OwnedRightType;
        let type3 = 3 as schema::OwnedRightType;

        // Create 1 NodeID
        let node_id = NodeId::default();

        // Construct assignments
        let mut assignments = BTreeMap::new();
        assignments.insert(type1, vec1.clone());
        assignments.insert(type2, vec2.clone());
        assignments.insert(type3, vec3.clone());

        // Construct ancestor
        let mut parent_rights = ParentOwnedRights::default();
        parent_rights.as_mut().insert(node_id, assignments);

        // get the commit encoding
        let mut original_commit = vec![];
        parent_rights
            .to_merkle_source()
            .commit_encode(&mut original_commit);

        // Make commitment by hand
        // Create the leaf tupples

        let vec_1: Vec<(NodeId, schema::OwnedRightType, u16)> = vec1
            .iter()
            .map(|i| (NodeId::default(), type1, *i))
            .collect();
        let vec_2: Vec<(NodeId, schema::OwnedRightType, u16)> = vec2
            .iter()
            .map(|i| (NodeId::default(), type2, *i))
            .collect();
        let vec_3: Vec<(NodeId, schema::OwnedRightType, u16)> = vec3
            .iter()
            .map(|i| (NodeId::default(), type3, *i))
            .collect();

        // Combine all to create the final tupple list
        let vec_4: Vec<(NodeId, schema::OwnedRightType, u16)> = [vec_1, vec_2, vec_3].concat();

        // Strict encode each tupple
        // hash the encoding
        // convert each hash into a MerkleNode
        let nodes: Vec<MerkleNode> = vec_4
            .into_iter()
            .map(|item| -> MerkleNode {
                let mut e = vec![];
                item.0.strict_encode(&mut e).unwrap();
                item.1.strict_encode(&mut e).unwrap();
                item.2.strict_encode(&mut e).unwrap();

                MerkleNode::hash(&e[..])
            })
            .collect();

        // Calculate Merkle Root for the the above nodes
        let (root, _) = merklize("parent_owned_right", nodes);

        // Commit encode the root
        let handmade_commit = root.commit_serialize();

        // This should match with the original encoding
        assert_eq!(original_commit, handmade_commit);
    }

    #[test]
    fn test_commitencode_assignments() {
        //Create Declerative variant

        let mut rng = thread_rng();

        let txid_vec: Vec<bitcoin::Txid> = TXID_VEC
            .iter()
            .map(|txid| bitcoin::Txid::from_hex(txid).unwrap())
            .collect();

        let assignment_1 = Assignment::<DeclarativeStrategy>::Revealed {
            seal: Revealed::from(Outpoint::new(txid_vec[0], 1)),
            state: data::Void(),
        };

        let assignment_2 = Assignment::<DeclarativeStrategy>::ConfidentialState {
            seal: Revealed::from(Outpoint::new(txid_vec[1], 2)),
            state: data::Void(),
        };

        let assignment_3 = Assignment::<DeclarativeStrategy>::ConfidentialSeal {
            seal: Revealed::from(Outpoint::new(txid_vec[2], 3)).commit_conceal(),
            state: data::Void(),
        };

        let assignment_4 = Assignment::<DeclarativeStrategy>::Confidential {
            seal: Revealed::from(Outpoint::new(txid_vec[3], 4)).commit_conceal(),
            state: data::Void(),
        };

        let mut set = Vec::new();

        set.push(assignment_1);
        set.push(assignment_2);
        set.push(assignment_3);
        set.push(assignment_4);

        let declarative_variant = TypedAssignments::Void(set);

        // Create Pedersan Variant

        let txid_vec: Vec<bitcoin::Txid> = TXID_VEC
            .iter()
            .map(|txid| bitcoin::Txid::from_hex(txid).unwrap())
            .collect();

        let assignment_1 = Assignment::<PedersenStrategy>::Revealed {
            seal: Revealed::from(Outpoint::new(txid_vec[0], 1)),
            state: value::Revealed::with_amount(10u64, &mut rng),
        };

        let assignment_2 = Assignment::<PedersenStrategy>::ConfidentialState {
            seal: Revealed::from(Outpoint::new(txid_vec[1], 1)),
            state: value::Revealed::with_amount(20u64, &mut rng).commit_conceal(),
        };

        let assignment_3 = Assignment::<PedersenStrategy>::ConfidentialSeal {
            seal: Revealed::from(Outpoint::new(txid_vec[2], 1)).commit_conceal(),
            state: value::Revealed::with_amount(30u64, &mut rng),
        };

        let assignment_4 = Assignment::<PedersenStrategy>::Confidential {
            seal: Revealed::from(Outpoint::new(txid_vec[3], 1)).commit_conceal(),
            state: value::Revealed::with_amount(10u64, &mut rng).commit_conceal(),
        };

        let mut set = Vec::new();

        set.push(assignment_1);
        set.push(assignment_2);
        set.push(assignment_3);
        set.push(assignment_4);

        let pedersen_variant = TypedAssignments::Value(set);

        // Create Hash variant
        let txid_vec: Vec<bitcoin::Txid> = TXID_VEC
            .iter()
            .map(|txid| bitcoin::Txid::from_hex(txid).unwrap())
            .collect();

        let state_data_vec: Vec<data::Revealed> = STATE_DATA
            .iter()
            .map(|data| data::Revealed::Bytes(sha256::Hash::from_hex(data).unwrap().to_vec()))
            .collect();

        let assignment_1 = Assignment::<HashStrategy>::Revealed {
            seal: Revealed::from(Outpoint::new(txid_vec[0], 1)),
            state: state_data_vec[0].clone(),
        };

        let assignment_2 = Assignment::<HashStrategy>::ConfidentialState {
            seal: Revealed::from(Outpoint::new(txid_vec[1], 1)),
            state: state_data_vec[1].clone().commit_conceal(),
        };

        let assignment_3 = Assignment::<HashStrategy>::ConfidentialSeal {
            seal: Revealed::from(Outpoint::new(txid_vec[2], 1)).commit_conceal(),
            state: state_data_vec[2].clone(),
        };

        let assignment_4 = Assignment::<HashStrategy>::Confidential {
            seal: Revealed::from(Outpoint::new(txid_vec[3], 1)).commit_conceal(),
            state: state_data_vec[3].clone().commit_conceal(),
        };

        let mut set = Vec::new();

        set.push(assignment_1);
        set.push(assignment_2);
        set.push(assignment_3);
        set.push(assignment_4);

        let hash_variant = TypedAssignments::Data(set);

        // Create assignemnts

        let type1 = 1 as schema::OwnedRightType;
        let type2 = 2 as schema::OwnedRightType;
        let type3 = 3 as schema::OwnedRightType;
        let mut owned_rights = OwnedRights::default();
        owned_rights
            .as_mut()
            .insert(type1, declarative_variant.clone());
        owned_rights
            .as_mut()
            .insert(type2, pedersen_variant.clone());
        owned_rights.as_mut().insert(type3, hash_variant.clone());

        let mut original_encoding = vec![];
        owned_rights
            .to_merkle_source()
            .commit_encode(&mut original_encoding);

        // Hand calculate commitment
        // create individual leaves
        let declarative_leaves: Vec<(schema::OwnedRightType, MerkleNode)> = declarative_variant
            .to_declarative_assignments()
            .iter()
            .map(|assignment| {
                (type1, MerkleNode::hash(&CommitEncode::commit_serialize(assignment)))
            })
            .collect();

        let pedersan_leaves: Vec<(schema::OwnedRightType, MerkleNode)> = pedersen_variant
            .to_value_assignments()
            .iter()
            .map(|assignment| {
                (type2, MerkleNode::hash(&CommitEncode::commit_serialize(assignment)))
            })
            .collect();

        let hash_leaves: Vec<(schema::OwnedRightType, MerkleNode)> = hash_variant
            .to_data_assignments()
            .iter()
            .map(|assignment| {
                (type3, MerkleNode::hash(&CommitEncode::commit_serialize(assignment)))
            })
            .collect();

        // Combine all of them in a single collection
        let all_leaves = [declarative_leaves, pedersan_leaves, hash_leaves].concat();

        // create MerkleNodes from each leaf
        let nodes: Vec<MerkleNode> = all_leaves
            .iter()
            .map(|item| MerkleNode::hash(&CommitEncode::commit_serialize(item)))
            .collect();

        // compute merkle root of all the nodes
        let (root, _) = merklize("owned_right", nodes);

        // Commit encode the root
        let handmade_encoding = root.commit_serialize();

        // This should match with original encoding
        assert_eq!(original_encoding, handmade_encoding);
    }
}

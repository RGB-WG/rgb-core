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

use amplify::AsAny;
use core::cmp::Ordering;
use core::fmt::Debug;
use std::collections::HashMap;
use std::io;

use commit_verify::{
    merkle::MerkleNode, CommitConceal, CommitEncode, ConsensusCommit,
};
use strict_encoding::{StrictDecode, StrictEncode};

use super::{
    data, seal, value, ConcealSeals, ConcealState, EndpointValueMap,
    NoDataError, SealEndpoint, SealValueMap, SECP256K1_ZKP,
};
use crate::{schema, ConfidentialDataError, StateRetrievalError};

lazy_static! {
    pub(super) static ref EMPTY_ASSIGNMENT_VEC: AssignmentVec =
        AssignmentVec::default();
}

/// Categories of the state
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub enum StateType {
    /// No state data
    Declarative,

    /// Value-based state, i.e. which can be committed to with a Pedersen
    /// commitment
    Value,

    /// State defined with custom data
    Data,
}

#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[display(Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "snake_case")
)]
pub enum AssignmentVec {
    Declarative(Vec<Assignment<DeclarativeStrategy>>),
    DiscreteFiniteField(Vec<Assignment<PedersenStrategy>>),
    CustomData(Vec<Assignment<HashStrategy>>),
}

impl Default for AssignmentVec {
    fn default() -> Self {
        AssignmentVec::Declarative(vec![])
    }
}

impl AssignmentVec {
    pub fn zero_balanced(
        inputs: Vec<value::Revealed>,
        allocations_ours: SealValueMap,
        allocations_theirs: EndpointValueMap,
    ) -> Self {
        if allocations_ours.len() + allocations_theirs.len() == 0 {
            return Self::DiscreteFiniteField(vec![]);
        }

        // Generate random blinding factors
        let mut rng = bitcoin::secp256k1::rand::thread_rng();
        // We will compute the last blinding factors from all others so they
        // sum up to 0, so we need to generate only n - 1 random factors
        let count = allocations_theirs.len() + allocations_ours.len();
        let mut blinding_factors = Vec::<_>::with_capacity(count);
        for _ in 0..count {
            blinding_factors
                .push(secp256k1zkp::SecretKey::new(&SECP256K1_ZKP, &mut rng));
        }

        // We need the last factor to be equal to the difference
        let mut blinding_inputs: Vec<_> =
            inputs.iter().map(|inp| inp.blinding.into()).collect();
        if blinding_inputs.is_empty() {
            blinding_inputs.push(secp256k1zkp::key::ONE_KEY);
        }

        // the last blinding factor must be a correction value
        if !blinding_factors.is_empty() {
            blinding_factors.pop();
            let blinding_correction = SECP256K1_ZKP
                .blind_sum(blinding_inputs.clone(), blinding_factors.clone())
                .expect("SECP256K1_ZKP failure has negligible probability");
            blinding_factors.push(blinding_correction);
        }

        let mut blinding_iter = blinding_factors.into_iter();
        let mut set: Vec<Assignment<_>> = allocations_ours
            .into_iter()
            .map(|(seal_definition, amount)| Assignment::Revealed {
                seal_definition,
                assigned_state: value::Revealed {
                    value: amount,
                    blinding: blinding_iter
                        .next()
                        .expect("Internal inconsistency in `AssignmentsVariant::zero_balanced`")
                        .into(),
                },
            })
            .collect();
        set.extend(
            allocations_theirs
                .into_iter()
                .map(|(seal_proto, amount)| {
                    let assigned_state = value::Revealed {
                        value: amount,
                        blinding: blinding_iter.next().expect(
                            "Internal inconsistency in `AssignmentsVariant::zero_balanced`",
                        ).into(),
                    };
                    match seal_proto {
                        SealEndpoint::ConcealedUtxo(seal_definition) => Assignment::ConfidentialSeal {
                            seal_definition,
                            assigned_state,
                        },
                        SealEndpoint::WitnessVout { method, vout, blinding } => Assignment::Revealed {
                            seal_definition: seal::Revealed { method, txid: None, vout, blinding },
                            assigned_state
                        }
                    }
                }),
        );

        Self::DiscreteFiniteField(set)
    }

    #[inline]
    pub fn state_type(&self) -> StateType {
        match self {
            AssignmentVec::Declarative(_) => StateType::Declarative,
            AssignmentVec::DiscreteFiniteField(_) => StateType::Value,
            AssignmentVec::CustomData(_) => StateType::Data,
        }
    }

    #[inline]
    pub fn is_declarative(&self) -> bool {
        match self {
            AssignmentVec::Declarative(_) => true,
            _ => false,
        }
    }

    #[inline]
    pub fn has_value(&self) -> bool {
        match self {
            AssignmentVec::DiscreteFiniteField(_) => true,
            _ => false,
        }
    }

    #[inline]
    pub fn has_data(&self) -> bool {
        match self {
            AssignmentVec::CustomData(_) => true,
            _ => false,
        }
    }

    #[inline]
    pub fn declarative_assignment_vec_mut(
        &mut self,
    ) -> Option<&mut Vec<Assignment<DeclarativeStrategy>>> {
        match self {
            AssignmentVec::Declarative(set) => Some(set),
            _ => None,
        }
    }

    #[inline]
    pub fn value_assignment_vec_mut(
        &mut self,
    ) -> Option<&mut Vec<Assignment<PedersenStrategy>>> {
        match self {
            AssignmentVec::DiscreteFiniteField(set) => Some(set),
            _ => None,
        }
    }

    #[inline]
    pub fn data_assignment_vec_mut(
        &mut self,
    ) -> Option<&mut Vec<Assignment<HashStrategy>>> {
        match self {
            AssignmentVec::CustomData(set) => Some(set),
            _ => None,
        }
    }

    #[inline]
    pub fn to_declarative_assignment_vec(
        &self,
    ) -> Vec<Assignment<DeclarativeStrategy>> {
        match self {
            AssignmentVec::Declarative(set) => set.clone(),
            _ => Default::default(),
        }
    }

    #[inline]
    pub fn to_value_assignment_vec(&self) -> Vec<Assignment<PedersenStrategy>> {
        match self {
            AssignmentVec::DiscreteFiniteField(set) => set.clone(),
            _ => Default::default(),
        }
    }

    #[inline]
    pub fn to_data_assignment_vec(&self) -> Vec<Assignment<HashStrategy>> {
        match self {
            AssignmentVec::CustomData(set) => set.clone(),
            _ => Default::default(),
        }
    }

    #[inline]
    pub fn into_declarative_assignment_vec(
        self,
    ) -> Vec<Assignment<DeclarativeStrategy>> {
        match self {
            AssignmentVec::Declarative(set) => set,
            _ => Default::default(),
        }
    }

    #[inline]
    pub fn into_value_assignment_vec(
        self,
    ) -> Vec<Assignment<PedersenStrategy>> {
        match self {
            AssignmentVec::DiscreteFiniteField(set) => set,
            _ => Default::default(),
        }
    }

    #[inline]
    pub fn into_data_assignment_vec(self) -> Vec<Assignment<HashStrategy>> {
        match self {
            AssignmentVec::CustomData(set) => set,
            _ => Default::default(),
        }
    }

    /// If seal definition does not exist, returns [`NoDataError`]. If the
    /// seal is confidential, returns `Ok(None)`; otherwise returns revealed
    /// seal data packed as `Ok(Some(`[`seal::Revealed`]`))`
    pub fn revealed_seal_at(
        &self,
        index: u16,
    ) -> Result<Option<seal::Revealed>, NoDataError> {
        Ok(match self {
            AssignmentVec::Declarative(vec) => {
                vec.get(index as usize).ok_or(NoDataError)?.revealed_seal()
            }
            AssignmentVec::DiscreteFiniteField(vec) => {
                vec.get(index as usize).ok_or(NoDataError)?.revealed_seal()
            }
            AssignmentVec::CustomData(vec) => {
                vec.get(index as usize).ok_or(NoDataError)?.revealed_seal()
            }
        })
    }

    pub fn revealed_seals(
        &self,
    ) -> Result<Vec<seal::Revealed>, ConfidentialDataError> {
        let list: Vec<_> = match self {
            AssignmentVec::Declarative(s) => {
                s.into_iter().map(Assignment::<_>::revealed_seal).collect()
            }
            AssignmentVec::DiscreteFiniteField(s) => {
                s.into_iter().map(Assignment::<_>::revealed_seal).collect()
            }
            AssignmentVec::CustomData(s) => {
                s.into_iter().map(Assignment::<_>::revealed_seal).collect()
            }
        };
        let len = list.len();
        let filtered: Vec<seal::Revealed> =
            list.into_iter().filter_map(|v| v).collect();
        if len != filtered.len() {
            return Err(ConfidentialDataError);
        }
        return Ok(filtered);
    }

    pub fn filter_revealed_seals(&self) -> Vec<seal::Revealed> {
        match self {
            AssignmentVec::Declarative(s) => s
                .into_iter()
                .filter_map(Assignment::<_>::revealed_seal)
                .collect(),
            AssignmentVec::DiscreteFiniteField(s) => s
                .into_iter()
                .filter_map(Assignment::<_>::revealed_seal)
                .collect(),
            AssignmentVec::CustomData(s) => s
                .into_iter()
                .filter_map(Assignment::<_>::revealed_seal)
                .collect(),
        }
    }

    pub fn to_confidential_seals(&self) -> Vec<seal::Confidential> {
        match self {
            AssignmentVec::Declarative(s) => s
                .into_iter()
                .map(Assignment::<_>::to_confidential_seal)
                .collect(),
            AssignmentVec::DiscreteFiniteField(s) => s
                .into_iter()
                .map(Assignment::<_>::to_confidential_seal)
                .collect(),
            AssignmentVec::CustomData(s) => s
                .into_iter()
                .map(Assignment::<_>::to_confidential_seal)
                .collect(),
        }
    }

    pub fn as_revealed_state_values(
        &self,
    ) -> Result<Vec<&value::Revealed>, StateRetrievalError> {
        let list = match self {
            AssignmentVec::DiscreteFiniteField(s) => {
                s.into_iter().map(Assignment::<_>::as_revealed_state)
            }
            _ => return Err(StateRetrievalError::StateTypeMismatch),
        };
        let len = list.len();
        let filtered: Vec<&value::Revealed> = list.filter_map(|v| v).collect();
        if len != filtered.len() {
            return Err(StateRetrievalError::ConfidentialData);
        }
        return Ok(filtered);
    }

    pub fn as_revealed_state_data(
        &self,
    ) -> Result<Vec<&data::Revealed>, StateRetrievalError> {
        let list = match self {
            AssignmentVec::CustomData(s) => {
                s.into_iter().map(Assignment::<_>::as_revealed_state)
            }
            _ => return Err(StateRetrievalError::StateTypeMismatch),
        };
        let len = list.len();
        let filtered: Vec<&data::Revealed> = list.filter_map(|v| v).collect();
        if len != filtered.len() {
            return Err(StateRetrievalError::ConfidentialData);
        }
        return Ok(filtered);
    }

    pub fn filter_revealed_state_values(&self) -> Vec<&value::Revealed> {
        match self {
            AssignmentVec::Declarative(_) => vec![],
            AssignmentVec::DiscreteFiniteField(s) => s
                .into_iter()
                .filter_map(Assignment::<_>::as_revealed_state)
                .collect(),
            AssignmentVec::CustomData(_) => vec![],
        }
    }

    pub fn filter_revealed_state_data(&self) -> Vec<&data::Revealed> {
        match self {
            AssignmentVec::Declarative(_) => vec![],
            AssignmentVec::DiscreteFiniteField(_) => vec![],
            AssignmentVec::CustomData(s) => s
                .into_iter()
                .filter_map(Assignment::<_>::as_revealed_state)
                .collect(),
        }
    }

    pub fn to_confidential_state_pedersen(&self) -> Vec<value::Confidential> {
        match self {
            AssignmentVec::Declarative(_) => vec![],
            AssignmentVec::DiscreteFiniteField(s) => s
                .into_iter()
                .map(Assignment::<_>::to_confidential_state)
                .collect(),
            AssignmentVec::CustomData(_) => vec![],
        }
    }

    pub fn to_confidential_state_hashed(&self) -> Vec<data::Confidential> {
        match self {
            AssignmentVec::Declarative(_) => vec![],
            AssignmentVec::DiscreteFiniteField(_) => vec![],
            AssignmentVec::CustomData(s) => s
                .into_iter()
                .map(Assignment::<_>::to_confidential_state)
                .collect(),
        }
    }

    #[inline]
    pub fn as_revealed_owned_value(
        &self,
    ) -> Result<Vec<(seal::Revealed, &value::Revealed)>, StateRetrievalError>
    {
        match self {
            AssignmentVec::DiscreteFiniteField(vec) => {
                let unfiltered: Vec<_> = vec
                    .into_iter()
                    .filter_map(|assignment| {
                        assignment.revealed_seal().and_then(|seal| {
                            assignment
                                .as_revealed_state()
                                .map(|state| (seal, state))
                        })
                    })
                    .collect();
                if unfiltered.len() != vec.len() {
                    Err(StateRetrievalError::ConfidentialData)
                } else {
                    Ok(unfiltered)
                }
            }
            _ => Err(StateRetrievalError::StateTypeMismatch),
        }
    }

    #[inline]
    pub fn as_revealed_owned_data(
        &self,
    ) -> Result<Vec<(seal::Revealed, &data::Revealed)>, StateRetrievalError>
    {
        match self {
            AssignmentVec::CustomData(vec) => {
                let unfiltered: Vec<_> = vec
                    .into_iter()
                    .filter_map(|assignment| {
                        assignment.revealed_seal().and_then(|seal| {
                            assignment
                                .as_revealed_state()
                                .map(|state| (seal, state))
                        })
                    })
                    .collect();
                if unfiltered.len() != vec.len() {
                    Err(StateRetrievalError::ConfidentialData)
                } else {
                    Ok(unfiltered)
                }
            }
            _ => Err(StateRetrievalError::StateTypeMismatch),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            AssignmentVec::Declarative(set) => set.len(),
            AssignmentVec::DiscreteFiniteField(set) => set.len(),
            AssignmentVec::CustomData(set) => set.len(),
        }
    }

    /// Reveals previously known seal information (replacing blind UTXOs with
    /// explicit ones). Function is used when a peer receives consignment
    /// containing concealed seals for the outputs owned by the peer
    pub fn reveal_seals<'a>(
        &mut self,
        known_seals: impl Iterator<Item = &'a seal::Revealed> + Clone,
    ) -> usize {
        let mut counter = 0;
        match self {
            AssignmentVec::Declarative(_) => {}
            AssignmentVec::DiscreteFiniteField(set) => {
                *self = AssignmentVec::DiscreteFiniteField(
                    set.iter()
                        .map(|assignment| {
                            let mut assignment = assignment.clone();
                            counter +=
                                assignment.reveal_seals(known_seals.clone());
                            assignment
                        })
                        .collect(),
                );
            }
            AssignmentVec::CustomData(set) => {
                *self = AssignmentVec::CustomData(
                    set.iter()
                        .map(|assignment| {
                            let mut assignment = assignment.clone();
                            counter +=
                                assignment.reveal_seals(known_seals.clone());
                            assignment
                        })
                        .collect(),
                );
            }
        }
        counter
    }

    pub fn consensus_commitments(&self) -> Vec<MerkleNode> {
        match self {
            AssignmentVec::Declarative(vec) => vec
                .iter()
                .map(Assignment::<DeclarativeStrategy>::consensus_commit)
                .collect(),
            AssignmentVec::DiscreteFiniteField(vec) => vec
                .iter()
                .map(Assignment::<PedersenStrategy>::consensus_commit)
                .collect(),
            AssignmentVec::CustomData(vec) => vec
                .iter()
                .map(Assignment::<HashStrategy>::consensus_commit)
                .collect(),
        }
    }
}

impl ConcealSeals for AssignmentVec {
    fn conceal_seals(&mut self, seals: &Vec<seal::Confidential>) -> usize {
        match self {
            AssignmentVec::Declarative(data) => data as &mut dyn ConcealSeals,
            AssignmentVec::DiscreteFiniteField(data) => {
                data as &mut dyn ConcealSeals
            }
            AssignmentVec::CustomData(data) => data as &mut dyn ConcealSeals,
        }
        .conceal_seals(seals)
    }
}

impl ConcealState for AssignmentVec {
    fn conceal_state_except(
        &mut self,
        seals: &Vec<seal::Confidential>,
    ) -> usize {
        match self {
            AssignmentVec::Declarative(data) => data as &mut dyn ConcealState,
            AssignmentVec::DiscreteFiniteField(data) => {
                data as &mut dyn ConcealState
            }
            AssignmentVec::CustomData(data) => data as &mut dyn ConcealState,
        }
        .conceal_state_except(seals)
    }
}

pub trait ConfidentialState:
    StrictEncode + StrictDecode + Debug + Clone + AsAny
{
}

pub trait RevealedState:
    StrictEncode + StrictDecode + Debug + CommitConceal + Clone + AsAny
{
}

impl AssignmentVec {
    pub fn u8(&self) -> Vec<u8> {
        self.filter_revealed_state_data()
            .into_iter()
            .filter_map(data::Revealed::u8)
            .collect()
    }
    pub fn u16(&self) -> Vec<u16> {
        self.filter_revealed_state_data()
            .into_iter()
            .filter_map(data::Revealed::u16)
            .collect()
    }
    pub fn u32(&self) -> Vec<u32> {
        self.filter_revealed_state_data()
            .into_iter()
            .filter_map(data::Revealed::u32)
            .collect()
    }
    pub fn u64(&self) -> Vec<u64> {
        self.filter_revealed_state_data()
            .into_iter()
            .filter_map(data::Revealed::u64)
            .collect()
    }
    pub fn i8(&self) -> Vec<i8> {
        self.filter_revealed_state_data()
            .into_iter()
            .filter_map(data::Revealed::i8)
            .collect()
    }
    pub fn i16(&self) -> Vec<i16> {
        self.filter_revealed_state_data()
            .into_iter()
            .filter_map(data::Revealed::i16)
            .collect()
    }
    pub fn i32(&self) -> Vec<i32> {
        self.filter_revealed_state_data()
            .into_iter()
            .filter_map(data::Revealed::i32)
            .collect()
    }
    pub fn i64(&self) -> Vec<i64> {
        self.filter_revealed_state_data()
            .into_iter()
            .filter_map(data::Revealed::i64)
            .collect()
    }
    pub fn f32(&self) -> Vec<f32> {
        self.filter_revealed_state_data()
            .into_iter()
            .filter_map(data::Revealed::f32)
            .collect()
    }
    pub fn f64(&self) -> Vec<f64> {
        self.filter_revealed_state_data()
            .into_iter()
            .filter_map(data::Revealed::f64)
            .collect()
    }
    pub fn bytes(&self) -> Vec<Vec<u8>> {
        self.filter_revealed_state_data()
            .into_iter()
            .filter_map(data::Revealed::bytes)
            .collect()
    }
    pub fn string(&self) -> Vec<String> {
        self.filter_revealed_state_data()
            .into_iter()
            .filter_map(data::Revealed::string)
            .collect()
    }
}

pub trait State: Debug {
    type Confidential: ConfidentialState;
    type Revealed: RevealedState;
}

#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq)]
pub struct DeclarativeStrategy;
impl State for DeclarativeStrategy {
    type Confidential = data::Void;
    type Revealed = data::Void;
}

#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq)]
pub struct PedersenStrategy;
impl State for PedersenStrategy {
    type Confidential = value::Confidential;
    type Revealed = value::Revealed;
}

#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq)]
pub struct HashStrategy;
impl State for HashStrategy {
    type Confidential = data::Confidential;
    type Revealed = data::Revealed;
}

/// State data are assigned to a seal definition, which means that they are
/// owned by a person controlling spending of the seal UTXO, unless the seal
/// is closed, indicating that a transfer of ownership had taken place
#[derive(Clone, Debug, Display)]
#[display(Debug)]
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
    StateType::Confidential:
        From<<StateType::Revealed as CommitConceal>::ConcealedCommitment>,
{
    Confidential {
        seal_definition: seal::Confidential,
        assigned_state: StateType::Confidential,
    },
    Revealed {
        seal_definition: seal::Revealed,
        assigned_state: StateType::Revealed,
    },
    ConfidentialSeal {
        seal_definition: seal::Confidential,
        assigned_state: StateType::Revealed,
    },
    ConfidentialAmount {
        seal_definition: seal::Revealed,
        assigned_state: StateType::Confidential,
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
    StateType::Confidential:
        From<<StateType::Revealed as CommitConceal>::ConcealedCommitment>,
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
    StateType::Confidential:
        From<<StateType::Revealed as CommitConceal>::ConcealedCommitment>,
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
    StateType::Confidential:
        From<<StateType::Revealed as CommitConceal>::ConcealedCommitment>,
{
    fn eq(&self, other: &Self) -> bool {
        self.to_confidential_seal() == other.to_confidential_seal()
            && self.to_confidential_state() == other.to_confidential_state()
    }
}

impl<StateType> Eq for Assignment<StateType>
where
    StateType: State,
    StateType::Confidential: PartialEq + Eq,
    StateType::Confidential:
        From<<StateType::Revealed as CommitConceal>::ConcealedCommitment>,
{
}

impl<StateType> Assignment<StateType>
where
    StateType: State,
    StateType::Confidential: PartialEq + Eq,
    StateType::Confidential:
        From<<StateType::Revealed as CommitConceal>::ConcealedCommitment>,
{
    pub fn to_confidential_seal(&self) -> seal::Confidential {
        match self {
            Assignment::Revealed {
                seal_definition, ..
            }
            | Assignment::ConfidentialAmount {
                seal_definition, ..
            } => seal_definition.commit_conceal(),
            Assignment::Confidential {
                seal_definition, ..
            }
            | Assignment::ConfidentialSeal {
                seal_definition, ..
            } => *seal_definition,
        }
    }

    pub fn revealed_seal(&self) -> Option<seal::Revealed> {
        match self {
            Assignment::Revealed {
                seal_definition, ..
            }
            | Assignment::ConfidentialAmount {
                seal_definition, ..
            } => Some(*seal_definition),
            Assignment::Confidential { .. }
            | Assignment::ConfidentialSeal { .. } => None,
        }
    }

    pub fn to_confidential_state(&self) -> StateType::Confidential {
        match self {
            Assignment::Revealed { assigned_state, .. }
            | Assignment::ConfidentialSeal { assigned_state, .. } => {
                assigned_state.commit_conceal().into()
            }
            Assignment::Confidential { assigned_state, .. }
            | Assignment::ConfidentialAmount { assigned_state, .. } => {
                assigned_state.clone()
            }
        }
    }

    pub fn as_revealed_state(&self) -> Option<&StateType::Revealed> {
        match self {
            Assignment::Revealed { assigned_state, .. }
            | Assignment::ConfidentialSeal { assigned_state, .. } => {
                Some(assigned_state)
            }
            Assignment::Confidential { .. }
            | Assignment::ConfidentialAmount { .. } => None,
        }
    }

    pub fn into_revealed(
        self,
    ) -> Option<(seal::Revealed, StateType::Revealed)> {
        match self {
            Assignment::Revealed {
                seal_definition,
                assigned_state,
            } => Some((seal_definition, assigned_state)),
            _ => None,
        }
    }

    /// Reveals previously known seal information (replacing blind UTXOs with
    /// unblind ones). Function is used when a peer receives consignment
    /// containing concealed seals for the outputs owned by the peer
    pub fn reveal_seals<'a>(
        &mut self,
        known_seals: impl Iterator<Item = &'a seal::Revealed>,
    ) -> usize {
        let known_seals: HashMap<seal::Confidential, seal::Revealed> =
            known_seals
                .map(|rev| (rev.commit_conceal(), rev.clone()))
                .collect();

        let mut counter = 0;
        match self {
            Assignment::Confidential {
                seal_definition,
                assigned_state,
            } => {
                if let Some(reveal) = known_seals.get(seal_definition) {
                    *self = Assignment::ConfidentialAmount {
                        seal_definition: reveal.clone(),
                        assigned_state: assigned_state.clone(),
                    };
                    counter += 1;
                };
            }
            Assignment::ConfidentialSeal {
                seal_definition,
                assigned_state,
            } => {
                if let Some(reveal) = known_seals.get(seal_definition) {
                    *self = Assignment::Revealed {
                        seal_definition: reveal.clone(),
                        assigned_state: assigned_state.clone(),
                    };
                    counter += 1;
                };
            }
            _ => {}
        }
        counter
    }
}

impl<StateType> CommitConceal for Assignment<StateType>
where
    Self: Clone,
    StateType: State,
    StateType::Confidential: PartialEq + Eq,
    StateType::Confidential:
        From<<StateType::Revealed as CommitConceal>::ConcealedCommitment>,
{
    type ConcealedCommitment = Self;

    fn commit_conceal(&self) -> Self::ConcealedCommitment {
        match self {
            Assignment::Confidential { .. } => self.clone(),
            Assignment::ConfidentialAmount {
                seal_definition,
                assigned_state,
            } => Self::Confidential {
                seal_definition: seal_definition.commit_conceal(),
                assigned_state: assigned_state.clone(),
            },
            Assignment::Revealed {
                seal_definition,
                assigned_state,
            } => Self::Confidential {
                seal_definition: seal_definition.commit_conceal(),
                assigned_state: assigned_state.commit_conceal().into(),
            },
            Assignment::ConfidentialSeal {
                seal_definition,
                assigned_state,
            } => Self::Confidential {
                seal_definition: seal_definition.clone(),
                assigned_state: assigned_state.commit_conceal().into(),
            },
        }
    }
}

impl<StateType> ConcealSeals for Assignment<StateType>
where
    StateType: State,
    StateType::Revealed: CommitConceal,
    StateType::Confidential: PartialEq + Eq,
    <StateType as State>::Confidential:
        From<<StateType::Revealed as CommitConceal>::ConcealedCommitment>,
{
    fn conceal_seals(&mut self, seals: &Vec<seal::Confidential>) -> usize {
        match self {
            Assignment::Confidential { .. }
            | Assignment::ConfidentialSeal { .. } => 0,
            Assignment::ConfidentialAmount {
                seal_definition,
                assigned_state,
            } => {
                if seals.contains(&seal_definition.commit_conceal()) {
                    *self = Assignment::<StateType>::Confidential {
                        assigned_state: assigned_state.clone(),
                        seal_definition: seal_definition.commit_conceal(),
                    };
                    1
                } else {
                    0
                }
            }
            Assignment::Revealed {
                seal_definition,
                assigned_state,
            } => {
                if seals.contains(&seal_definition.commit_conceal()) {
                    *self = Assignment::<StateType>::ConfidentialSeal {
                        assigned_state: assigned_state.clone(),
                        seal_definition: seal_definition.commit_conceal(),
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
    StateType::Revealed: CommitConceal,
    StateType::Confidential: PartialEq + Eq,
    <StateType as State>::Confidential:
        From<<StateType::Revealed as CommitConceal>::ConcealedCommitment>,
{
    fn conceal_state_except(
        &mut self,
        seals: &Vec<seal::Confidential>,
    ) -> usize {
        match self {
            Assignment::Confidential { .. }
            | Assignment::ConfidentialAmount { .. } => 0,
            Assignment::ConfidentialSeal {
                seal_definition,
                assigned_state,
            } => {
                if seals.contains(&seal_definition) {
                    0
                } else {
                    *self = Assignment::<StateType>::Confidential {
                        assigned_state: assigned_state.commit_conceal().into(),
                        seal_definition: seal_definition.clone(),
                    };
                    1
                }
            }
            Assignment::Revealed {
                seal_definition,
                assigned_state,
            } => {
                if seals.contains(&seal_definition.commit_conceal()) {
                    0
                } else {
                    *self = Assignment::<StateType>::ConfidentialAmount {
                        assigned_state: assigned_state.commit_conceal().into(),
                        seal_definition: seal_definition.clone(),
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
    StateType::Confidential:
        From<<StateType::Revealed as CommitConceal>::ConcealedCommitment>,
{
    fn commit_encode<E: io::Write>(&self, e: E) -> usize {
        self.commit_conceal().strict_encode(e).expect(
            "Strict encoding must not fail for types implementing \
             ConsensusCommit via marker trait ConsensusCommitFromStrictEncoding"
        )
    }
}

impl<StateType> ConsensusCommit for Assignment<StateType>
where
    Self: Clone,
    StateType: State,
    StateType::Confidential: PartialEq + Eq,
    StateType::Confidential:
        From<<StateType::Revealed as CommitConceal>::ConcealedCommitment>,
{
    type Commitment = MerkleNode;
}

mod _strict_encoding {
    use super::*;
    use data::_strict_encoding::EncodingTag;
    use std::io;
    use strict_encoding::Error;

    impl StrictEncode for AssignmentVec {
        fn strict_encode<E: io::Write>(
            &self,
            mut e: E,
        ) -> Result<usize, Error> {
            Ok(match self {
                AssignmentVec::Declarative(tree) => {
                    strict_encode_list!(e; schema::StateType::Declarative, tree)
                }
                AssignmentVec::DiscreteFiniteField(tree) => {
                    strict_encode_list!(e; schema::StateType::DiscreteFiniteField, EncodingTag::U64, tree)
                }
                AssignmentVec::CustomData(tree) => {
                    strict_encode_list!(e; schema::StateType::CustomData, tree)
                }
            })
        }
    }

    impl StrictDecode for AssignmentVec {
        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
            let format = schema::StateType::strict_decode(&mut d)?;
            Ok(match format {
                schema::StateType::Declarative => {
                    AssignmentVec::Declarative(StrictDecode::strict_decode(d)?)
                }
                schema::StateType::DiscreteFiniteField => match EncodingTag::strict_decode(&mut d)?
                {
                    EncodingTag::U64 => {
                        AssignmentVec::DiscreteFiniteField(StrictDecode::strict_decode(&mut d)?)
                    }
                    _ => Err(Error::UnsupportedDataStructure(
                        "We support only homomorphic commitments to U64 data",
                    ))?,
                },
                schema::StateType::CustomData => {
                    AssignmentVec::CustomData(StrictDecode::strict_decode(d)?)
                }
            })
        }
    }

    impl<StateType> StrictEncode for Assignment<StateType>
    where
        StateType: State,
        StateType::Confidential: PartialEq + Eq,
        StateType::Confidential:
            From<<StateType::Revealed as CommitConceal>::ConcealedCommitment>,
    {
        fn strict_encode<E: io::Write>(
            &self,
            mut e: E,
        ) -> Result<usize, Error> {
            Ok(match self {
                Assignment::Confidential {
                    seal_definition,
                    assigned_state,
                } => {
                    strict_encode_list!(e; 0u8, seal_definition, assigned_state)
                }
                Assignment::Revealed {
                    seal_definition,
                    assigned_state,
                } => {
                    strict_encode_list!(e; 1u8, seal_definition, assigned_state)
                }
                Assignment::ConfidentialSeal {
                    seal_definition,
                    assigned_state,
                } => {
                    strict_encode_list!(e; 2u8, seal_definition, assigned_state)
                }
                Assignment::ConfidentialAmount {
                    seal_definition,
                    assigned_state,
                } => {
                    strict_encode_list!(e; 3u8, seal_definition, assigned_state)
                }
            })
        }
    }

    impl<StateType> StrictDecode for Assignment<StateType>
    where
        StateType: State,
        StateType::Confidential: PartialEq + Eq,
        StateType::Confidential:
            From<<StateType::Revealed as CommitConceal>::ConcealedCommitment>,
    {
        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
            let format = u8::strict_decode(&mut d)?;
            Ok(match format {
                0u8 => Assignment::Confidential {
                    seal_definition: seal::Confidential::strict_decode(&mut d)?,
                    assigned_state: StateType::Confidential::strict_decode(
                        &mut d,
                    )?,
                },
                1u8 => Assignment::Revealed {
                    seal_definition: seal::Revealed::strict_decode(&mut d)?,
                    assigned_state: StateType::Revealed::strict_decode(&mut d)?,
                },
                2u8 => Assignment::ConfidentialSeal {
                    seal_definition: seal::Confidential::strict_decode(&mut d)?,
                    assigned_state: StateType::Revealed::strict_decode(&mut d)?,
                },
                3u8 => Assignment::ConfidentialAmount {
                    seal_definition: seal::Revealed::strict_decode(&mut d)?,
                    assigned_state: StateType::Confidential::strict_decode(
                        &mut d,
                    )?,
                },
                invalid => Err(Error::EnumValueNotKnown(
                    "Assignment",
                    invalid as usize,
                ))?,
            })
        }
    }
}

#[cfg(test)]
mod test {
    use super::super::{NodeId, OwnedRights, ParentOwnedRights};
    use super::*;
    use crate::contract::seal::Revealed;
    use bitcoin::blockdata::transaction::OutPoint;
    use bitcoin::hashes::{
        hex::{FromHex, ToHex},
        sha256, Hash,
    };
    use bp::seals::txout::TxoSeal;
    use commit_verify::{
        merkle::MerkleNode, merklize, CommitConceal, CommitEncode,
        ToMerkleSource,
    };
    use secp256k1zkp::rand::{thread_rng, Rng, RngCore};
    use secp256k1zkp::{pedersen::Commitment, Secp256k1, SecretKey};
    use std::collections::BTreeMap;

    // Hard coded test vectors of Assignment Variants
    // Each Variant contains 4 types of Assignments
    // [Revealed, Confidential, ConfidentialSeal, ConfidentialState]
    static HASH_VARIANT: [u8; 267] = include!("../../test/hash_state.in");

    static PEDERSAN_VARIANT: [u8; 1664] =
        include!("../../test/pedersan_state.in");

    static DECLARATIVE_VARIANT: [u8; 161] =
        include!("../../test/declarative_state.in");

    static PARENT_RIGHTS: [u8; 78] = include!("../../test/parent_rights.in");

    // Real data used for creation of above variants
    // Used in tests to ensure operations of AssignmentVariants gives
    // deterministic results

    // Txids to generate seals
    static TXID_VEC: [&str; 4] = [
        "201fdd1e2b62d7b6938271295118ee181f1bac5e57d9f4528925650d36d3af8e",
        "f57ed27ee4199072c5ff3b774febc94d26d3e4a5559d133de4750a948df50e06",
        "12072893d951c633dcafb4d3074d1fc41c5e6e64b8d53e3b0705c41bc6679d54",
        "8f75db9f89c7c75f0a54322f18cd4d557ae75c24a8e5a95eae13fe26edc2d789",
    ];

    // State data used in CustomData type Assignments
    static STATE_DATA: [&str; 4] = [
        "e70a36e2ce51d31d4cf5d6731fa63738648127db833715d39652d86d927d4888",
        "408e331ebce96ca98cfb7b8a6286a79300379eed6395636e6d103017d474039f",
        "c6411aea082e2c5d74347368677db69545126237d5ed78faa0846352f5383f95",
        "277fb00655e2523424677686c24d90fba6b70869050ae204782e8ef0ab8049c6",
    ];

    // Confidential seals for Declarative Assignments
    static DECLARATIVE_OUTPOINT_HASH: [&str; 4] = [
        "58f3ea4817a12aa6f1007d5b3d24dd2940ce40f8498029e05f1dc6465b3d65b4",
        "6b3c1bee0bd431f53e6c099890fdaf51b8556a6dcd61c6150ca055d0e1d4a524",
        "9a17566abc006cf335fd96d8f8a4136526d85493a85ebe875abbbee19795c496",
        "c843ac6b197ae371191264cc0e4ed18a910b5522a0bad72a24f2080c170e2053",
    ];

    // Confidential seals for Pedersan type Assignments
    static PEDERSAN_OUTPOINT_HASH: [&str; 4] = [
        "281543d7f791d4b4f8ef1196e436bc3286a5505f7bafd978d4af9be6f112e1b4",
        "32d71a47d8ff6015fc58525985af7346e0802c7ad065ad79335602c7a6562ab3",
        "68955a27e1ffde810fcfdd18697eb59aa4f7b0afde2a8193cd28184b729b5195",
        "698c43d973bec68540e6df67137785e40be6d29def4888ada3cd7b7884b37f62",
    ];

    // Confidential seals for CustomData type Assignments
    static HASH_OUTPOINT_HASH: [&str; 4] = [
        "7efe71b7a37a39da798774ca6b09def9724d81303892d55cac3edb0dc8340a3a",
        "9565d29461c863e013c26d176a9929307286963322849a1dc6c978e5c70c8d52",
        "9b64a3024632f0517d8a608cb29902f7083eab0ac25d2827a5ef27e9a68b18f9",
        "dc0d0d7139a3ad6010a210e5900201979a1a09047b10a877688ee5a740ae215a",
    ];

    // Generic encode-decode testing
    #[test]
    fn test_encoded_data() {
        test_encode!((HASH_VARIANT, AssignmentVec));
        test_encode!((PEDERSAN_VARIANT, AssignmentVec));
        test_encode!((DECLARATIVE_VARIANT, AssignmentVec));
    }

    // Generic garbage value testing
    #[test]
    fn test_garbage_dec() {
        let err = "StateType";
        test_garbage_exhaustive!(4..255; (DECLARATIVE_VARIANT, AssignmentVec, err),
            (HASH_VARIANT, AssignmentVec, err),
            (DECLARATIVE_VARIANT, AssignmentVec, err));
    }

    #[test]
    #[should_panic(expected = "UnsupportedDataStructure")]
    fn test_garbage_ped_2() {
        let mut bytes = PEDERSAN_VARIANT.clone();
        bytes[1] = 0x02;

        AssignmentVec::strict_decode(&bytes[..]).unwrap();
    }

    fn zero_balance(
        input_amounts: &[u64],
        output_amounts: &[u64],
        partition: usize,
    ) -> (Vec<Commitment>, Vec<Commitment>) {
        let mut rng = thread_rng();

        // Create revealed amount from input amounts
        let input_revealed: Vec<value::Revealed> = input_amounts[..]
            .into_iter()
            .map(|amount| value::Revealed::with_amount(*amount, &mut rng))
            .collect();

        // Allocate Txid vector of size of the output vector
        let mut txid_vec: Vec<bitcoin::Txid> =
            Vec::with_capacity(output_amounts.len());

        // Fill the txid vector with random txids.
        for _ in 0..output_amounts.len() {
            let mut bytes: [u8; 32] = [0; 32];
            rng.fill(&mut bytes[..]);
            let txid =
                bitcoin::Txid::from_hex(&bytes.to_vec().to_hex()[..]).unwrap();
            txid_vec.push(txid);
        }

        // Take first two amounts to create our allocations
        let zip_data = txid_vec[..partition]
            .iter()
            .zip(output_amounts[..partition].iter());

        // Create our allocations
        let ours: SealValueMap = zip_data
            .map(|(txid, amount)| {
                (
                    Revealed::from(OutPoint::new(*txid, rng.gen_range(0, 10))),
                    amount.clone(),
                )
            })
            .collect();

        // Take next two amounts for their allocations
        let zip_data2 = txid_vec[partition..]
            .iter()
            .zip(output_amounts[partition..].iter());

        // Create their allocations
        let theirs: EndpointValueMap = zip_data2
            .map(|(txid, amount)| {
                (
                    SealEndpoint::ConcealedUtxo(
                        Revealed::from(OutPoint::new(
                            *txid,
                            rng.gen_range(0, 10),
                        ))
                        .commit_conceal(),
                    ),
                    amount.clone(),
                )
            })
            .collect();

        // Balance both the allocations against input amounts
        let balanced =
            AssignmentVec::zero_balanced(input_revealed.clone(), ours, theirs);

        // Extract balanced confidential output amounts
        let outputs: Vec<Commitment> = balanced
            .to_confidential_state_pedersen()
            .iter()
            .map(|confidential| confidential.commitment)
            .collect();

        // Create confidential input amounts
        let inputs: Vec<Commitment> = input_revealed
            .iter()
            .map(|revealed| revealed.commit_conceal().commitment)
            .collect();

        (inputs, outputs)
    }

    fn zero_balance_verify(
        input_amounts: &[u64],
        output_amounts: &[u64],
        partition: usize,
    ) -> bool {
        let (inputs, outputs) =
            zero_balance(input_amounts, output_amounts, partition);
        value::Confidential::verify_commit_sum(inputs, outputs)
    }

    #[test]
    fn test_zero_balance_nonoverflow() {
        assert!(zero_balance_verify(
            &[core::u64::MAX, 1],
            &[1, core::u64::MAX],
            1
        ));
        assert!(zero_balance_verify(
            &[core::u64::MAX, core::u64::MAX],
            &[core::u64::MAX, core::u64::MAX],
            1
        ));
        assert!(zero_balance_verify(
            &[core::u32::MAX as u64, core::u32::MAX as u64],
            &[core::u32::MAX as u64 + core::u32::MAX as u64],
            1
        ));
        assert!(zero_balance_verify(
            &[core::u32::MAX as u64, core::u32::MAX as u64, core::u64::MAX],
            &[core::u64::MAX, (core::u32::MAX as u64) * 2],
            1
        ));
    }

    #[test]
    fn test_zero_balance_single() {
        // test equal inputs and outputs
        let single_amounts = vec![
            [0u64],
            [1u64],
            [core::u16::MAX as u64],
            [core::u32::MAX as u64],
            [core::u64::MAX - 1u64],
            [core::u64::MAX],
        ];

        for vec in single_amounts.iter() {
            assert!(zero_balance_verify(vec, vec, 0));
            assert!(zero_balance_verify(vec, vec, 1));
            assert!(zero_balance_verify(vec, vec, vec.len() / 2));
            assert!(zero_balance_verify(vec, vec, vec.len() / 2 + 1));
        }
    }

    #[test]
    fn test_zero_balance_double() {
        let double_amounts = vec![
            [(core::u32::MAX - 1) as u64, (core::u32::MAX - 1) as u64],
            [core::u32::MAX as u64, core::u32::MAX as u64],
        ];

        for vec in double_amounts.iter() {
            assert!(zero_balance_verify(vec, vec, 0));
            assert!(zero_balance_verify(vec, vec, 1));
            assert!(zero_balance_verify(vec, vec, vec.len() / 2));
            assert!(zero_balance_verify(vec, vec, vec.len() / 2 + 1));
        }
    }

    #[test]
    fn test_zero_balance_multiple() {
        let multiple_amounts = vec![
            [0u64, 0u64, 0u64, 0u64],
            [0u64, 1u64, 0u64, 1u64],
            [1u64, 2u64, 3u64, core::u64::MAX],
            [10u64, 20u64, 30u64, 40u64],
            [0u64, 197642u64, core::u64::MAX, 476543u64],
            [
                core::u64::MAX,
                core::u64::MAX,
                core::u64::MAX,
                core::u64::MAX,
            ],
        ];

        for vec in multiple_amounts.iter() {
            assert!(zero_balance_verify(vec, vec, 0));
            assert!(zero_balance_verify(vec, vec, 1));
            assert!(zero_balance_verify(vec, vec, vec.len() / 2));
            assert!(zero_balance_verify(vec, vec, vec.len() / 2 + 1));
        }

        // Test when ours is empty
        assert!(zero_balance_verify(
            &multiple_amounts[2],
            &multiple_amounts[2],
            0
        ));

        // Test when theirs is empty
        assert!(zero_balance_verify(
            &multiple_amounts[4],
            &multiple_amounts[4],
            multiple_amounts[4].len()
        ));
    }

    #[test]
    fn test_zero_balance_negative() {
        // Test when input.sum() != output.sum()
        // When they only differ by 1
        // When they differ by core::u64::MAX
        assert!(!zero_balance_verify(
            &[0u64, 1u64, 0u64, 1u64],
            &[1u64, 2u64, 3u64, core::u64::MAX],
            2
        ));
        assert!(!zero_balance_verify(
            &[1u64, 2u64, 3u64, core::u64::MAX],
            &[10u64, 20u64, 30u64, 40u64],
            2
        ));
        assert!(!zero_balance_verify(
            &[10u64, 20u64, 30u64, 40u64],
            &[0u64, 197642u64, core::u64::MAX, 476543u64],
            2
        ));
        assert!(!zero_balance_verify(
            &[0u64, 197642u64, core::u64::MAX, 476543u64],
            &[
                core::u64::MAX,
                core::u64::MAX,
                core::u64::MAX,
                core::u64::MAX
            ],
            2
        ));
        assert!(!zero_balance_verify(&[1, 2, 3, 4], &[1, 2, 3, 5], 2));
        assert!(!zero_balance_verify(
            &[1, 2, 3, 0],
            &[1, 2, 3, core::u64::MAX],
            2
        ));
    }

    #[test]
    fn test_zero_balance_random() {
        let mut rng = thread_rng();

        // Test random inputs and outputs
        // Randomly distributed between ours and theirs allocation
        for _ in 0..5 {
            // Randomly generate number of amounts between 1 to 20
            let input_length = rng.gen_range(1, 20);

            // Randomly fill the amount vector
            let mut input_amounts = vec![0; input_length];
            for index in 0..input_length {
                // keep the amount value low for faster testing
                input_amounts[index] =
                    rng.gen_range::<u64>(100_000, 100_000_000_000);
            }
            let input_sum: u64 = input_amounts.iter().sum();

            // Create an output amount vector such that
            // input.sum() = output.sum(), but
            // input.count() != output.count()

            let mut output_amounts = vec![0u64; rng.gen_range(1, 20)];
            let output_length = output_amounts.len();

            // Add random values to output amounts until the last element
            for index in 0..output_length - 1 {
                output_amounts[index] =
                    rng.gen_range::<u64>(100_000, 100_000_000_000);
            }
            let output_sum: u64 = output_amounts.iter().sum();

            // Balance input and output amount vector based on their sums
            if input_sum == output_sum {
                continue;
            } else if output_sum > input_sum {
                input_amounts[input_length - 1] += output_sum - input_sum;
            } else {
                output_amounts[output_length - 1] += input_sum - output_sum;
            }

            let (inputs, outputs) = zero_balance(
                &input_amounts[..],
                &output_amounts[..],
                rng.gen_range(0, output_length),
            );
            // Check if test passes
            assert!(value::Confidential::verify_commit_sum(
                inputs.clone(),
                outputs.clone()
            ));

            // Check non-equivalent amounts do not verify
            if input_length > 1 {
                assert_eq!(
                    value::Confidential::verify_commit_sum(
                        inputs[..(input_length - 1)].to_vec(),
                        outputs
                    ),
                    false
                );
            } else if output_length > 1 {
                assert_eq!(
                    value::Confidential::verify_commit_sum(
                        inputs,
                        outputs[..(output_length - 1)].to_vec()
                    ),
                    false
                );
            }
        }
    }

    #[test]
    fn test_identification() {
        let declarative_type =
            AssignmentVec::strict_decode(&DECLARATIVE_VARIANT[..]).unwrap();
        let pedersan_type =
            AssignmentVec::strict_decode(&PEDERSAN_VARIANT[..]).unwrap();
        let hash_type =
            AssignmentVec::strict_decode(&HASH_VARIANT[..]).unwrap();

        // Check correct types are being identified
        // and wrong types return false
        assert!(declarative_type.is_declarative());
        assert!(pedersan_type.has_value());
        assert!(hash_type.has_data());
        assert!(!declarative_type.has_data());
        assert!(!declarative_type.has_value());
        assert!(!pedersan_type.is_declarative());
        assert!(!pedersan_type.has_data());
        assert!(!hash_type.is_declarative());
        assert!(!hash_type.has_value());
    }

    #[test]
    fn test_extraction() {
        let mut declarative_type =
            AssignmentVec::strict_decode(&DECLARATIVE_VARIANT[..]).unwrap();
        let mut pedersan_type =
            AssignmentVec::strict_decode(&PEDERSAN_VARIANT[..]).unwrap();
        let mut hash_type =
            AssignmentVec::strict_decode(&HASH_VARIANT[..]).unwrap();

        // Check Correct type extraction works
        assert!(!declarative_type.to_declarative_assignment_vec().is_empty());
        assert!(!pedersan_type.to_value_assignment_vec().is_empty());
        assert!(!hash_type.to_data_assignment_vec().is_empty());

        // Check wrong type extraction doesn't work
        assert!(declarative_type.to_value_assignment_vec().is_empty());
        assert!(declarative_type
            .clone()
            .into_data_assignment_vec()
            .is_empty());
        assert!(pedersan_type.to_declarative_assignment_vec().is_empty());
        assert!(pedersan_type.clone().into_data_assignment_vec().is_empty());
        assert!(hash_type.to_declarative_assignment_vec().is_empty());
        assert!(hash_type.clone().into_value_assignment_vec().is_empty());

        // Check correct mutable type extraction works
        assert!(declarative_type.declarative_assignment_vec_mut().is_some());
        assert!(pedersan_type.value_assignment_vec_mut().is_some());
        assert!(hash_type.data_assignment_vec_mut().is_some());

        // Check wrong mutable type extraction doesn't work
        assert!(declarative_type.value_assignment_vec_mut().is_none());
        assert!(declarative_type.data_assignment_vec_mut().is_none());
        assert!(pedersan_type.declarative_assignment_vec_mut().is_none());
        assert!(pedersan_type.data_assignment_vec_mut().is_none());
        assert!(hash_type.declarative_assignment_vec_mut().is_none());
        assert!(hash_type.value_assignment_vec_mut().is_none());
    }

    #[test]
    fn test_seal_extraction() {
        let declarative_type =
            AssignmentVec::strict_decode(&DECLARATIVE_VARIANT[..]).unwrap();
        let pedersan_type =
            AssignmentVec::strict_decode(&PEDERSAN_VARIANT[..]).unwrap();
        let hash_type =
            AssignmentVec::strict_decode(&HASH_VARIANT[..]).unwrap();

        // Extract a specific Txid from each variants
        let txid_1 = match declarative_type
            .revealed_seal_at(2)
            .unwrap()
            .unwrap()
            .outpoint()
        {
            Some(outpoint) => Some(outpoint.txid),
            _ => None,
        }
        .unwrap()
        .to_hex();

        let txid_2 = match pedersan_type
            .revealed_seal_at(0)
            .unwrap()
            .unwrap()
            .outpoint()
        {
            Some(outpoint) => Some(outpoint.txid),
            _ => None,
        }
        .unwrap()
        .to_hex();

        let txid_3 =
            match hash_type.revealed_seal_at(1).unwrap().unwrap().outpoint() {
                Some(outpoint) => Some(outpoint.txid),
                _ => None,
            }
            .unwrap()
            .to_hex();

        // Check extracted Txids matches with predetermined values
        assert_eq!(txid_1, TXID_VEC[1]);
        assert_eq!(txid_2, TXID_VEC[1]);
        assert_eq!(txid_3, TXID_VEC[1]);
    }

    #[test]
    fn test_known_seals() {
        let declarative_type =
            AssignmentVec::strict_decode(&DECLARATIVE_VARIANT[..]).unwrap();
        let pedersan_type =
            AssignmentVec::strict_decode(&PEDERSAN_VARIANT[..]).unwrap();
        let hash_type =
            AssignmentVec::strict_decode(&HASH_VARIANT[..]).unwrap();

        // Extract known Txids from each variants
        let mut dec_txids: Vec<String> = declarative_type
            .filter_revealed_seals()
            .iter()
            .map(|revealed| {
                match revealed.outpoint() {
                    Some(outpoint) => Some(outpoint.txid),
                    _ => None,
                }
                .unwrap()
                .to_hex()
            })
            .collect();

        let mut ped_txids: Vec<String> = pedersan_type
            .filter_revealed_seals()
            .iter()
            .map(|revealed| {
                match revealed.outpoint() {
                    Some(outpoint) => Some(outpoint.txid),
                    _ => None,
                }
                .unwrap()
                .to_hex()
            })
            .collect();

        let mut hash_txids: Vec<String> = hash_type
            .filter_revealed_seals()
            .iter()
            .map(|revealed| {
                match revealed.outpoint() {
                    Some(outpoint) => Some(outpoint.txid),
                    _ => None,
                }
                .unwrap()
                .to_hex()
            })
            .collect();

        // Sort the extracted Txids
        dec_txids.sort();
        ped_txids.sort();
        hash_txids.sort();

        // Predetermined values
        let mut sorted_txid = TXID_VEC[..2].to_vec().clone();
        sorted_txid.sort();

        // Check extracted values matches with predetermined values
        assert_eq!(dec_txids, sorted_txid);
        assert_eq!(ped_txids, sorted_txid);
        assert_eq!(hash_txids, sorted_txid);
    }

    #[test]
    fn test_all_seals() {
        let declarative_type =
            AssignmentVec::strict_decode(&DECLARATIVE_VARIANT[..]).unwrap();
        let pedersan_type =
            AssignmentVec::strict_decode(&PEDERSAN_VARIANT[..]).unwrap();
        let hash_type =
            AssignmentVec::strict_decode(&HASH_VARIANT[..]).unwrap();

        // Extract seals from all variants and conceal them
        let mut dec_hashes: Vec<String> = declarative_type
            .to_confidential_seals()
            .iter()
            .map(|hash| hash.to_hex())
            .collect();

        let mut ped_hashes: Vec<String> = pedersan_type
            .to_confidential_seals()
            .iter()
            .map(|hash| hash.to_hex())
            .collect();

        let mut hash_hashes: Vec<String> = hash_type
            .to_confidential_seals()
            .iter()
            .map(|hash| hash.to_hex())
            .collect();

        // Sort the concealed seals
        dec_hashes.sort();
        ped_hashes.sort();
        hash_hashes.sort();

        // Check extracted values matches with precomputed values
        assert_eq!(dec_hashes, DECLARATIVE_OUTPOINT_HASH);
        assert_eq!(ped_hashes, PEDERSAN_OUTPOINT_HASH);
        assert_eq!(hash_hashes, HASH_OUTPOINT_HASH);
    }

    #[test]
    fn test_known_state_homomorphic() {
        let declarative_type =
            AssignmentVec::strict_decode(&DECLARATIVE_VARIANT[..]).unwrap();
        let pedersan_type =
            AssignmentVec::strict_decode(&PEDERSAN_VARIANT[..]).unwrap();
        let hash_type =
            AssignmentVec::strict_decode(&HASH_VARIANT[..]).unwrap();

        // Extract known states from pedersan type variant
        let states = pedersan_type.filter_revealed_state_values();

        // Check the amounts matches with precomputed values
        assert_eq!(states[0].value, 10);
        assert_eq!(states[1].value, 30);

        // Precomputed blinding factors
        let blind_1: Vec<u8> = Vec::from_hex(
            "debbbefd1683e335296a0c86f1c882a2ea3759f114220b0b2cf869e37dec24c8",
        )
        .unwrap();
        let blind_2: Vec<u8> = Vec::from_hex(
            "5d3574c4d99c08ef950619be72bfa1d50ae3c153d1f30f64bc1ac08de99ea556",
        )
        .unwrap();

        // Check blinding factor matches with precomputed values
        assert_eq!(
            SecretKey::from(states[0].blinding),
            SecretKey::from_slice(&Secp256k1::new(), &blind_1[..]).unwrap()
        );
        assert_eq!(
            SecretKey::from(states[1].blinding),
            SecretKey::from_slice(&Secp256k1::new(), &blind_2[..]).unwrap()
        );

        // Check no values returned for declarative and custom data type
        // variants
        assert_eq!(declarative_type.filter_revealed_state_values().len(), 0);
        assert_eq!(hash_type.filter_revealed_state_values().len(), 0);
    }

    #[test]
    fn test_known_state_data() {
        let declarative_type =
            AssignmentVec::strict_decode(&DECLARATIVE_VARIANT[..]).unwrap();
        let pedersan_type =
            AssignmentVec::strict_decode(&PEDERSAN_VARIANT[..]).unwrap();
        let hash_type =
            AssignmentVec::strict_decode(&HASH_VARIANT[..]).unwrap();

        // Extract known states from custom data type variant
        let data_set = hash_type.filter_revealed_state_data();

        // Create state data from precomputed values
        let data_1 = data::Revealed::Sha256(
            sha256::Hash::from_hex(STATE_DATA[2]).unwrap(),
        );
        let data_2 = data::Revealed::Sha256(
            sha256::Hash::from_hex(STATE_DATA[0]).unwrap(),
        );

        // Check extracted data matches with precomputed values
        assert_eq!(data_set[0].to_owned(), data_1);
        assert_eq!(data_set[1].to_owned(), data_2);

        // Check no values returned for declarative and pedersan type variants
        assert_eq!(declarative_type.filter_revealed_state_data().len(), 0);
        assert_eq!(pedersan_type.filter_revealed_state_data().len(), 0);
    }

    #[test]
    fn test_all_state_pedersan() {
        let declarative_type =
            AssignmentVec::strict_decode(&DECLARATIVE_VARIANT[..]).unwrap();
        let pedersan_type =
            AssignmentVec::strict_decode(&PEDERSAN_VARIANT[..]).unwrap();
        let hash_type =
            AssignmentVec::strict_decode(&HASH_VARIANT[..]).unwrap();

        // Extract state data for pedersan type and conceal them
        let conf_amounts = pedersan_type.to_confidential_state_pedersen();

        // Check extracted values matches with precomputed values
        assert_eq!(
            conf_amounts[0].commitment,
            Commitment::from_vec(
                Vec::from_hex("08cc48fa5e5cb1d2d2465bd8c437c0e00514abd813f9a7dd506a778405a2c43bc0")
                    .unwrap()
            )
        );
        assert_eq!(
            conf_amounts[1].commitment,
            Commitment::from_vec(
                Vec::from_hex("091e1b9e7605fc214806f3af3eba13947b91f47bac729f5def5e8fbd530112bed1")
                    .unwrap()
            )
        );
        assert_eq!(
            conf_amounts[2].commitment,
            Commitment::from_vec(
                Vec::from_hex("089775f829c8adad92ada17b5931edf63064d54678f4eb9a6fdfe8e4cb5d95f6f4")
                    .unwrap()
            )
        );

        // Check no values returned for declarative and hash type
        assert_eq!(declarative_type.to_confidential_state_pedersen().len(), 0);
        assert_eq!(hash_type.to_confidential_state_pedersen().len(), 0);
    }

    #[test]
    fn test_all_state_hashed() {
        let declarative_type =
            AssignmentVec::strict_decode(&DECLARATIVE_VARIANT[..]).unwrap();
        let pedersan_type =
            AssignmentVec::strict_decode(&PEDERSAN_VARIANT[..]).unwrap();
        let hash_type =
            AssignmentVec::strict_decode(&HASH_VARIANT[..]).unwrap();

        // Extract state data from hash type variant and conceal them
        let extracted_states = hash_type.to_confidential_state_hashed();

        // Precomputed concealed state data
        let expected: [&str; 4] = [
            "fa6eae3e74de3e5dd92f58ac753d02b613daaaab",
            "6420cc421e1189805c8cec089d74c1980f79c069",
            "43e446006c5bc93864dafb03cf4ba472bedf5ca7",
            "69b01b4d96d00ceff2599eb089e4c7b979961fec",
        ];

        // Check extracted values matches with precomputed values
        assert_eq!(
            extracted_states
                .iter()
                .map(|hash| hash.to_hex())
                .collect::<Vec<String>>(),
            expected
        );

        // Check no values returned for declarative and pedersan types
        assert_eq!(declarative_type.to_confidential_state_hashed().len(), 0);
        assert_eq!(pedersan_type.to_confidential_state_hashed().len(), 0);
    }

    #[test]
    fn test_conceal() {
        // Only hash type is considered for concealment operations because
        // Declarative type has void state data
        // Pedersan type has very large concealed state data which slows down
        // the test
        let mut hash_type =
            AssignmentVec::strict_decode(&HASH_VARIANT[..]).unwrap();

        // CommitConceal all without any exception
        // This will create 2 Confidential and 2 ConfidentialState type
        // Assignments
        assert_eq!(2, hash_type.conceal_state());

        // Precomputed values of revealed seals in 2 ConfidentialState type
        // Assignments
        let known_txid: [&str; 2] = [
            "f57ed27ee4199072c5ff3b774febc94d26d3e4a5559d133de4750a948df50e06",
            "201fdd1e2b62d7b6938271295118ee181f1bac5e57d9f4528925650d36d3af8e",
        ];

        // Extracted seal values
        let extracted_txid: Vec<String> = hash_type
            .filter_revealed_seals()
            .iter()
            .map(|revealed| {
                match revealed.outpoint() {
                    Some(outpoint) => Some(outpoint.txid),
                    _ => None,
                }
                .unwrap()
                .to_hex()
            })
            .collect();

        // Check extracted values matches with precomputed values
        assert_eq!(known_txid.to_vec(), extracted_txid);

        // Precomputed of concealed seals of all 4 assignments
        let all_seals_confidential: [&str; 4] = [
            "7efe71b7a37a39da798774ca6b09def9724d81303892d55cac3edb0dc8340a3a",
            "9565d29461c863e013c26d176a9929307286963322849a1dc6c978e5c70c8d52",
            "dc0d0d7139a3ad6010a210e5900201979a1a09047b10a877688ee5a740ae215a",
            "9b64a3024632f0517d8a608cb29902f7083eab0ac25d2827a5ef27e9a68b18f9",
        ];

        // Extract concealed seals
        let extracted_seals_confidential: Vec<String> = hash_type
            .to_confidential_seals()
            .iter()
            .map(|hash| hash.to_hex())
            .collect();

        // Check extracted values matches with precomputed values
        assert_eq!(
            all_seals_confidential.to_vec(),
            extracted_seals_confidential
        );

        // Precomputed concealed state data of all 4 assignments
        let all_state_confidential = [
            "fa6eae3e74de3e5dd92f58ac753d02b613daaaab",
            "6420cc421e1189805c8cec089d74c1980f79c069",
            "43e446006c5bc93864dafb03cf4ba472bedf5ca7",
            "69b01b4d96d00ceff2599eb089e4c7b979961fec",
        ];

        // Extract concealed state data
        let extracted_state_confidential: Vec<String> = hash_type
            .to_confidential_state_hashed()
            .iter()
            .map(|confidential| confidential.to_hex())
            .collect();

        // Check extracted values matches with precomputed values
        assert_eq!(
            all_state_confidential.to_vec(),
            extracted_state_confidential
        );
    }

    #[test]
    fn test_len() {
        let declarative_type =
            AssignmentVec::strict_decode(&DECLARATIVE_VARIANT[..]).unwrap();
        let pedersan_type =
            AssignmentVec::strict_decode(&PEDERSAN_VARIANT[..]).unwrap();
        let hash_type =
            AssignmentVec::strict_decode(&HASH_VARIANT[..]).unwrap();

        // All variants have 4 assignments in them
        assert_eq!(declarative_type.len(), 4);
        assert_eq!(pedersan_type.len(), 4);
        assert_eq!(hash_type.len(), 4);
    }

    #[test]
    fn test_encoding_ancestor() {
        test_encode!((PARENT_RIGHTS, ParentOwnedRights));
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
        let vec_4: Vec<(NodeId, schema::OwnedRightType, u16)> =
            [vec_1, vec_2, vec_3].concat();

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
            seal_definition: Revealed::from(OutPoint::new(txid_vec[0], 1)),
            assigned_state: data::Void,
        };

        let assignment_2 =
            Assignment::<DeclarativeStrategy>::ConfidentialAmount {
                seal_definition: Revealed::from(OutPoint::new(txid_vec[1], 2)),
                assigned_state: data::Void,
            };

        let assignment_3 =
            Assignment::<DeclarativeStrategy>::ConfidentialSeal {
                seal_definition: Revealed::from(OutPoint::new(txid_vec[2], 3))
                    .commit_conceal(),
                assigned_state: data::Void,
            };

        let assignment_4 = Assignment::<DeclarativeStrategy>::Confidential {
            seal_definition: Revealed::from(OutPoint::new(txid_vec[3], 4))
                .commit_conceal(),
            assigned_state: data::Void,
        };

        let mut set = Vec::new();

        set.push(assignment_1);
        set.push(assignment_2);
        set.push(assignment_3);
        set.push(assignment_4);

        let declarative_variant = AssignmentVec::Declarative(set);

        // Create Pedersan Variant

        let txid_vec: Vec<bitcoin::Txid> = TXID_VEC
            .iter()
            .map(|txid| bitcoin::Txid::from_hex(txid).unwrap())
            .collect();

        let assignment_1 = Assignment::<PedersenStrategy>::Revealed {
            seal_definition: Revealed::from(OutPoint::new(txid_vec[0], 1)),
            assigned_state: value::Revealed::with_amount(10u64, &mut rng),
        };

        let assignment_2 = Assignment::<PedersenStrategy>::ConfidentialAmount {
            seal_definition: Revealed::from(OutPoint::new(txid_vec[1], 1)),
            assigned_state: value::Revealed::with_amount(20u64, &mut rng)
                .commit_conceal(),
        };

        let assignment_3 = Assignment::<PedersenStrategy>::ConfidentialSeal {
            seal_definition: Revealed::from(OutPoint::new(txid_vec[2], 1))
                .commit_conceal(),
            assigned_state: value::Revealed::with_amount(30u64, &mut rng),
        };

        let assignment_4 = Assignment::<PedersenStrategy>::Confidential {
            seal_definition: Revealed::from(OutPoint::new(txid_vec[3], 1))
                .commit_conceal(),
            assigned_state: value::Revealed::with_amount(10u64, &mut rng)
                .commit_conceal(),
        };

        let mut set = Vec::new();

        set.push(assignment_1);
        set.push(assignment_2);
        set.push(assignment_3);
        set.push(assignment_4);

        let pedersen_variant = AssignmentVec::DiscreteFiniteField(set);

        // Create Hash variant
        let txid_vec: Vec<bitcoin::Txid> = TXID_VEC
            .iter()
            .map(|txid| bitcoin::Txid::from_hex(txid).unwrap())
            .collect();

        let state_data_vec: Vec<data::Revealed> = STATE_DATA
            .iter()
            .map(|data| {
                data::Revealed::Sha256(sha256::Hash::from_hex(data).unwrap())
            })
            .collect();

        let assignment_1 = Assignment::<HashStrategy>::Revealed {
            seal_definition: Revealed::from(OutPoint::new(txid_vec[0], 1)),
            assigned_state: state_data_vec[0].clone(),
        };

        let assignment_2 = Assignment::<HashStrategy>::ConfidentialAmount {
            seal_definition: Revealed::from(OutPoint::new(txid_vec[1], 1)),
            assigned_state: state_data_vec[1].clone().commit_conceal(),
        };

        let assignment_3 = Assignment::<HashStrategy>::ConfidentialSeal {
            seal_definition: Revealed::from(OutPoint::new(txid_vec[2], 1))
                .commit_conceal(),
            assigned_state: state_data_vec[2].clone(),
        };

        let assignment_4 = Assignment::<HashStrategy>::Confidential {
            seal_definition: Revealed::from(OutPoint::new(txid_vec[3], 1))
                .commit_conceal(),
            assigned_state: state_data_vec[3].clone().commit_conceal(),
        };

        let mut set = Vec::new();

        set.push(assignment_1);
        set.push(assignment_2);
        set.push(assignment_3);
        set.push(assignment_4);

        let hash_variant = AssignmentVec::CustomData(set);

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
        let declarative_leaves: Vec<(schema::OwnedRightType, MerkleNode)> =
            declarative_variant
                .to_declarative_assignment_vec()
                .iter()
                .map(|assignment| {
                    (
                        type1,
                        MerkleNode::hash(&CommitEncode::commit_serialize(
                            assignment,
                        )),
                    )
                })
                .collect();

        let pedersan_leaves: Vec<(schema::OwnedRightType, MerkleNode)> =
            pedersen_variant
                .to_value_assignment_vec()
                .iter()
                .map(|assignment| {
                    (
                        type2,
                        MerkleNode::hash(&CommitEncode::commit_serialize(
                            assignment,
                        )),
                    )
                })
                .collect();

        let hash_leaves: Vec<(schema::OwnedRightType, MerkleNode)> =
            hash_variant
                .to_data_assignment_vec()
                .iter()
                .map(|assignment| {
                    (
                        type3,
                        MerkleNode::hash(&CommitEncode::commit_serialize(
                            assignment,
                        )),
                    )
                })
                .collect();

        // Combine all of them in a single collection
        let all_leaves =
            [declarative_leaves, pedersan_leaves, hash_leaves].concat();

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

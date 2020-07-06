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
use core::fmt::Debug;
use core::option::NoneError;
use std::collections::{BTreeMap, BTreeSet};

use super::{
    super::schema, amount, data, seal, Amount, AutoConceal, NodeId, SealDefinition, SECP256K1_ZKP,
};
use crate::bp::blind::OutpointHash;
use crate::client_side_validation::{commit_strategy, CommitEncodeWithStrategy, Conceal};
use crate::strict_encoding::{Error as EncodingError, StrictDecode, StrictEncode};

use bitcoin_hashes::core::cmp::Ordering;

pub type Assignments = BTreeMap<schema::AssignmentsType, AssignmentsVariant>;

impl CommitEncodeWithStrategy for Assignments {
    type Strategy = commit_strategy::Merklization;
}

pub type Ancestors = BTreeMap<NodeId, BTreeMap<schema::AssignmentsType, Vec<u16>>>;

impl CommitEncodeWithStrategy for Ancestors {
    type Strategy = commit_strategy::Merklization;
}

#[derive(Clone, Debug, Display)]
#[display_from(Debug)]
pub enum AssignmentsVariant {
    Declarative(BTreeSet<Assignment<DeclarativeStrategy>>),
    DiscreteFiniteField(BTreeSet<Assignment<PedersenStrategy>>),
    CustomData(BTreeSet<Assignment<HashStrategy>>),
}

impl AssignmentsVariant {
    pub fn zero_balanced(
        inputs: Vec<amount::Revealed>,
        allocations_ours: Vec<(SealDefinition, Amount)>,
        allocations_theirs: Vec<(OutpointHash, Amount)>,
    ) -> Self {
        // Generate random blinding factors
        let mut rng = rand::thread_rng();
        let count = allocations_theirs.len() + allocations_ours.len();
        let mut blinding_factors = Vec::<_>::with_capacity(count);
        for _ in 0..count {
            blinding_factors.push(amount::BlindingFactor::new(&SECP256K1_ZKP, &mut rng));
        }

        // We need the last factor to be equal to the difference
        let mut blinding_inputs: Vec<_> = inputs.iter().map(|inp| inp.blinding.clone()).collect();
        if blinding_inputs.is_empty() {
            blinding_inputs.push(secp256k1zkp::key::ONE_KEY);
        }

        // remove one output blinding factor and replace it with the correction factor
        blinding_factors.pop();
        let blinding_correction = SECP256K1_ZKP
            .blind_sum(blinding_inputs.clone(), blinding_factors.clone())
            .expect("SECP256K1_ZKP failure has negligible probability");
        blinding_factors.push(blinding_correction);

        let mut set: BTreeSet<Assignment<_>> = allocations_ours
            .into_iter()
            .map(|(seal_definition, amount)| Assignment::Revealed {
                seal_definition,
                assigned_state: amount::Revealed {
                    amount,
                    blinding: blinding_factors.pop().unwrap(), // factors are counted, so it's safe to unwrap here
                },
            })
            .collect();
        set.extend(
            allocations_theirs
                .into_iter()
                .map(|(seal_definition, amount)| Assignment::ConfidentialSeal {
                    seal_definition,
                    assigned_state: amount::Revealed {
                        amount,
                        blinding: blinding_factors.pop().unwrap(), // factors are counted, so it's safe to unwrap here
                    },
                }),
        );

        Self::DiscreteFiniteField(set)
    }

    #[inline]
    pub fn is_declarative(&self) -> bool {
        match self {
            AssignmentsVariant::Declarative(_) => true,
            _ => false,
        }
    }

    #[inline]
    pub fn is_field(&self) -> bool {
        match self {
            AssignmentsVariant::DiscreteFiniteField(_) => true,
            _ => false,
        }
    }

    #[inline]
    pub fn is_data(&self) -> bool {
        match self {
            AssignmentsVariant::CustomData(_) => true,
            _ => false,
        }
    }

    #[inline]
    pub fn declarative(&self) -> Option<&BTreeSet<Assignment<DeclarativeStrategy>>> {
        match self {
            AssignmentsVariant::Declarative(set) => Some(set),
            _ => None,
        }
    }

    #[inline]
    pub fn declarative_mut(&mut self) -> Option<&mut BTreeSet<Assignment<DeclarativeStrategy>>> {
        match self {
            AssignmentsVariant::Declarative(set) => Some(set),
            _ => None,
        }
    }

    #[inline]
    pub fn field(&self) -> Option<&BTreeSet<Assignment<PedersenStrategy>>> {
        match self {
            AssignmentsVariant::DiscreteFiniteField(set) => Some(set),
            _ => None,
        }
    }

    #[inline]
    pub fn field_mut(&mut self) -> Option<&mut BTreeSet<Assignment<PedersenStrategy>>> {
        match self {
            AssignmentsVariant::DiscreteFiniteField(set) => Some(set),
            _ => None,
        }
    }

    #[inline]
    pub fn data(&self) -> Option<&BTreeSet<Assignment<HashStrategy>>> {
        match self {
            AssignmentsVariant::CustomData(set) => Some(set),
            _ => None,
        }
    }

    #[inline]
    pub fn data_mut(&mut self) -> Option<&mut BTreeSet<Assignment<HashStrategy>>> {
        match self {
            AssignmentsVariant::CustomData(set) => Some(set),
            _ => None,
        }
    }

    pub fn seal(&self, index: u16) -> Result<Option<&seal::Revealed>, NoneError> {
        // NB: Seal indexes are part of the consensus commitment, so we have to use
        // deterministic ordering of the seals. This is currently done by using
        // `sort` vector method and `Ord` implementation for the `Assignment` type
        Ok(match self {
            AssignmentsVariant::Declarative(set) => {
                let mut vec = set.into_iter().collect::<Vec<_>>();
                vec.sort();
                vec.get(index as usize)?.seal_definition()
            }
            AssignmentsVariant::DiscreteFiniteField(set) => {
                let mut vec = set.into_iter().collect::<Vec<_>>();
                vec.sort();
                vec.get(index as usize)?.seal_definition()
            }
            AssignmentsVariant::CustomData(set) => {
                let mut vec = set.into_iter().collect::<Vec<_>>();
                vec.sort();
                vec.get(index as usize)?.seal_definition()
            }
        })
    }

    pub fn known_seals(&self) -> Vec<&seal::Revealed> {
        match self {
            AssignmentsVariant::Declarative(s) => s
                .into_iter()
                .filter_map(Assignment::<_>::seal_definition)
                .collect(),
            AssignmentsVariant::DiscreteFiniteField(s) => s
                .into_iter()
                .filter_map(Assignment::<_>::seal_definition)
                .collect(),
            AssignmentsVariant::CustomData(s) => s
                .into_iter()
                .filter_map(Assignment::<_>::seal_definition)
                .collect(),
        }
    }

    pub fn all_seals(&self) -> Vec<seal::Confidential> {
        match self {
            AssignmentsVariant::Declarative(s) => s
                .into_iter()
                .map(Assignment::<_>::seal_definition_confidential)
                .collect(),
            AssignmentsVariant::DiscreteFiniteField(s) => s
                .into_iter()
                .map(Assignment::<_>::seal_definition_confidential)
                .collect(),
            AssignmentsVariant::CustomData(s) => s
                .into_iter()
                .map(Assignment::<_>::seal_definition_confidential)
                .collect(),
        }
    }

    pub fn known_state_homomorphic(&self) -> Vec<&amount::Revealed> {
        match self {
            AssignmentsVariant::Declarative(_) => vec![],
            AssignmentsVariant::DiscreteFiniteField(s) => s
                .into_iter()
                .filter_map(Assignment::<_>::assigned_state)
                .collect(),
            AssignmentsVariant::CustomData(_) => vec![],
        }
    }

    pub fn known_state_data(&self) -> Vec<&data::Revealed> {
        match self {
            AssignmentsVariant::Declarative(_) => vec![],
            AssignmentsVariant::DiscreteFiniteField(_) => vec![],
            AssignmentsVariant::CustomData(s) => s
                .into_iter()
                .filter_map(Assignment::<_>::assigned_state)
                .collect(),
        }
    }

    pub fn all_state_pedersen(&self) -> Vec<amount::Confidential> {
        match self {
            AssignmentsVariant::Declarative(_) => vec![],
            AssignmentsVariant::DiscreteFiniteField(s) => s
                .into_iter()
                .map(Assignment::<_>::assigned_state_confidential)
                .collect(),
            AssignmentsVariant::CustomData(_) => vec![],
        }
    }

    pub fn all_state_hashed(&self) -> Vec<data::Confidential> {
        match self {
            AssignmentsVariant::Declarative(_) => vec![],
            AssignmentsVariant::DiscreteFiniteField(_) => vec![],
            AssignmentsVariant::CustomData(s) => s
                .into_iter()
                .map(Assignment::<_>::assigned_state_confidential)
                .collect(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            AssignmentsVariant::Declarative(set) => set.len(),
            AssignmentsVariant::DiscreteFiniteField(set) => set.len(),
            AssignmentsVariant::CustomData(set) => set.len(),
        }
    }
}

impl AutoConceal for AssignmentsVariant {
    fn conceal_except(&mut self, seals: &Vec<seal::Confidential>) -> usize {
        match self {
            AssignmentsVariant::Declarative(data) => data as &mut dyn AutoConceal,
            AssignmentsVariant::DiscreteFiniteField(data) => data as &mut dyn AutoConceal,
            AssignmentsVariant::CustomData(data) => data as &mut dyn AutoConceal,
        }
        .conceal_except(seals)
    }
}

impl CommitEncodeWithStrategy for AssignmentsVariant {
    type Strategy = commit_strategy::UsingStrict;
}

pub trait ConfidentialState:
    StrictEncode<Error = EncodingError> + StrictDecode<Error = EncodingError> + Debug + Clone + AsAny
{
}

pub trait RevealedState:
    StrictEncode<Error = EncodingError>
    + StrictDecode<Error = EncodingError>
    + Debug
    + Conceal
    + Clone
    + AsAny
{
}

pub trait StateTypes: Debug {
    type Confidential: ConfidentialState;
    type Revealed: RevealedState;
}

#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq)]
pub struct DeclarativeStrategy;
impl StateTypes for DeclarativeStrategy {
    type Confidential = data::Void;
    type Revealed = data::Void;
}

#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq)]
pub struct PedersenStrategy;
impl StateTypes for PedersenStrategy {
    type Confidential = amount::Confidential;
    type Revealed = amount::Revealed;
}

#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq)]
pub struct HashStrategy;
impl StateTypes for HashStrategy {
    type Confidential = data::Confidential;
    type Revealed = data::Revealed;
}

#[derive(Clone, Debug, Display)]
#[display_from(Debug)]
pub enum Assignment<STATE>
where
    STATE: StateTypes,
    // Deterministic ordering requires Eq operation, so the confidential
    // state must have it
    STATE::Confidential: PartialEq + Eq,
    STATE::Confidential: From<<STATE::Revealed as Conceal>::Confidential>,
    EncodingError: From<<STATE::Confidential as StrictEncode>::Error>
        + From<<STATE::Confidential as StrictDecode>::Error>
        + From<<STATE::Revealed as StrictEncode>::Error>
        + From<<STATE::Revealed as StrictDecode>::Error>,
{
    Confidential {
        seal_definition: seal::Confidential,
        assigned_state: STATE::Confidential,
    },
    Revealed {
        seal_definition: seal::Revealed,
        assigned_state: STATE::Revealed,
    },
    ConfidentialSeal {
        seal_definition: seal::Confidential,
        assigned_state: STATE::Revealed,
    },
    ConfidentialAmount {
        seal_definition: seal::Revealed,
        assigned_state: STATE::Confidential,
    },
}

// Consensus-critical!
// Assignment indexes are part of the transition ancestor's commitment, so
// here we use deterministic ordering based on hash values of the concealed
// seal data contained within the assignment
impl<STATE> PartialOrd for Assignment<STATE>
where
    STATE: StateTypes,
    STATE::Confidential: PartialEq + Eq,
    STATE::Confidential: From<<STATE::Revealed as Conceal>::Confidential>,
    EncodingError: From<<STATE::Confidential as StrictEncode>::Error>
        + From<<STATE::Confidential as StrictDecode>::Error>
        + From<<STATE::Revealed as StrictEncode>::Error>
        + From<<STATE::Revealed as StrictDecode>::Error>,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.seal_definition_confidential()
            .partial_cmp(&other.seal_definition_confidential())
    }
}

impl<STATE> Ord for Assignment<STATE>
where
    STATE: StateTypes,
    STATE::Confidential: PartialEq + Eq,
    STATE::Confidential: From<<STATE::Revealed as Conceal>::Confidential>,
    EncodingError: From<<STATE::Confidential as StrictEncode>::Error>
        + From<<STATE::Confidential as StrictDecode>::Error>
        + From<<STATE::Revealed as StrictEncode>::Error>
        + From<<STATE::Revealed as StrictDecode>::Error>,
{
    fn cmp(&self, other: &Self) -> Ordering {
        self.seal_definition_confidential()
            .cmp(&other.seal_definition_confidential())
    }
}

impl<STATE> PartialEq for Assignment<STATE>
where
    STATE: StateTypes,
    STATE::Confidential: PartialEq + Eq,
    STATE::Confidential: From<<STATE::Revealed as Conceal>::Confidential>,
    EncodingError: From<<STATE::Confidential as StrictEncode>::Error>
        + From<<STATE::Confidential as StrictDecode>::Error>
        + From<<STATE::Revealed as StrictEncode>::Error>
        + From<<STATE::Revealed as StrictDecode>::Error>,
{
    fn eq(&self, other: &Self) -> bool {
        self.seal_definition_confidential() == other.seal_definition_confidential()
            && self.assigned_state_confidential() == other.assigned_state_confidential()
    }
}

impl<STATE> Eq for Assignment<STATE>
where
    STATE: StateTypes,
    STATE::Confidential: PartialEq + Eq,
    STATE::Confidential: From<<STATE::Revealed as Conceal>::Confidential>,
    EncodingError: From<<STATE::Confidential as StrictEncode>::Error>
        + From<<STATE::Confidential as StrictDecode>::Error>
        + From<<STATE::Revealed as StrictEncode>::Error>
        + From<<STATE::Revealed as StrictDecode>::Error>,
{
}

impl<STATE> Assignment<STATE>
where
    STATE: StateTypes,
    STATE::Confidential: PartialEq + Eq,
    STATE::Confidential: From<<STATE::Revealed as Conceal>::Confidential>,
    EncodingError: From<<STATE::Confidential as StrictEncode>::Error>
        + From<<STATE::Confidential as StrictDecode>::Error>
        + From<<STATE::Revealed as StrictEncode>::Error>
        + From<<STATE::Revealed as StrictDecode>::Error>,
{
    pub fn seal_definition_confidential(&self) -> seal::Confidential {
        match self {
            Assignment::Revealed {
                seal_definition, ..
            }
            | Assignment::ConfidentialAmount {
                seal_definition, ..
            } => seal_definition.conceal(),
            Assignment::Confidential {
                seal_definition, ..
            }
            | Assignment::ConfidentialSeal {
                seal_definition, ..
            } => *seal_definition,
        }
    }

    pub fn seal_definition(&self) -> Option<&seal::Revealed> {
        match self {
            Assignment::Revealed {
                seal_definition, ..
            }
            | Assignment::ConfidentialAmount {
                seal_definition, ..
            } => Some(seal_definition),
            Assignment::Confidential { .. } | Assignment::ConfidentialSeal { .. } => None,
        }
    }

    pub fn assigned_state_confidential(&self) -> STATE::Confidential {
        match self {
            Assignment::Revealed { assigned_state, .. }
            | Assignment::ConfidentialSeal { assigned_state, .. } => {
                assigned_state.conceal().into()
            }
            Assignment::Confidential { assigned_state, .. }
            | Assignment::ConfidentialAmount { assigned_state, .. } => assigned_state.clone(),
        }
    }

    pub fn assigned_state(&self) -> Option<&STATE::Revealed> {
        match self {
            Assignment::Revealed { assigned_state, .. }
            | Assignment::ConfidentialSeal { assigned_state, .. } => Some(assigned_state),
            Assignment::Confidential { .. } | Assignment::ConfidentialAmount { .. } => None,
        }
    }
}

impl<STATE> Conceal for Assignment<STATE>
where
    Self: Clone,
    STATE: StateTypes,
    STATE::Confidential: PartialEq + Eq,
    STATE::Confidential: From<<STATE::Revealed as Conceal>::Confidential>,
    EncodingError: From<<STATE::Confidential as StrictEncode>::Error>
        + From<<STATE::Confidential as StrictDecode>::Error>
        + From<<STATE::Revealed as StrictEncode>::Error>
        + From<<STATE::Revealed as StrictDecode>::Error>,
{
    type Confidential = Assignment<STATE>;

    fn conceal(&self) -> Self {
        match self {
            Assignment::Confidential { .. } | Assignment::ConfidentialAmount { .. } => self.clone(),
            Assignment::Revealed {
                seal_definition,
                assigned_state,
            } => Self::ConfidentialAmount {
                seal_definition: seal_definition.clone(),
                assigned_state: assigned_state.conceal().into(),
            },
            Assignment::ConfidentialSeal {
                seal_definition,
                assigned_state,
            } => Self::Confidential {
                seal_definition: seal_definition.clone(),
                assigned_state: assigned_state.conceal().into(),
            },
        }
    }
}

impl<STATE> AutoConceal for Assignment<STATE>
where
    STATE: StateTypes,
    STATE::Revealed: Conceal,
    STATE::Confidential: PartialEq + Eq,
    <STATE as StateTypes>::Confidential: From<<STATE::Revealed as Conceal>::Confidential>,
    EncodingError: From<<STATE::Confidential as StrictEncode>::Error>
        + From<<STATE::Confidential as StrictDecode>::Error>
        + From<<STATE::Revealed as StrictEncode>::Error>
        + From<<STATE::Revealed as StrictDecode>::Error>,
{
    fn conceal_except(&mut self, seals: &Vec<seal::Confidential>) -> usize {
        match self {
            Assignment::Confidential { .. } | Assignment::ConfidentialAmount { .. } => 0,
            Assignment::ConfidentialSeal {
                seal_definition,
                assigned_state,
            } => {
                if seals.contains(&seal_definition) {
                    0
                } else {
                    *self = Assignment::<STATE>::Confidential {
                        assigned_state: assigned_state.conceal().into(),
                        seal_definition: seal_definition.clone(),
                    };
                    1
                }
            }
            Assignment::Revealed {
                seal_definition,
                assigned_state,
            } => {
                if seals.contains(&seal_definition.conceal()) {
                    0
                } else {
                    *self = Assignment::<STATE>::ConfidentialAmount {
                        assigned_state: assigned_state.conceal().into(),
                        seal_definition: seal_definition.clone(),
                    };
                    1
                }
            }
        }
    }
}

impl<STATE> CommitEncodeWithStrategy for Assignment<STATE>
where
    STATE: StateTypes,
    STATE::Confidential: PartialEq + Eq,
    STATE::Confidential: From<<STATE::Revealed as Conceal>::Confidential>,
    EncodingError: From<<STATE::Confidential as StrictEncode>::Error>
        + From<<STATE::Confidential as StrictDecode>::Error>
        + From<<STATE::Revealed as StrictEncode>::Error>
        + From<<STATE::Revealed as StrictDecode>::Error>,
{
    type Strategy = commit_strategy::UsingConceal;
}

mod strict_encoding {
    use super::*;
    use crate::strict_encoding::Error;
    use data::strict_encoding::EncodingTag;
    use std::io;

    impl StrictEncode for AssignmentsVariant {
        type Error = Error;

        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
            Ok(match self {
                AssignmentsVariant::Declarative(tree) => {
                    strict_encode_list!(e; schema::StateType::Declarative, tree)
                }
                AssignmentsVariant::DiscreteFiniteField(tree) => {
                    strict_encode_list!(e; schema::StateType::DiscreteFiniteField, EncodingTag::U64, tree)
                }
                AssignmentsVariant::CustomData(tree) => {
                    strict_encode_list!(e; schema::StateType::CustomData, tree)
                }
            })
        }
    }

    impl StrictDecode for AssignmentsVariant {
        type Error = Error;

        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
            let format = schema::StateType::strict_decode(&mut d)?;
            Ok(match format {
                schema::StateType::Declarative => {
                    AssignmentsVariant::Declarative(BTreeSet::strict_decode(d)?)
                }
                schema::StateType::DiscreteFiniteField => match EncodingTag::strict_decode(&mut d)?
                {
                    EncodingTag::U64 => {
                        AssignmentsVariant::DiscreteFiniteField(BTreeSet::strict_decode(&mut d)?)
                    }
                    _ => Err(Error::UnsupportedDataStructure(
                        "We support only homomorphic commitments to U64 data".to_string(),
                    ))?,
                },
                schema::StateType::CustomData => {
                    AssignmentsVariant::CustomData(BTreeSet::strict_decode(d)?)
                }
            })
        }
    }

    impl<STATE> StrictEncode for Assignment<STATE>
    where
        STATE: StateTypes,
        STATE::Confidential: PartialEq + Eq,
        STATE::Confidential: From<<STATE::Revealed as Conceal>::Confidential>,
        EncodingError: From<<STATE::Confidential as StrictEncode>::Error>
            + From<<STATE::Confidential as StrictDecode>::Error>
            + From<<STATE::Revealed as StrictEncode>::Error>
            + From<<STATE::Revealed as StrictDecode>::Error>,
    {
        type Error = Error;

        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
            Ok(match self {
                Assignment::Confidential {
                    seal_definition,
                    assigned_state,
                } => strict_encode_list!(e; 0u8, seal_definition, assigned_state),
                Assignment::Revealed {
                    seal_definition,
                    assigned_state,
                } => strict_encode_list!(e; 1u8, seal_definition, assigned_state),
                Assignment::ConfidentialSeal {
                    seal_definition,
                    assigned_state,
                } => strict_encode_list!(e; 2u8, seal_definition, assigned_state),
                Assignment::ConfidentialAmount {
                    seal_definition,
                    assigned_state,
                } => strict_encode_list!(e; 3u8, seal_definition, assigned_state),
            })
        }
    }

    impl<STATE> StrictDecode for Assignment<STATE>
    where
        STATE: StateTypes,
        STATE::Confidential: PartialEq + Eq,
        STATE::Confidential: From<<STATE::Revealed as Conceal>::Confidential>,
        EncodingError: From<<STATE::Confidential as StrictEncode>::Error>
            + From<<STATE::Confidential as StrictDecode>::Error>
            + From<<STATE::Revealed as StrictEncode>::Error>
            + From<<STATE::Revealed as StrictDecode>::Error>,
    {
        type Error = Error;

        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
            let format = u8::strict_decode(&mut d)?;
            Ok(match format {
                0u8 => Assignment::Confidential {
                    seal_definition: seal::Confidential::strict_decode(&mut d)?,
                    assigned_state: STATE::Confidential::strict_decode(&mut d)?,
                },
                1u8 => Assignment::Revealed {
                    seal_definition: seal::Revealed::strict_decode(&mut d)?,
                    assigned_state: STATE::Revealed::strict_decode(&mut d)?,
                },
                2u8 => Assignment::ConfidentialSeal {
                    seal_definition: seal::Confidential::strict_decode(&mut d)?,
                    assigned_state: STATE::Revealed::strict_decode(&mut d)?,
                },
                3u8 => Assignment::ConfidentialAmount {
                    seal_definition: seal::Revealed::strict_decode(&mut d)?,
                    assigned_state: STATE::Confidential::strict_decode(&mut d)?,
                },
                invalid => Err(Error::EnumValueNotKnown("Assignment".to_string(), invalid))?,
            })
        }
    }
}

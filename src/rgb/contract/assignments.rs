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

use std::collections::BTreeSet;

use super::{super::schema, amount, data, seal, Amount, SealDefinition};
use crate::bp::blind::OutpointHash;
use crate::client_side_validation::{commit_strategy, CommitEncodeWithStrategy, Conceal};
use crate::strict_encoding::{Error as EncodingError, StrictDecode, StrictEncode};

use secp256k1zkp::Secp256k1 as Secp256k1zkp;
lazy_static! {
    /// Secp256k1zpk context object
    static ref SECP256K1_ZKP: Secp256k1zkp = Secp256k1zkp::with_caps(secp256k1zkp::ContextFlag::Commit);
}

#[derive(Clone, Debug, Display)]
#[display_from(Debug)]
pub enum AssignmentsVariant {
    Void(BTreeSet<Assignment<VoidStrategy>>),
    Homomorphic(BTreeSet<Assignment<HomomorphStrategy>>),
    Hashed(BTreeSet<Assignment<HashStrategy>>),
}

impl AssignmentsVariant {
    /// Returns `None` if bot `allocations_ours` and `allocations_theirs` vecs
    /// are empty
    pub fn zero_balanced(
        mut inputs: Vec<amount::Revealed>,
        allocations_ours: Vec<(SealDefinition, Amount)>,
        allocations_theirs: Vec<(OutpointHash, Amount)>,
    ) -> Option<Self> {
        let mut rng = rand::thread_rng();
        let mut blinding_factors = vec![];

        if inputs.is_empty() {
            inputs = vec![amount::Revealed {
                amount: 0,
                blinding: secp256k1zkp::key::ZERO_KEY,
            }];
        }

        let mut list_ours: Vec<_> = allocations_ours
            .into_iter()
            .map(|(seal, amount)| {
                let blinding = amount::BlindingFactor::new(&SECP256K1_ZKP, &mut rng);
                blinding_factors.push(blinding.clone());
                (seal, amount::Revealed { amount, blinding })
            })
            .collect();

        let mut list_theirs: Vec<_> = allocations_theirs
            .into_iter()
            .map(|(seal_hash, amount)| {
                let blinding = amount::BlindingFactor::new(&SECP256K1_ZKP, &mut rng);
                blinding_factors.push(blinding.clone());
                (seal_hash, amount::Revealed { amount, blinding })
            })
            .collect();

        let blinding_inputs = inputs.iter().map(|inp| inp.blinding.clone()).collect();
        let mut blinding_correction = SECP256K1_ZKP
            .blind_sum(blinding_inputs, blinding_factors)
            .expect("Internal inconsistency in Grin secp256k1zkp library Pedersen commitments");
        blinding_correction.neg_assign(&SECP256K1_ZKP).expect(
            "You won lottery and will live forever: the probability \
                    of this event is less than a life of the universe",
        );
        if let Some(item) = list_ours.last_mut() {
            let blinding = &mut item.1.blinding;
            blinding
                .add_assign(&SECP256K1_ZKP, &blinding_correction)
                .expect(
                    "You won lottery and will live forever: the probability \
                    of this event is less than a lifetime of the universe",
                );
        } else if let Some(item) = list_theirs.last_mut() {
            let blinding = &mut item.1.blinding;
            blinding
                .add_assign(&SECP256K1_ZKP, &blinding_correction)
                .expect(
                    "You won lottery and will live forever: the probability \
                    of this event is less than a lifetime of the universe",
                );
        } else {
            return None;
        }

        let set = list_ours
            .into_iter()
            .map(|(seal_definition, assigned_state)| Assignment::Revealed {
                seal_definition,
                assigned_state,
            })
            .chain(
                list_theirs
                    .into_iter()
                    .map(|(seal_definition, assigned_state)| Assignment::Partial {
                        seal_definition,
                        assigned_state,
                    }),
            )
            .collect();

        Some(Self::Homomorphic(set))
    }

    pub fn known_seals(&self) -> Vec<&SealDefinition> {
        match self {
            AssignmentsVariant::Void(s) => s
                .into_iter()
                .filter_map(|a| match a {
                    Assignment::Revealed {
                        seal_definition, ..
                    } => Some(seal_definition),
                    _ => None,
                })
                .collect(),
            AssignmentsVariant::Homomorphic(s) => s
                .into_iter()
                .filter_map(|a| match a {
                    Assignment::Revealed {
                        seal_definition, ..
                    } => Some(seal_definition),
                    _ => None,
                })
                .collect(),
            AssignmentsVariant::Hashed(s) => s
                .into_iter()
                .filter_map(|a| match a {
                    Assignment::Revealed {
                        seal_definition, ..
                    } => Some(seal_definition),
                    _ => None,
                })
                .collect(),
        }
    }
}

impl CommitEncodeWithStrategy for AssignmentsVariant {
    type Strategy = commit_strategy::UsingStrict;
}

pub trait StateTypes: core::fmt::Debug {
    type Confidential: StrictEncode + StrictDecode + core::fmt::Debug + Eq + Ord + Clone;
    type Revealed: StrictEncode + StrictDecode + core::fmt::Debug + Eq + Ord + Conceal + Clone;
}

#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq)]
pub struct VoidStrategy;
impl StateTypes for VoidStrategy {
    type Confidential = data::Void;
    type Revealed = data::Void;
}

#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq)]
pub struct HomomorphStrategy;
impl StateTypes for HomomorphStrategy {
    type Confidential = amount::Confidential;
    type Revealed = amount::Revealed;
}

#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq)]
pub struct HashStrategy;
impl StateTypes for HashStrategy {
    type Confidential = data::Confidential;
    type Revealed = data::Revealed;
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Display)]
#[display_from(Debug)]
pub enum Assignment<STATE>
where
    STATE: StateTypes,
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
    Partial {
        seal_definition: seal::Confidential,
        assigned_state: STATE::Revealed,
    },
}

impl<STATE> Conceal for Assignment<STATE>
where
    STATE: StateTypes,
    STATE::Confidential: From<<STATE::Revealed as Conceal>::Confidential>,
    EncodingError: From<<STATE::Confidential as StrictEncode>::Error>
        + From<<STATE::Confidential as StrictDecode>::Error>
        + From<<STATE::Revealed as StrictEncode>::Error>
        + From<<STATE::Revealed as StrictDecode>::Error>,
{
    type Confidential = Assignment<STATE>;

    fn conceal(&self) -> Self {
        match self {
            Assignment::Confidential {
                seal_definition,
                assigned_state,
            } => Assignment::Confidential {
                seal_definition: *seal_definition,
                assigned_state: assigned_state.clone(),
            },
            Assignment::Revealed {
                seal_definition,
                assigned_state,
            } => Self::Confidential {
                seal_definition: seal_definition.conceal(),
                assigned_state: assigned_state.conceal().into(),
            },
            Assignment::Partial {
                seal_definition,
                assigned_state,
            } => Self::Confidential {
                seal_definition: *seal_definition,
                assigned_state: assigned_state.conceal().into(),
            },
        }
    }
}

impl<STATE> CommitEncodeWithStrategy for Assignment<STATE>
where
    STATE: StateTypes,
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
                AssignmentsVariant::Void(tree) => {
                    strict_encode_list!(e; schema::StateType::Void, tree)
                }
                AssignmentsVariant::Homomorphic(tree) => {
                    strict_encode_list!(e; schema::StateType::Homomorphic, EncodingTag::U64, tree)
                }
                AssignmentsVariant::Hashed(tree) => {
                    strict_encode_list!(e; schema::StateType::Hashed, tree)
                }
            })
        }
    }

    impl StrictDecode for AssignmentsVariant {
        type Error = Error;

        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
            let format = schema::StateType::strict_decode(&mut d)?;
            Ok(match format {
                schema::StateType::Void => AssignmentsVariant::Void(BTreeSet::strict_decode(d)?),
                schema::StateType::Homomorphic => match EncodingTag::strict_decode(&mut d)? {
                    EncodingTag::U64 => {
                        AssignmentsVariant::Homomorphic(BTreeSet::strict_decode(&mut d)?)
                    }
                    _ => Err(Error::UnsupportedDataStructure(
                        "We support only homomorphic commitments to U64 data".to_string(),
                    ))?,
                },
                schema::StateType::Hashed => {
                    AssignmentsVariant::Hashed(BTreeSet::strict_decode(d)?)
                }
            })
        }
    }

    impl<STATE> StrictEncode for Assignment<STATE>
    where
        STATE: StateTypes,
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
                Assignment::Partial {
                    seal_definition,
                    assigned_state,
                } => strict_encode_list!(e; 2u8, seal_definition, assigned_state),
            })
        }
    }

    impl<STATE> StrictDecode for Assignment<STATE>
    where
        STATE: StateTypes,
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
                2u8 => Assignment::Partial {
                    seal_definition: seal::Confidential::strict_decode(&mut d)?,
                    assigned_state: STATE::Revealed::strict_decode(&mut d)?,
                },
                invalid => Err(Error::EnumValueNotKnown("Assignment".to_string(), invalid))?,
            })
        }
    }
}

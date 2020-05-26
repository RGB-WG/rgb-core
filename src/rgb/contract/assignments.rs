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
use crate::client_side_validation::{commit_strategy, CommitEncodeWithStrategy, Conceal};
use crate::strict_encoding::{Error as EncodingError, StrictDecode, StrictEncode};

#[derive(Clone, Debug, Display)]
#[display_from(Debug)]
pub enum AssignmentsVariant {
    Void(BTreeSet<Assignment<VoidStrategy>>),
    Homomorphic(u64, BTreeSet<Assignment<HomomorphStrategy>>),
    Hashed(BTreeSet<Assignment<HashStrategy>>),
}

impl AssignmentsVariant {
    pub fn zero_balanced(
        allocations: Vec<(SealDefinition, Amount)>,
        homomorphic_factor: u64,
    ) -> Self {
        let secp = secp256k1zkp::Secp256k1::with_caps(secp256k1zkp::ContextFlag::Commit);
        let mut rng = rand::thread_rng();
        let mut blinding_factors = vec![];

        let mut list: Vec<_> = allocations
            .into_iter()
            .map(|(seal, amount)| {
                let blinding = amount::BlindingFactor::new(&secp, &mut rng);
                blinding_factors.push(blinding.clone());
                (seal, amount::Revealed { amount, blinding })
            })
            .collect();

        let mut blinding_correction = secp
            .blind_sum(vec![secp256k1zkp::key::ZERO_KEY], blinding_factors)
            .expect("Internal inconsistency in Grin secp256k1zkp library Pedersen commitments");
        blinding_correction.neg_assign(&secp).expect(
            "You won lottery and will live forever: the probability \
                    of this event is less than a life of the universe",
        );
        if let Some(item) = list.last_mut() {
            let blinding = &mut item.1.blinding;
            blinding.add_assign(&secp, &blinding_correction).expect(
                "You won lottery and will live forever: the probability \
                    of this event is less than a life of the universe",
            );
        }

        let set = list
            .into_iter()
            .map(|item| Assignment::Revealed {
                seal_definition: item.0,
                assigned_state: item.1,
            })
            .collect();

        Self::Homomorphic(homomorphic_factor, set)
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
                AssignmentsVariant::Homomorphic(homomorphic_factor, tree) => {
                    strict_encode_list!(e; EncodingTag::U64, homomorphic_factor, schema::StateType::Homomorphic, tree)
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
                    EncodingTag::U64 => AssignmentsVariant::Homomorphic(
                        u64::strict_decode(&mut d)?,
                        BTreeSet::strict_decode(&mut d)?,
                    ),
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
                invalid => Err(Error::EnumValueNotKnown("Assignment".to_string(), invalid))?,
            })
        }
    }
}

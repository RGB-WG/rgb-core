// LNP/BP Rust Library
// Written in 2020 by
//     Rajarshi Maitra <rajarshi149@protonmail.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the MIT License
// along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

use crate::contract::nodes::{Extension, Genesis, Node, Transition};
use crate::contract::{Assignments, OwnedState, StateTypes};
use lnpbp::client_side_validation::{
    CommitConceal, CommitEncode, ConsensusCommit,
};
/// A trait to merge two structures modifying the revealed status
/// of the first one.
///
/// The resulting structure will depend on the openness of the both the input.
/// And the most revealed condition among the two will be selected
/// Usage: prevent hiding already known previous state data by merging
/// incoming new consignment in stash.
///
/// The follwoing conversion logic is intended by this trait:
///
/// merge (Revelaed, Anything) = Revealed
/// merge(ConfidentialSeal, ConfidentiualAmount) = Revealed
/// merge(ConfidentialAmount, ConfidentialSeal) = Revealed
/// merge(Confidential, Anything) = Anything
///   
pub trait MergeRevealed: Sized {
    fn merge_revealed(&mut self, other: &Self) -> Result<bool, String>;
}

impl<STATE> MergeRevealed for OwnedState<STATE>
where
    Self: Clone,
    STATE: StateTypes,
    STATE::Confidential: PartialEq + Eq,
    STATE::Confidential:
        From<<STATE::Revealed as CommitConceal>::ConcealedCommitment>,
{
    fn merge_revealed(&mut self, other: &Self) -> Result<bool, String> {
        // if self and other is different through error
        if self.commit_serialize() != other.commit_serialize() {
            Err(s!("Owned state data missmatch in merge operation"))
        } else {
            match (self.clone(), other) {
                // Anything + Revealed = Revealed
                (
                    _,
                    OwnedState::Revealed {
                        seal_definition: seal,
                        assigned_state: state,
                    },
                ) => {
                    *self = OwnedState::Revealed {
                        seal_definition: seal.clone(),
                        assigned_state: state.clone(),
                    };
                    Ok(true)
                }

                // Revealed + Anything = Revealed
                (OwnedState::Revealed { .. }, _) => Ok(true),

                // ConfidentialAmount + ConfidentialSeal = Revealed
                (
                    OwnedState::ConfidentialSeal {
                        assigned_state: state,
                        ..
                    },
                    OwnedState::ConfidentialAmount {
                        seal_definition: seal,
                        ..
                    },
                ) => {
                    *self = OwnedState::Revealed {
                        seal_definition: seal.clone(),
                        assigned_state: state.clone(),
                    };

                    Ok(true)
                }

                // ConfidentialSeal + ConfidentialAmount = Revealed
                (
                    OwnedState::ConfidentialAmount {
                        seal_definition: seal,
                        ..
                    },
                    OwnedState::ConfidentialSeal {
                        assigned_state: state,
                        ..
                    },
                ) => {
                    *self = OwnedState::Revealed {
                        seal_definition: seal.clone(),
                        assigned_state: state.clone(),
                    };

                    Ok(true)
                }

                // if self and other is of same variant do nothing
                (
                    OwnedState::ConfidentialAmount { .. },
                    OwnedState::ConfidentialAmount { .. },
                ) => Ok(true),
                (
                    OwnedState::ConfidentialSeal { .. },
                    OwnedState::ConfidentialSeal { .. },
                ) => Ok(true),

                // Anything + Confidential = Anything
                (_, OwnedState::Confidential { .. }) => Ok(true),

                // Confidential + Anything = Anything
                (OwnedState::Confidential { .. }, _) => {
                    match other {
                        OwnedState::ConfidentialSeal {
                            seal_definition,
                            assigned_state,
                        } => {
                            *self = OwnedState::ConfidentialSeal {
                                seal_definition: seal_definition.clone(),
                                assigned_state: assigned_state.clone(),
                            };
                            Ok(true)
                        }

                        OwnedState::ConfidentialAmount {
                            seal_definition,
                            assigned_state,
                        } => {
                            *self = OwnedState::ConfidentialAmount {
                                seal_definition: seal_definition.clone(),
                                assigned_state: assigned_state.clone(),
                            };
                            Ok(true)
                        }

                        // Other patterns are covered already. Should not reach
                        // here
                        _ => unreachable!(),
                    }
                }
            }
        }
    }
}

impl MergeRevealed for Assignments {
    fn merge_revealed(&mut self, other: &Self) -> Result<bool, String> {
        // Better ways to do this?
        if self.consensus_commitments() != other.consensus_commitments() {
            Err(s!("Assignments data mismatch in merge operation"))
        } else {
            match (self, other) {
                (
                    Assignments::Declarative(first_vec),
                    Assignments::Declarative(second_vec),
                ) => {
                    for (first, second) in
                        first_vec.iter_mut().zip(second_vec.iter())
                    {
                        first.merge_revealed(second)?;
                    }
                    Ok(true)
                }

                (
                    Assignments::DiscreteFiniteField(first_vec),
                    Assignments::DiscreteFiniteField(second_vec),
                ) => {
                    for (first, second) in
                        first_vec.iter_mut().zip(second_vec.iter())
                    {
                        first.merge_revealed(second)?;
                    }
                    Ok(true)
                }

                (
                    Assignments::CustomData(first_vec),
                    Assignments::CustomData(second_vec),
                ) => {
                    for (first, second) in
                        first_vec.iter_mut().zip(second_vec.iter())
                    {
                        first.merge_revealed(second)?;
                    }
                    Ok(true)
                }
                // No other patterns possible, should not reach here
                _ => unreachable!(),
            }
        }
    }
}

impl MergeRevealed for Genesis {
    fn merge_revealed(&mut self, other: &Self) -> Result<bool, String> {
        if self.consensus_commit() != other.consensus_commit() {
            Err(s!("Genesis node missmatch in merged operation"))
        } else {
            self.owned_rights_mut()
                .merge_revealed(other.owned_rights())?;
            Ok(true)
        }
    }
}

impl MergeRevealed for Transition {
    fn merge_revealed(&mut self, other: &Self) -> Result<bool, String> {
        if self.consensus_commit() != other.consensus_commit() {
            Err(s!("Genesis node missmatch in merged operation"))
        } else {
            self.owned_rights_mut()
                .merge_revealed(other.owned_rights())?;
            Ok(true)
        }
    }
}

impl MergeRevealed for Extension {
    fn merge_revealed(&mut self, other: &Self) -> Result<bool, String> {
        if self.consensus_commit() != other.consensus_commit() {
            Err(s!("Genesis node missmatch in merged operation"))
        } else {
            self.owned_rights_mut()
                .merge_revealed(other.owned_rights())?;
            Ok(true)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::contract::{ConcealState, OwnedRights};
    use crate::stash::MergeRevealed;
    use crate::strict_encoding::StrictDecode;
    use crate::{HashStrategy, PedersenStrategy};

    // Hard coded test vectors of Assignment Variants
    // Each Variant contains 4 types of Assignments
    // [Revealed, Confidential, ConfidentialSeal, ConfidentialState]
    static HASH_VARIANT: [u8; 267] = include!("../../test/hash_state.in");

    static PEDERSAN_VARIANT: [u8; 1664] =
        include!("../../test/pedersan_state.in");

    #[test]
    fn test_merge_revealed_state() {
        let ass = Assignments::strict_decode(&PEDERSAN_VARIANT[..])
            .unwrap()
            .into_discrete_state();

        let rev = ass[1].clone();

        // Check Revealed + Anything = Revealed

        // Revealed + Revealed = Revealed
        let mut merged = rev.clone();
        assert_eq!(merged.merge_revealed(&rev).unwrap(), true);
        assert_eq!(merged.seal_definition(), rev.seal_definition());
        assert_eq!(merged.assigned_state(), rev.assigned_state());

        // Revealed + Confidential = Revealed
        let conf = rev.commit_conceal();
        assert_eq!(merged.merge_revealed(&conf).unwrap(), true);
        assert_eq!(merged.seal_definition(), rev.seal_definition());
        assert_eq!(merged.assigned_state(), rev.assigned_state());

        // Revealed + Confidential State = Revealed
        let mut conf_state = rev.clone();
        conf_state.conceal_state();
        assert_eq!(merged.merge_revealed(&conf_state).unwrap(), true);
        assert_eq!(merged.seal_definition(), rev.seal_definition());
        assert_eq!(merged.assigned_state(), rev.assigned_state());

        // Revealed + Confidential Seal = Revealed
        let seal = rev.seal_definition_confidential();
        let conf_seal = OwnedState::<PedersenStrategy>::ConfidentialSeal {
            seal_definition: seal,
            assigned_state: rev.assigned_state().unwrap().clone(),
        };
        assert_eq!(merged.merge_revealed(&conf_seal).unwrap(), true);
        assert_eq!(merged.seal_definition(), rev.seal_definition());
        assert_eq!(merged.assigned_state(), rev.assigned_state());

        // Check Confidential Seal + Condfidential State = Revealed
        merged = conf_seal.clone();
        assert_eq!(merged.merge_revealed(&conf_state).unwrap(), true);
        assert_eq!(merged.seal_definition(), rev.seal_definition());
        assert_eq!(merged.assigned_state(), rev.assigned_state());

        // Check Condifential State + Confidential Seal = Revealed
        merged = conf_state.clone();
        assert_eq!(merged.merge_revealed(&conf_seal).unwrap(), true);
        assert_eq!(merged.seal_definition(), rev.seal_definition());
        assert_eq!(merged.assigned_state(), rev.assigned_state());

        // Check Confidential + Anything = Anything

        // Confidential + Reveal = Reveal
        merged = conf.clone();
        assert_eq!(merged.merge_revealed(&rev).unwrap(), true);
        assert_eq!(merged.seal_definition(), rev.seal_definition());
        assert_eq!(merged.assigned_state(), rev.assigned_state());

        // Confidential + Confidential Seal = Confidential Seal
        merged = conf.clone();
        assert_eq!(merged.merge_revealed(&conf_seal).unwrap(), true);
        assert_eq!(merged.seal_definition(), conf.seal_definition());
        assert_eq!(merged.assigned_state(), conf_seal.assigned_state());

        // Confidential + Confidential State = Confidential State
        merged = conf.clone();
        assert_eq!(merged.merge_revealed(&conf_state).unwrap(), true);
        assert_eq!(merged.seal_definition(), conf_state.seal_definition());
        assert_eq!(merged.assigned_state(), conf_state.assigned_state());

        // Confidential + Confidential = Confidential
        merged = conf.clone();
        assert_eq!(merged.merge_revealed(&conf).unwrap(), true);
        assert_eq!(merged.seal_definition(), conf.seal_definition());
        assert_eq!(merged.assigned_state(), conf.assigned_state());
    }

    #[test]
    fn test_merge_revealed_assignements_ownedstates() {
        let assignment = Assignments::strict_decode(&HASH_VARIANT[..])
            .unwrap()
            .to_custom_state();

        // Get a revealed state
        let rev = assignment[3].clone();

        // Compute different exposure of the same state
        let conf = rev.clone().commit_conceal();

        let seal = rev.seal_definition_confidential();

        let conf_seal = OwnedState::<HashStrategy>::ConfidentialSeal {
            seal_definition: seal,
            assigned_state: rev.assigned_state().unwrap().clone(),
        };

        let mut conf_state = rev.clone();
        conf_state.conceal_state();

        // Create assignment for testing
        let test_variant_1 =
            vec![rev.clone(), conf_seal, conf_state, conf.clone()];
        let mut assignment_1 = Assignments::CustomData(test_variant_1.clone());

        // Create assignment 2 for testing
        // which is reverse of assignment 1
        let mut test_variant_2 = test_variant_1.clone();
        test_variant_2.reverse();
        let assignmnet_2 = Assignments::CustomData(test_variant_2);

        // Performing merge revelaing
        assert_eq!(assignment_1.merge_revealed(&assignmnet_2).unwrap(), true);

        // After merging all the states expeected be revealed
        for state in assignment_1.to_custom_state() {
            assert_eq!(state, rev);
        }

        // Test against confidential merging
        // Confidential + Anything = Anything
        let test_variant_3 =
            vec![conf.clone(), conf.clone(), conf.clone(), conf.clone()];
        let mut assignment_3 = Assignments::CustomData(test_variant_3);

        // merge with assignment 1
        assert_eq!(assignment_3.merge_revealed(&assignment_1).unwrap(), true);

        assert_eq!(assignment_1, assignment_3);

        // test for OwnedRights structure
        let test_owned_rights_1: OwnedRights =
            bmap! { 1usize => assignment_1.clone()};
        let mut test_owned_rights_2: OwnedRights =
            bmap! { 1usize => assignmnet_2.clone()};

        // Perform merge
        assert_eq!(
            test_owned_rights_2
                .merge_revealed(&test_owned_rights_1)
                .unwrap(),
            true
        );

        // after merge operation all the states will be revealed
        let states = vec![rev.clone(), rev.clone(), rev.clone(), rev.clone()];
        let assgn = Assignments::CustomData(states);
        let expected_rights: OwnedRights = bmap! {1usize => assgn};

        assert_eq!(test_owned_rights_2, expected_rights);
    }
}

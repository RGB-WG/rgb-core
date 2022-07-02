// RGB Core Library: a reference implementation of RGB smart contract standards.
// Written in 2019-2022 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the MIT License along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

use std::collections::BTreeMap;

use amplify::Wrapper;
use bp::dbc;
use commit_verify::{CommitConceal, CommitEncode, ToMerkleSource};

use super::OwnedRightsInner;
use crate::schema::NodeType;
use crate::{Assignment, OwnedRights, State, TypedAssignments};

/// Merge Error generated in merging operation
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, From, Error)]
#[display(doc_comments)]
pub enum Error {
    /// Owned State has different commitment ids and can't be reveal-merged
    OwnedStateMismatch,

    /// Assignment has different commitment ids and can't be reveal-merged
    AssignmentMismatch,

    /// OwnedRights has different commitment ids and can't be reveal-merged
    OwnedRightsMismatch,

    /// Anchors has different commitment ids and can't be reveal-merged. Details: {0}
    #[from]
    AnchorsMismatch(dbc::anchor::MergeError),

    /// Node of type {0} has different commitment ids and can't be
    /// reveal-merged
    NodeMismatch(NodeType),
}

/// A trait to merge two structures modifying the revealed status
/// of the first one. The merge operation will **consume** both the structures
/// and return a new structure with revealed states.
///
/// The resulting structure will depend on the reveal status of both of the
/// variant. And the most revealed condition among the two will be selected
/// Usage: prevent hiding already known previous state data by merging
/// incoming new consignment in stash.
///
/// The follwoing conversion logic is intended by this trait:
///
/// merge(Revealed, Anything) => Revealed
/// merge(ConfidentialSeal, ConfidentialAmount) => Revealed
/// merge(ConfidentialAmount, ConfidentialSeal) => Revealed
/// merge(Confidential, Anything) => Anything
pub trait MergeReveal: Sized {
    fn merge_reveal(self, other: Self) -> Result<Self, Error>;
}

impl<STATE> MergeReveal for Assignment<STATE>
where
    Self: Clone,
    STATE: State,
    STATE::Confidential: PartialEq + Eq,
    STATE::Confidential: From<<STATE::Revealed as CommitConceal>::ConcealedCommitment>,
{
    fn merge_reveal(self, other: Self) -> Result<Self, Error> {
        // if self and other is different through error
        if self.commit_serialize() != other.commit_serialize() {
            Err(Error::OwnedStateMismatch)
        } else {
            match (self, other) {
                // Anything + Revealed = Revealed
                (_, state @ Assignment::Revealed { .. })
                | (state @ Assignment::Revealed { .. }, _) => Ok(state),

                // ConfidentialAmount + ConfidentialSeal = Revealed
                (
                    Assignment::ConfidentialSeal { state, .. },
                    Assignment::ConfidentialState { seal, .. },
                ) => Ok(Assignment::Revealed { seal, state }),

                // ConfidentialSeal + ConfidentialAmount = Revealed
                (
                    Assignment::ConfidentialState { seal, .. },
                    Assignment::ConfidentialSeal { state, .. },
                ) => Ok(Assignment::Revealed { seal, state }),

                // if self and other is of same variant return self
                (
                    state @ Assignment::ConfidentialState { .. },
                    Assignment::ConfidentialState { .. },
                ) => Ok(state),
                (
                    state @ Assignment::ConfidentialSeal { .. },
                    Assignment::ConfidentialSeal { .. },
                ) => Ok(state),

                // Anything + Confidential = Anything
                (state, Assignment::Confidential { .. })
                | (Assignment::Confidential { .. }, state) => Ok(state),
            }
        }
    }
}

impl MergeReveal for TypedAssignments {
    fn merge_reveal(self, other: Self) -> Result<Self, Error> {
        if self.consensus_commitments() != other.consensus_commitments() {
            Err(Error::AssignmentMismatch)
        } else {
            match (self, other) {
                (TypedAssignments::Void(first_vec), TypedAssignments::Void(second_vec)) => {
                    let mut result = Vec::with_capacity(first_vec.len());
                    for (first, second) in first_vec.into_iter().zip(second_vec.into_iter()) {
                        result.push(first.merge_reveal(second)?);
                    }
                    Ok(TypedAssignments::Void(result))
                }

                (TypedAssignments::Value(first_vec), TypedAssignments::Value(second_vec)) => {
                    let mut result = Vec::with_capacity(first_vec.len());
                    for (first, second) in first_vec.into_iter().zip(second_vec.into_iter()) {
                        result.push(first.merge_reveal(second)?);
                    }
                    Ok(TypedAssignments::Value(result))
                }

                (TypedAssignments::Data(first_vec), TypedAssignments::Data(second_vec)) => {
                    let mut result = Vec::with_capacity(first_vec.len());
                    for (first, second) in first_vec.into_iter().zip(second_vec.into_iter()) {
                        result.push(first.merge_reveal(second)?);
                    }
                    Ok(TypedAssignments::Data(result))
                }
                // No other patterns possible, should not reach here
                _ => {
                    unreachable!("Assignments::consensus_commitments is broken")
                }
            }
        }
    }
}

impl MergeReveal for OwnedRights {
    fn merge_reveal(self, other: Self) -> Result<Self, Error> {
        if self.to_merkle_source().commit_serialize() != other.to_merkle_source().commit_serialize()
        {
            return Err(Error::OwnedRightsMismatch);
        }
        let mut result: OwnedRightsInner = BTreeMap::new();
        for (first, second) in self
            .into_inner()
            .into_iter()
            .zip(other.into_inner().into_iter())
        {
            result.insert(first.0, first.1.merge_reveal(second.1)?);
        }
        Ok(OwnedRights::from_inner(result))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::strict_encoding::StrictDecode;
    use crate::{ConcealState, HashStrategy, PedersenStrategy};

    // Hard coded test vectors of Assignment Variants
    // Each Variant contains 4 types of Assignments
    // [Revealed, Confidential, ConfidentialSeal, ConfidentialState]
    static HASH_VARIANT: [u8; 267] = include!("../../test/hash_state.in");

    static PEDERSAN_VARIANT: [u8; 1664] = include!("../../test/pedersan_state.in");

    #[test]
    #[ignore]
    fn test_into_revealed_state() {
        let ass = TypedAssignments::strict_decode(&PEDERSAN_VARIANT[..])
            .unwrap()
            .into_value_assignments();

        let rev = ass[1].clone();

        // Check Revealed + Anything = Revealed

        // Revealed + Revealed = Revealed
        let mut merged = rev.clone().merge_reveal(rev.clone()).unwrap();
        assert_eq!(merged, rev);

        // Revealed + Confidential = Revealed
        let conf = rev.commit_conceal();
        merged = rev.clone().merge_reveal(conf.clone()).unwrap();
        assert_eq!(merged, rev);

        // Revealed + Confidential State = Revealed
        let mut conf_state = rev.clone();
        conf_state.conceal_state();
        merged = rev.clone().merge_reveal(conf_state.clone()).unwrap();
        assert_eq!(merged, rev);

        // Revealed + Confidential Seal = Revealed
        let seal = rev.to_confidential_seal();
        let conf_seal = Assignment::<PedersenStrategy>::ConfidentialSeal {
            seal,
            state: rev.as_revealed_state().unwrap().clone(),
        };
        merged = rev.clone().merge_reveal(conf_seal.clone()).unwrap();
        assert_eq!(merged, rev);

        // Check Confidential Seal + Condfidential State = Revealed
        merged = conf_seal.clone().merge_reveal(conf_state.clone()).unwrap();
        assert_eq!(merged, rev);

        // Check Condifential State + Confidential Seal = Revealed
        merged = conf_state.clone().merge_reveal(conf_seal.clone()).unwrap();
        assert_eq!(merged, rev);

        // Check Confidential + Anything = Anything
        // Confidential + Reveal = Reveal
        merged = conf.clone().merge_reveal(rev.clone()).unwrap();
        assert_eq!(merged, rev);

        // Confidential + Confidential Seal = Confidential Seal
        merged = conf.clone().merge_reveal(conf_seal.clone()).unwrap();
        assert_eq!(merged, conf_seal);

        // Confidential + Confidential State = Confidential State
        merged = conf.clone().merge_reveal(conf_state.clone()).unwrap();
        assert_eq!(merged, conf_state);

        // Confidential + Confidential = Confidential
        merged = conf.clone().merge_reveal(conf.clone()).unwrap();
        assert_eq!(merged, conf);
    }

    #[test]
    #[ignore]
    fn test_into_revealed_assignements_ownedstates() {
        let assignment = TypedAssignments::strict_decode(&HASH_VARIANT[..])
            .unwrap()
            .to_data_assignments();

        // Get a revealed state
        let rev = assignment[3].clone();

        // Compute different exposure of the same state
        let conf = rev.clone().commit_conceal();

        let seal = rev.to_confidential_seal();

        let conf_seal = Assignment::<HashStrategy>::ConfidentialSeal {
            seal,
            state: rev.as_revealed_state().unwrap().clone(),
        };

        let mut conf_state = rev.clone();
        conf_state.conceal_state();

        // Create assignment for testing
        let test_variant_1 = vec![rev.clone(), conf_seal, conf_state, conf.clone()];
        let assignment_1 = TypedAssignments::Data(test_variant_1.clone());

        // Create assignment 2 for testing
        // which is reverse of assignment 1
        let mut test_variant_2 = test_variant_1.clone();
        test_variant_2.reverse();
        let assignmnet_2 = TypedAssignments::Data(test_variant_2);

        // Performing merge revelaing
        let merged = assignment_1
            .clone()
            .merge_reveal(assignmnet_2.clone())
            .unwrap();

        // After merging all the states expeected be revealed
        for state in merged.to_data_assignments() {
            assert_eq!(state, rev);
        }

        // Test against confidential merging
        // Confidential + Anything = Anything
        let test_variant_3 = vec![conf.clone(), conf.clone(), conf.clone(), conf.clone()];
        let assignment_3 = TypedAssignments::Data(test_variant_3);

        // merge with assignment 1
        let merged = assignment_3
            .clone()
            .merge_reveal(assignment_1.clone())
            .unwrap();

        assert_eq!(assignment_1, merged);

        // test for OwnedRights structure
        let test_owned_rights_1: OwnedRights = bmap! { 1u16 => assignment_1.clone() }.into();
        let test_owned_rights_2: OwnedRights = bmap! { 1u16 => assignmnet_2.clone()}.into();

        // Perform merge
        let merged = test_owned_rights_1
            .clone()
            .merge_reveal(test_owned_rights_2.clone())
            .unwrap();

        // after merge operation all the states will be revealed
        let states = vec![rev.clone(), rev.clone(), rev.clone(), rev.clone()];
        let assgn = TypedAssignments::Data(states);
        let expected_rights: OwnedRights = bmap! {1u16 => assgn}.into();

        assert_eq!(merged, expected_rights);
    }
}

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

use std::collections::{btree_map, BTreeMap, BTreeSet};
use std::io::Write;

use bitcoin::hashes::{sha256, sha256t, Hash};
use commit_verify::{
    lnpbp4, CommitEncode, CommitVerify, ConsensusCommit, PrehashedProtocol, TaggedHash,
};
use strict_encoding::StrictEncode;

use crate::{Node, NodeId, Transition};

// "rgb:bundle"
static MIDSTATE_BUNDLE_ID: [u8; 32] = [
    219, 42, 125, 118, 252, 62, 163, 226, 43, 104, 76, 97, 218, 62, 92, 108, 200, 133, 207, 235,
    35, 72, 210, 0, 122, 143, 80, 88, 238, 145, 95, 89,
];

/// Tag used for [`BundleId`] hash type
pub struct BundleIdTag;

impl sha256t::Tag for BundleIdTag {
    #[inline]
    fn engine() -> sha256::HashEngine {
        let midstate = sha256::Midstate::from_inner(MIDSTATE_BUNDLE_ID);
        sha256::HashEngine::from_midstate(midstate, 64)
    }
}

/// Unique state transition bundle identifier equivalent to the bundle commitment hash
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[derive(Wrapper, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, From)]
#[derive(StrictEncode, StrictDecode)]
#[wrapper(Debug, Display)]
pub struct BundleId(sha256t::Hash<BundleIdTag>);

impl<Msg> CommitVerify<Msg, PrehashedProtocol> for BundleId
where Msg: AsRef<[u8]>
{
    #[inline]
    fn commit(msg: &Msg) -> BundleId { BundleId::hash(msg) }
}

pub trait ConcealTransitions {
    fn conceal_transitions(&mut self) -> usize { self.conceal_transitions_except(&[]) }
    fn conceal_transitions_except(&mut self, node_ids: &[NodeId]) -> usize;
}

impl From<BundleId> for lnpbp4::Message {
    fn from(id: BundleId) -> Self { lnpbp4::Message::from_inner(id.into_inner()) }
}

impl From<lnpbp4::Message> for BundleId {
    fn from(id: lnpbp4::Message) -> Self { BundleId(sha256t::Hash::from_inner(id.into_inner())) }
}

#[derive(Clone, PartialEq, Eq, Debug, Default, AsAny)]
#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct TransitionBundle {
    revealed: BTreeMap<Transition, BTreeSet<u16>>,
    concealed: BTreeMap<NodeId, BTreeSet<u16>>,
}

impl CommitEncode for TransitionBundle {
    fn commit_encode<E: Write>(&self, mut e: E) -> usize {
        let mut concealed = self.clone();
        concealed.conceal_transitions();

        let mut count = 0usize;
        for (node_id, inputs) in concealed.concealed {
            count += node_id
                .strict_encode(&mut e)
                .expect("memory encoders do not fail");
            count += inputs
                .strict_encode(&mut e)
                .expect("memory encoders do not fail");
        }
        count
    }
}

impl ConsensusCommit for TransitionBundle {
    type Commitment = BundleId;
}

impl ConcealTransitions for TransitionBundle {
    fn conceal_transitions_except(&mut self, node_ids: &[NodeId]) -> usize {
        let mut concealed = bmap! {};
        self.revealed = self
            .revealed
            .iter()
            .filter_map(|(transition, inputs)| {
                let node_id = transition.node_id();
                if !node_ids.contains(&node_id) {
                    concealed.insert(node_id, inputs.clone());
                    None
                } else {
                    Some((transition.clone(), inputs.clone()))
                }
            })
            .collect();
        let count = concealed.len();
        self.concealed.extend(concealed);
        count
    }
}

impl From<BTreeMap<Transition, BTreeSet<u16>>> for TransitionBundle {
    fn from(revealed: BTreeMap<Transition, BTreeSet<u16>>) -> Self {
        TransitionBundle {
            revealed,
            concealed: empty!(),
        }
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum RevealError {
    /// the provided input set is invalid, since bundle is invalidated by after the reveal operation
    InvalidInputSet,
    /// the provided input set is invalid, not matching input set which is already known
    InputsNotMatch,
    /// the provided state transition is not a part of the bundle
    UnrelatedTransition,
}

impl TransitionBundle {
    pub fn len(&self) -> usize { self.concealed.len() + self.revealed.len() }

    pub fn bundle_id(&self) -> BundleId { self.consensus_commit() }

    pub fn node_ids(&self) -> BTreeSet<NodeId> {
        self.concealed
            .keys()
            .copied()
            .chain(self.revealed.keys().map(Transition::node_id))
            .collect()
    }

    pub fn contains_id(&self, node_id: NodeId) -> bool {
        self.is_concealed(node_id) || self.is_revealed(node_id)
    }

    pub fn inputs_for(&self, node_id: NodeId) -> Option<&BTreeSet<u16>> {
        self.revealed
            .iter()
            .find_map(|(ts, inputs)| if ts.node_id() == node_id { Some(inputs) } else { None })
            .or_else(|| self.concealed.get(&node_id))
    }

    pub fn is_revealed(&self, node_id: NodeId) -> bool {
        self.revealed.keys().any(|ts| ts.node_id() == node_id)
    }

    pub fn is_concealed(&self, node_id: NodeId) -> bool { self.concealed.contains_key(&node_id) }

    pub fn reveal_transition(
        &mut self,
        transition: Transition,
        inputs: BTreeSet<u16>,
    ) -> Result<bool, RevealError> {
        let id = transition.node_id();
        if self.concealed.contains_key(&id) {
            let bundle_id = self.bundle_id();
            let mut clone = self.clone();
            clone.concealed.remove(&id);
            clone.revealed.insert(transition, inputs);
            if clone.bundle_id() != bundle_id {
                Err(RevealError::InvalidInputSet)
            } else if !clone.validate() {
                Err(RevealError::InvalidInputSet)
            } else {
                *self = clone;
                Ok(true)
            }
        } else if let Some(existing_inputs) = self.revealed.get(&transition) {
            if existing_inputs != &inputs {
                Err(RevealError::InputsNotMatch)
            } else {
                Ok(false)
            }
        } else {
            Err(RevealError::UnrelatedTransition)
        }
    }

    pub fn revealed_iter(&self) -> btree_map::Iter<Transition, BTreeSet<u16>> {
        self.revealed.iter()
    }

    pub fn into_revealed_iter(self) -> btree_map::IntoIter<Transition, BTreeSet<u16>> {
        self.revealed.into_iter()
    }

    pub fn concealed_iter(&self) -> btree_map::Iter<NodeId, BTreeSet<u16>> { self.concealed.iter() }

    pub fn into_concealed_iter(self) -> btree_map::IntoIter<NodeId, BTreeSet<u16>> {
        self.concealed.into_iter()
    }

    pub fn known_transitions(&self) -> btree_map::Keys<Transition, BTreeSet<u16>> {
        self.revealed.keys()
    }

    pub fn known_node_ids(&self) -> BTreeSet<NodeId> {
        self.known_transitions().map(Transition::node_id).collect()
    }
}

impl TransitionBundle {
    pub fn validate(&self) -> bool {
        let mut used_inputs = bset! {};
        for set in self.revealed.values() {
            if used_inputs.intersection(set).count() > 0 {
                return false;
            }
            used_inputs.extend(set);
        }
        for set in self.concealed.values() {
            if used_inputs.intersection(set).count() > 0 {
                return false;
            }
            used_inputs.extend(set);
        }
        true
    }
}

#[cfg(test)]
mod test {
    use amplify::Wrapper;
    use commit_verify::tagged_hash;

    use super::*;

    #[test]
    fn test_bundle_id_midstate() {
        let midstate = tagged_hash::Midstate::with(b"rgb:bundle");
        assert_eq!(midstate.into_inner().into_inner(), MIDSTATE_BUNDLE_ID);
    }
}

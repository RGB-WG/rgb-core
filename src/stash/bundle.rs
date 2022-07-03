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
use std::io::{Read, Write};

use bitcoin::hashes::{sha256, sha256t, Hash};
use commit_verify::{
    lnpbp4, CommitEncode, CommitVerify, ConsensusCommit, PrehashedProtocol, TaggedHash,
};
use strict_encoding::{StrictDecode, StrictEncode};

use crate::{seal, ConcealSeals, Node, NodeId, RevealSeals, Transition};

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

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum RevealError {
    /// the provided state transition is not a part of the bundle
    UnrelatedTransition,
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display("attempt to construct transition bundle with no transitions given")]
pub struct NoDataError;

#[derive(Clone, PartialEq, Eq, Debug, Default, AsAny)]
#[derive(StrictEncode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct TransitionBundle {
    revealed: BTreeMap<Transition, BTreeSet<u16>>,
    concealed: BTreeMap<NodeId, BTreeSet<u16>>,
}

impl StrictDecode for TransitionBundle {
    fn strict_decode<D: Read>(mut d: D) -> Result<Self, strict_encoding::Error> {
        let bundle = strict_decode_self!(d; revealed, concealed);
        if bundle.revealed.is_empty() && bundle.concealed.is_empty() {
            return Err(strict_encoding::Error::DataIntegrityError(s!(
                "transition bundle without any transitions"
            )));
        }
        Ok(bundle)
    }
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

impl ConcealSeals for TransitionBundle {
    fn conceal_seals(&mut self, seals: &[seal::Confidential]) -> usize {
        let mut counter = 0;
        self.revealed = self
            .revealed_iter()
            .map(|(transition, inputs)| {
                let mut transition = transition.clone();
                counter += transition.conceal_seals(seals);
                (transition, inputs.clone())
            })
            .collect::<BTreeMap<_, _>>();
        counter
    }
}

impl RevealSeals for TransitionBundle {
    fn reveal_seals(&mut self, known_seals: &[seal::Revealed]) -> usize {
        let mut counter = 0;
        self.revealed = self
            .revealed_iter()
            .map(|(transition, inputs)| {
                let mut transition = transition.clone();
                for (_, assignment) in transition.owned_rights_mut().iter_mut() {
                    counter += assignment.reveal_seals(known_seals);
                }
                (transition, inputs.clone())
            })
            .collect::<BTreeMap<_, _>>();
        counter
    }
}

impl TryFrom<BTreeMap<Transition, BTreeSet<u16>>> for TransitionBundle {
    type Error = NoDataError;

    fn try_from(revealed: BTreeMap<Transition, BTreeSet<u16>>) -> Result<Self, Self::Error> {
        if revealed.is_empty() {
            return Err(NoDataError);
        }
        Ok(TransitionBundle {
            revealed,
            concealed: empty!(),
        })
    }
}

impl TryFrom<BTreeMap<NodeId, BTreeSet<u16>>> for TransitionBundle {
    type Error = NoDataError;
    fn try_from(concealed: BTreeMap<NodeId, BTreeSet<u16>>) -> Result<Self, Self::Error> {
        if concealed.is_empty() {
            return Err(NoDataError);
        }
        Ok(TransitionBundle {
            revealed: empty!(),
            concealed,
        })
    }
}

impl TransitionBundle {
    pub fn with(
        revealed: BTreeMap<Transition, BTreeSet<u16>>,
        concealed: BTreeMap<NodeId, BTreeSet<u16>>,
    ) -> Result<TransitionBundle, NoDataError> {
        if revealed.is_empty() && concealed.is_empty() {
            return Err(NoDataError);
        }
        Ok(TransitionBundle {
            revealed,
            concealed,
        })
    }

    #[allow(clippy::len_without_is_empty)]
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

    pub fn reveal_transition(&mut self, transition: Transition) -> Result<bool, RevealError> {
        let id = transition.node_id();
        if let Some(inputs) = self.concealed.remove(&id) {
            self.revealed.insert(transition, inputs);
            Ok(true)
        } else if self.revealed.contains_key(&transition) {
            Ok(false)
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

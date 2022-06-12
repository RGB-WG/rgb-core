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

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

use bitcoin_hashes::{sha256, sha256t};
use commit_verify::{CommitEncode, CommitVerify, ConsensusCommit, PrehashedProtocol, TaggedHash};
use strict_encoding::StrictEncode;

use crate::{Node, NodeId, Transition};

// TODO: Update the value
// "rgb:bundle"
static MIDSTATE_BUNDLE_ID: [u8; 32] = [
    148, 72, 59, 59, 150, 173, 163, 140, 159, 237, 69, 118, 104, 132, 194, 110, 250, 108, 1, 140,
    74, 248, 152, 205, 70, 32, 184, 87, 20, 102, 127, 20,
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
    fn conceal_transitions(&mut self) -> usize { self.conceal_transitions_except(&vec![]) }
    fn conceal_transitions_except(&mut self, node_ids: &[NodeId]) -> usize;
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

impl<'me> IntoIterator for &'me TransitionBundle {
    type Item = (&'me Transition, &'me BTreeSet<u16>);
    type IntoIter = std::collections::btree_map::Iter<'me, Transition, BTreeSet<u16>>;

    fn into_iter(self) -> Self::IntoIter { self.revealed.iter() }
}

impl TransitionBundle {
    pub fn bundle_id(&self) -> BundleId { self.consensus_commit() }

    pub fn transitions(&self) -> std::collections::btree_map::Keys<Transition, BTreeSet<u16>> {
        self.revealed.keys()
    }

    pub fn revealed_node_ids(&self) -> BTreeSet<NodeId> {
        self.transitions().map(Transition::node_id).collect()
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

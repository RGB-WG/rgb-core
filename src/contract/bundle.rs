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

use bitcoin_hashes::{sha256, sha256t};
use commit_verify::{CommitVerify, PrehashedProtocol, TaggedHash};

use crate::Transition;

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
#[wrapper(Debug, Display, LowerHex, Index, IndexRange, IndexFrom, IndexTo, IndexFull)]
pub struct BundleId(sha256t::Hash<BundleIdTag>);

impl<Msg> CommitVerify<Msg, PrehashedProtocol> for BundleId
where Msg: AsRef<[u8]>
{
    #[inline]
    fn commit(msg: &Msg) -> BundleId { BundleId::hash(msg) }
}

impl strict_encoding::Strategy for BundleId {
    type Strategy = strict_encoding::strategies::Wrapped;
}

#[derive(Clone, PartialEq, Eq, Debug, Default, AsAny)]
#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct TransitionBundle(BTreeMap<Transition, BTreeSet<u16>>);

impl<'me> IntoIterator for &'me TransitionBundle {
    type Item = (&'me Transition, &'me BTreeSet<u16>);
    type IntoIter = std::collections::btree_map::Iter<'me, Transition, BTreeSet<u16>>;

    fn into_iter(self) -> Self::IntoIter { self.0.iter() }
}

impl TransitionBundle {
    pub fn transitions(&self) -> std::collections::btree_map::Keys<Transition, BTreeSet<u16>> {
        self.0.keys()
    }
}

impl TransitionBundle {
    pub fn validate(&self) -> bool {
        let mut used_inputs = bset! {};
        for set in self.0.values() {
            if used_inputs.intersection(set).count() > 0 {
                return false;
            }
            used_inputs.extend(set);
        }
        true
    }
}

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


use std::convert::From;

use bitcoin::hashes::{Hash, sha256, sha256t};

use crate::{bp, cmt, csv, rgb};


/// Midstate for RGB state commitment. Corresponds to "RGB:state:1" tag with
/// `23fadcc399c645274f9c884ff997f88168d6fe5739593114bb3e3851d3ed3406` hex value
const MIDSTATE_STATE: [u8; 32] = [
    35, 250, 220, 195, 153, 198, 69, 39, 79, 156, 136, 79, 249, 151, 248, 129, 104, 214, 254, 87,
    57, 89, 49, 20, 187, 62, 56, 81, 211, 237, 52, 6
];

/// Midstate for RGB metadata commitment. Corresponds to "RGB:metadata:1" tag with
/// `54d45bb78e754cec5cf6efb5bcb82a4ac1cf983c973a49e637e3811ebf6bddd0` hex value
const MIDSTATE_METADATA: [u8; 32] = [
    84, 212, 91, 183, 142, 117, 76, 236, 92, 246, 239, 181, 188, 184, 42, 74, 193, 207, 152, 60,
    151, 58, 73, 230, 55, 227, 129, 30, 191, 107, 221, 208
];

/// Midstate for RGB script commitment. Corresponds to "RGB:script:1" tag with
/// `fc546dcca351ba6fe7192795a9a2c788718a7fffaa87c9e562ebb50337d87597` hex value
const MIDSTATE_SCRIPT: [u8; 32] = [
    252, 84, 109, 204, 163, 81, 186, 111, 231, 25, 39, 149, 169, 162, 199, 136, 113, 138, 127, 255,
    170, 135, 201, 229, 98, 235, 181, 3, 55, 216, 117, 151
];

/// Midstate for RGB state transition commitment. Corresponds to "RGB:transition:1" tag with
/// `aed0c0d9e0983c5b619511e0ae76283eed9af37f0f547b8c126a4626da057eed` hex value
const MIDSTATE_TRANSITION: [u8; 32] = [
    174, 208, 192, 217, 224, 152, 60, 91, 97, 149, 17, 224, 174, 118, 40, 62, 237, 154, 243, 127,
    15, 84, 123, 140, 18, 106, 70, 38, 218, 5, 126, 237
];

tagged_hash!(StateCommitment, StateTag, MIDSTATE_STATE, doc="");
tagged_hash!(MetadataCommitment, MetadataTag, MIDSTATE_METADATA, doc="");
tagged_hash!(ScriptCommitment, ScriptTag, MIDSTATE_SCRIPT, doc="");
tagged_hash!(TransitionCommitment, TransitionTag, MIDSTATE_TRANSITION, doc="");
// TODO: This should be `sha256d::Hash`, but this requires changes to rust-bitcoin
hash_newtype!(MetadataRootCommitment, sha256::Hash, 32, doc="MerkleNode corresponding to the metadata tree root");
hash_newtype!(StateRootCommitment, sha256::Hash, 32, doc="MerkleNode corresponding to the state tree root");

impl_hashencode!(StateCommitment);
impl_hashencode!(StateRootCommitment);
impl_hashencode!(MetadataCommitment);
impl_hashencode!(MetadataRootCommitment);
impl_hashencode!(ScriptCommitment);
impl_hashencode!(TransitionCommitment);

impl csv::serialize::FromConsensus for StateCommitment { }
impl csv::serialize::FromConsensus for StateRootCommitment { }
impl csv::serialize::FromConsensus for MetadataCommitment { }
impl csv::serialize::FromConsensus for MetadataRootCommitment { }
impl csv::serialize::FromConsensus for ScriptCommitment { }
impl csv::serialize::FromConsensus for TransitionCommitment { }


impl From<bp::MerkleNode> for StateRootCommitment {
    fn from(node: bp::MerkleNode) -> Self {
        Self::from_inner(node.into_inner())
    }
}
impl From<bp::MerkleNode> for MetadataRootCommitment {
    fn from(node: bp::MerkleNode) -> Self {
        Self::from_inner(node.into_inner())
    }
}


pub trait Identifiable: csv::Commitment {
    type HashId: cmt::StandaloneCommitment<Vec<u8>> + Hash;
    fn commitment(&self) -> Result<Self::HashId, csv::serialize::Error> {
        use cmt::Committable;
        Ok(csv::serialize::commitment_serialize(self)?.commit())
    }
}


impl Identifiable for rgb::metadata::Field {
    type HashId = MetadataCommitment;
}

impl Identifiable for rgb::Metadata {
    type HashId = MetadataRootCommitment;
}

impl Identifiable for rgb::state::Partial {
    type HashId = StateCommitment;
    fn commitment(&self) -> Result<Self::HashId, csv::serialize::Error> {
        match self {
            Self::Commitment(cmt) => Ok(*cmt),
            Self::State(state) => state.commitment(),
        }
    }
}

impl Identifiable for rgb::state::Bound {
    type HashId = StateCommitment;
}

impl Identifiable for rgb::State {
    type HashId = StateRootCommitment;
}

impl Identifiable for Option<rgb::Script> {
    type HashId = ScriptCommitment;
}

impl Identifiable for rgb::Transition {
    type HashId = TransitionCommitment;
}

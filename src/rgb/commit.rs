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

use bitcoin::hashes::{
    Hash,
    sha256, sha256d, sha256t,
    hex::{ToHex, FromHex}
};

use crate::{bp, csv, rgb, cmt::Committable};


/// Midstate for RGB state commitment. Corresponds to "RGB:state:1" tag with
/// `23fadcc399c645274f9c884ff997f88168d6fe5739593114bb3e3851d3ed3406` hex value
const MIDSTATE_STATECOMMITMENT: [u8; 32] = [
    35, 250, 220, 195, 153, 198, 69, 39, 79, 156, 136, 79, 249, 151, 248, 129, 104, 214, 254, 87,
    57, 89, 49, 20, 187, 62, 56, 81, 211, 237, 52, 6
];

tagged_hash!(StateCommitment, StateCommitmentTag, StateCommitment, MIDSTATE_STATECOMMITMENT);


hash_newtype!(StateRootCommitment, sha256d::Hash, 32, doc="MerkleNode corresponding to the state tree root");
impl_hashencode!(StateRootCommitment);
impl csv::serialize::FromConsensus for StateRootCommitment { }
impl From<bp::MerkleNode> for StateRootCommitment {
    fn from(node: bp::MerkleNode) -> Self {
        Self::from_inner(node.into_inner())
    }
}


impl rgb::state::Partial {
    pub fn state_commitment(&self) -> Result<StateCommitment, csv::serialize::Error> {
        match self {
            Self::Commitment(cmt) => Ok(*cmt),
            Self::State(state) => state.state_commitment(),
        }
    }
}


impl rgb::state::Bound {
    pub fn state_commitment(&self) -> Result<StateCommitment, csv::serialize::Error> {
        Ok(csv::serialize::commitment_serialize(self)?.commit())
    }
}


impl rgb::state::State {
    pub fn state_root_commitment(&self) -> Result<StateRootCommitment, csv::serialize::Error> {
        // TODO: Refactor using `try_fold` method
        let mut data: Vec<bp::MerkleNode> = vec![];
        self.as_ref().iter().try_for_each(|state| -> Result<(), csv::serialize::Error> {
            data.push(bp::MerkleNode::from_inner(state.state_commitment()?.into_inner()));
            Ok(())
        })?;
        Ok(bp::merklize("RGB:state:1", &data[..], 0).into())
    }
}

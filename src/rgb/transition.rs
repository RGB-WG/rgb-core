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


use bitcoin::hashes::{Hash, sha256t};

use super::{State, Metadata, Script};
use crate::csv::ConsensusCommit;
use crate::csv::serialize;

#[derive(Clone, PartialEq, Debug, Display)]
#[display_from(Debug)]
pub struct Transition {
    pub id: usize,
    pub meta: Metadata,
    pub state: State,
    pub script: Option<Script>,
}

impl Transition {
    pub fn transition_id(&self) -> Result<TransitionId, serialize::Error> {
        self.consensus_commit()
    }
}

// FIXME: change this, copied from SCHEMA_ID
static MIDSTATE_TRANSITION: [u8; 32] = [
    25, 205, 224, 91, 171, 217, 131, 31, 140, 104, 5, 155, 127, 82, 14, 81, 58, 245, 79, 165, 114,
    243, 110, 60, 133, 174, 103, 187, 103, 230, 9, 106
];

tagged_hash!(TransitionId, TransitionIdTag, MIDSTATE_TRANSITION, doc="");

impl ConsensusCommit for Transition {
    type CommitmentHash = TransitionId;
}



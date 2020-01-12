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

use std::collections::HashMap;

use bitcoin::hashes::{sha256, sha256t};

use super::{
    types::*,
    transition::*,
    super::{
        ConsensusCommit,
        serialize
    }
};


pub struct ValidationError {

}

pub struct Schema {
    pub seals: HashMap<usize, StateFormat>,
    pub transitions: Vec<Transition>,
}

impl Schema {
    pub fn schema_id(&self) -> SchemaId {
        self.consensus_commit()
    }

    pub fn validate(&self, ts: super::transition::Transition) -> Result<(), ValidationError> {
        unimplemented!()
    }
}

impl serialize::Commitment for Schema {
    fn commitment_serialize(&self) -> Vec<u8> {
        unimplemented!()
        /*
        let buf = self.seals.commitment_serialize();
        buf.extend(self.transitions.commitment_serialize())
        */
    }
}

impl serialize::Commitment for Transition {
    fn commitment_serialize(&self) -> Vec<u8> {
        unimplemented!()
        /*
        let buf = self.closes.commitment_serialize();
        buf.extend(self.fields.commitment_serialize());
        buf.extend(self.binds.commitment_serialize());
        buf.extend(self.scripts.commitment_serialize())
        */
    }
}

static MIDSTATE_SHEMAID: [u8; 32] = [
    25, 205, 224, 91, 171, 217, 131, 31, 140, 104, 5, 155, 127, 82, 14, 81, 58, 245, 79, 165, 114,
    243, 110, 60, 133, 174, 103, 187, 103, 230, 9, 106
];

tagged_hash!(SchemaId, SchemaIdTag, SchemaId, MIDSTATE_SHEMAID);

impl ConsensusCommit for Schema {
    type CommitmentHash = SchemaId;
}

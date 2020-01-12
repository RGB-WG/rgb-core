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


use std::io::Cursor;
use bitcoin::hashes::Hash;

use super::serialize;

pub trait ConsensusCommit: serialize::Commitment {
    type CommitmentHash: Hash;
    fn consensus_commit(&self) -> Result<Self::CommitmentHash, serialize::Error> {
        let mut encoder = Cursor::new(vec![]);
        self.commitment_serialize(&mut encoder)?;
        Ok(Self::CommitmentHash::hash(&encoder.into_inner()))
    }
}

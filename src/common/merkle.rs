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

use std::io;
use bitcoin::{
    consensus,
    hashes::hex::{ToHex, FromHex},
    hashes::{Hash, HashEngine, sha256, sha256d}
};
use crate::csv::Commitment;

hash_newtype!(MerkleNode, sha256d::Hash, 32, doc="A hash of a arbitrary Merkle tree branch or root");

impl consensus::Encodable for MerkleNode {
    fn consensus_encode<S: io::Write>(&self, s: S) -> Result<usize, consensus::encode::Error> {
        self.0.consensus_encode(s)
    }
}

impl consensus::Decodable for MerkleNode {
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, consensus::encode::Error> {
        Ok(Self::from_inner(<<MerkleNode as Hash>::Inner>::consensus_decode(d)?))
    }
}


pub fn merklize(prefix: &str, data: &[MerkleNode], depth: u16) -> MerkleNode {
    let len = data.len();

    let mut height: usize = 0;
    while ((len + (1 << height) - 1) >> height) > 1 {
        height += 1;
    };

    let mut engine = MerkleNode::engine();
    let tag = format!("{}:merkle:{}", prefix, depth);
    let tag_hash = sha256::Hash::hash(tag.as_bytes());
    engine.input(&tag_hash[..]);
    engine.input(&tag_hash[..]);
    match len {
        0 => {
            0u8.commitment_serialize(&mut engine).unwrap();
        }
        1 => {
            data.first().expect("We know that we have one element").commitment_serialize(&mut engine).unwrap();
            0u8.commitment_serialize(&mut engine).unwrap();
        }
        2 => {
            data.first().expect("We know that we have at least two elements").commitment_serialize(&mut engine).unwrap();
            data.last().expect("We know that we have at least two elements").commitment_serialize(&mut engine).unwrap();
        }
        _ => {
            let div = len / 2;
            merklize(prefix, &data[0..div], depth + 1).commitment_serialize(&mut engine).unwrap();
            merklize(prefix, &data[div..], depth + 1).commitment_serialize(&mut engine).unwrap();
        }
    }
    MerkleNode::from_engine(engine)
}

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
    consensus::encode::{self, Encodable},
    hashes::hex::{ToHex, FromHex},
    hashes::{Hash, sha256d}
};

hash_newtype!(MerkleNode, sha256d::Hash, 32, doc="A hash of a arbitrary Merkle tree branch or root");

impl encode::Encodable for MerkleNode {
    fn consensus_encode<S: io::Write>(&self, s: S) -> Result<usize, encode::Error> {
        self.0.consensus_encode(s)
    }
}

impl encode::Decodable for MerkleNode {
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, encode::Error> {
        Ok(Self::from_inner(<<MerkleNode as Hash>::Inner>::consensus_decode(d)?))
    }
}

pub fn merklize(data: &[MerkleNode]) -> MerkleNode {
    // TODO: Commit to the branch depth and use tagged hashes

    let len = data.len();

    let mut height: usize = 0;
    while ((len + (1 << height) - 1) >> height) > 1 {
        height += 1;
    };

    let mut engine = MerkleNode::engine();
    match len {
        0 => {
            0u8.consensus_encode(&mut engine).unwrap();
        }
        1 => {
            data.first().expect("We know that we have one element").consensus_encode(&mut engine).unwrap();
            0u8.consensus_encode(&mut engine).unwrap();
        }
        2 => {
            data.first().expect("We know that we have at least two elements").consensus_encode(&mut engine).unwrap();
            data.last().expect("We know that we have at least two elements").consensus_encode(&mut engine).unwrap();
        }
        _ => {
            let div = len / 2;
            merklize(&data[0..div]).consensus_encode(&mut engine).unwrap();
            merklize(&data[div..]).consensus_encode(&mut engine).unwrap();
        }
    }
    MerkleNode::from_engine(engine)
}

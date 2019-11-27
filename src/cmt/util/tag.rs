// LNP/BP Rust Library
// Written in 2019 by
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

use bitcoin::hashes::{sha256, Hash, Error};
use std::ops::{Index, RangeFull};

pub struct BitcoinTag(sha256::Hash);

impl BitcoinTag {
    pub fn tag(tag: &str) -> Self {
        let hash = sha256::Hash::hash(tag.as_bytes());
        let mut prefix = hash.to_vec();
        prefix.extend(hash.to_vec());
        BitcoinTag(sha256::Hash::hash(&prefix[..]))
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, Error> {
        Ok(BitcoinTag(sha256::Hash::from_slice(slice)?))
    }
}

impl Index<RangeFull> for BitcoinTag {
    type Output = [u8];
    fn index(&self, index: RangeFull) -> &[u8] { &self.0[..] }
}

use bitcoin::hashes::{sha256, Hash, Error};
use std::ops::{Index, Range, RangeFull, RangeBounds};

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

// LNP/BP Core Library implementing LNPBP specifications & standards
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

//! # Tagged256
//! Bitcoin tagged hashes as defined by BIP-Schnorr proposal

use bitcoin::hashes::{sha256, Hash, HashEngine};

hash_newtype!(
    TaggedHash,
    sha256::Hash,
    32,
    doc = "Tagged hash data according to BIP-Schnorr"
);

pub fn tagged256hash(tag: &str, msg: Vec<u8>) -> TaggedHash {
    let mut engine = sha256::Hash::engine();
    let tag_hash = sha256::Hash::hash(tag.as_bytes());
    engine.input(&tag_hash[..]);
    engine.input(&tag_hash[..]);
    engine.input(&msg[..]);
    sha256::Hash::from_engine(engine).into()
}

#[macro_export]
macro_rules! hashed_tag {
    ($prefix:expr, $tag:expr) => {
        const TAG: &'static str = concat!($prefix, $tag);
    };
}

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


use bitcoin::hashes::{
    sha256d, Hash
};

#[macro_use]
pub mod tagged256;
pub mod scripts;
pub mod merkle;
pub mod short_id;

pub use scripts::*;
pub use merkle::*;
pub use short_id::*;

hash_newtype!(HashLock, sha256d::Hash, 32, doc="Hashed locks in HTLC");
hash_newtype!(HashPreimage, sha256d::Hash, 32, doc="Pre-images for hashed locks in HTLC");

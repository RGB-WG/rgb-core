// RGB Core Library: a reference implementation of RGB smart contract standards.
// Written in 2019-2022 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the MIT License along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

use bitcoin_hashes::Hash;
use commit_verify::{commit_encode, CommitConceal};
use strict_encoding::strict_serialize;

// TODO: Use tagged hash
hash_newtype!(
    Confidential,
    sha256d::Hash,
    20,
    doc = "Confidential representation of data container information"
);

#[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq)]
#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct Revealed {
    pub id: ContainerId,
    pub mime: String,
    pub salt: u64,
}

impl CommitConceal for Revealed {
    type ConcealedCommitment = Confidential;

    fn commit_conceal(&self) -> Self::ConcealedCommitment {
        Confidential::hash(
            &strict_serialize(self).expect("Encoding of predefined data types must not fail"),
        )
    }
}
impl commit_encode::Strategy for Revealed {
    type Strategy = commit_encode::strategies::UsingConceal;
}

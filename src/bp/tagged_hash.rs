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

//! Bitcoin tagged hash helper types.

use amplify::Wrapper;
use bitcoin::hashes::{sha256, sha256t, Hash, HashEngine};

/// Helper class for tests and creation of tagged hashes with dynamically-
/// defined tags. Do not use in all other cases; utilize
/// [`bitcoin::hashes::sha256t`] type and [`bitcoin::sha256t_hash_newtype!`]
/// macro instead.
#[derive(
    Wrapper, Clone, Copy, PartialEq, Eq, Hash, Debug, Display, Default, From,
)]
#[display("{_0:#x?}")]
pub struct Midstate([u8; 32]);

impl Midstate {
    /// Constructs tagged hash midstate for a given tag data
    pub fn with(tag: impl AsRef<[u8]>) -> Self {
        let mut engine = sha256::Hash::engine();
        let tag_hash = sha256::Hash::hash(tag.as_ref());
        engine.input(&tag_hash[..]);
        engine.input(&tag_hash[..]);
        Self::from_inner(engine.midstate().into_inner())
    }
}

pub trait TaggedHash<'a, H>
where
    Self: Wrapper<Inner = sha256t::Hash<H>>,
    H: 'a + sha256t::Tag,
{
    fn from_hash<X>(hash: X) -> Self
    where
        Self: Sized,
        X: Hash<Inner = [u8; 32]>,
    {
        Self::from_inner(sha256t::Hash::from_inner(hash.into_inner()))
    }

    fn as_slice(&'a self) -> &'a [u8; 32] {
        self.as_inner().as_inner()
    }
}

impl<'a, T, H> TaggedHash<'a, H> for T
where
    T: Wrapper<Inner = sha256t::Hash<H>>,
    H: 'a + sha256t::Tag,
{
}

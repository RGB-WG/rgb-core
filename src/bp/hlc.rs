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

//! Hash-locked contract supporting data structures

use amplify::{DumbDefault, Wrapper};
#[cfg(feature = "serde")]
use serde_with::{As, DisplayFromStr};

use bitcoin::hashes::hex::{Error, FromHex};
use bitcoin::hashes::{sha256, Hash};

use super::Slice32;

/// HTLC payment hash
#[cfg_attr(
    feature = "serde",
    serde_as,
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[derive(
    Wrapper,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Display,
    From,
    StrictEncode,
    StrictDecode,
)]
#[lnpbp_crate(crate)]
#[display(LowerHex)]
#[wrapper(FromStr, LowerHex, UpperHex)]
pub struct HashLock(
    #[cfg_attr(feature = "serde", serde(with = "As::<DisplayFromStr>"))]
    Slice32,
);

impl From<HashPreimage> for HashLock {
    fn from(preimage: HashPreimage) -> Self {
        let hash = sha256::Hash::hash(preimage.as_ref());
        Self::from_inner(Slice32::from_inner(hash.into_inner()))
    }
}

impl FromHex for HashLock {
    fn from_byte_iter<I>(iter: I) -> Result<Self, Error>
    where
        I: Iterator<Item = Result<u8, Error>>
            + ExactSizeIterator
            + DoubleEndedIterator,
    {
        Ok(Self(Slice32::from_byte_iter(iter)?))
    }
}

impl AsRef<[u8]> for HashLock {
    fn as_ref(&self) -> &[u8] {
        self.as_inner().as_ref()
    }
}

/// HTLC payment preimage
#[cfg_attr(
    feature = "serde",
    serde_as,
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[derive(
    Wrapper,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Display,
    From,
    StrictEncode,
    StrictDecode,
)]
#[lnpbp_crate(crate)]
#[display(LowerHex)]
#[wrapper(FromStr, LowerHex, UpperHex)]
pub struct HashPreimage(
    #[cfg_attr(feature = "serde", serde(with = "As::<DisplayFromStr>"))]
    Slice32,
);

impl HashPreimage {
    #[cfg(feature = "keygen")]
    pub fn random() -> Self {
        HashPreimage::from_inner(Slice32::random())
    }
}

impl FromHex for HashPreimage {
    fn from_byte_iter<I>(iter: I) -> Result<Self, Error>
    where
        I: Iterator<Item = Result<u8, Error>>
            + ExactSizeIterator
            + DoubleEndedIterator,
    {
        Ok(Self(Slice32::from_byte_iter(iter)?))
    }
}

impl DumbDefault for HashPreimage {
    fn dumb_default() -> Self {
        Self(Default::default())
    }
}

impl AsRef<[u8]> for HashPreimage {
    fn as_ref(&self) -> &[u8] {
        self.as_inner().as_ref()
    }
}

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

use amplify::{DumbDefault, Wrapper};
use std::collections::BTreeMap;
use std::fmt::Debug;

use bitcoin::hashes::hex::{Error, FromHex};
use bitcoin::hashes::Hash;
use bitcoin::OutPoint;

use crate::bp::chain::AssetId;
use crate::bp::Slice32;

/// Shorthand for representing asset - amount pairs
pub type AssetsBalance = BTreeMap<AssetId, u64>;

#[cfg_attr(feature = "serde", serde_as(as = "DisplayFromStr"))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Display,
    StrictEncode,
    StrictDecode,
)]
#[display(Debug)]
#[lnpbp_crate(crate)]
#[non_exhaustive]
#[repr(u8)]
pub enum Lifecycle {
    Initial,
    Proposed,                 // Got or sent `open_channel`
    Accepted,                 // Got or sent `accept_channel`
    Funding,                  // One party signed funding tx
    Signed,                   // Other peer signed funding tx
    Funded,                   // Funding tx is published but not mined
    Locked,                   // Funding tx mined
    Shutdown,                 // Shutdown proposed but not yet accepted
    Closing { round: usize }, // Shutdown agreed, exchanging `closing_signed`
    Closed,                   // Cooperative closing
    Aborted,                  // Non-cooperative unilateral closing
}

impl Default for Lifecycle {
    fn default() -> Self {
        Lifecycle::Initial
    }
}

/// Lightning network channel Id
#[cfg_attr(feature = "serde", serde_as(as = "DisplayFromStr"))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
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
    Default,
    From,
    StrictEncode,
    StrictDecode,
)]
#[lnpbp_crate(crate)]
#[display(LowerHex)]
#[wrapper(FromStr, LowerHex, UpperHex)]
pub struct ChannelId(Slice32);

impl FromHex for ChannelId {
    fn from_byte_iter<I>(iter: I) -> Result<Self, Error>
    where
        I: Iterator<Item = Result<u8, Error>>
            + ExactSizeIterator
            + DoubleEndedIterator,
    {
        Ok(Self(Slice32::from_byte_iter(iter)?))
    }
}

impl ChannelId {
    pub fn with(funding_outpoint: OutPoint) -> Self {
        let mut slice = funding_outpoint.txid.into_inner();
        let vout = funding_outpoint.vout.to_be_bytes();
        slice[30] ^= vout[0];
        slice[31] ^= vout[1];
        ChannelId::from_inner(Slice32::from_inner(slice))
    }
}

/// Lightning network temporary channel Id
#[cfg_attr(feature = "serde", serde_as(as = "DisplayFromStr"))]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
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
pub struct TempChannelId(Slice32);

impl From<TempChannelId> for ChannelId {
    fn from(temp: TempChannelId) -> Self {
        Self(temp.into_inner())
    }
}

impl From<ChannelId> for TempChannelId {
    fn from(id: ChannelId) -> Self {
        Self(id.into_inner())
    }
}

impl FromHex for TempChannelId {
    fn from_byte_iter<I>(iter: I) -> Result<Self, Error>
    where
        I: Iterator<Item = Result<u8, Error>>
            + ExactSizeIterator
            + DoubleEndedIterator,
    {
        Ok(Self(Slice32::from_byte_iter(iter)?))
    }
}

impl TempChannelId {
    #[cfg(feature = "keygen")]
    pub fn random() -> Self {
        TempChannelId::from_inner(Slice32::random())
    }
}

impl DumbDefault for TempChannelId {
    fn dumb_default() -> Self {
        Self(Default::default())
    }
}

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

use amplify::{DumbDefault, ToYamlString, Wrapper};
use std::collections::BTreeMap;

use bitcoin::hashes::hex::{Error, FromHex};
use bitcoin::hashes::{sha256, Hash, Hmac};
use bitcoin::secp256k1::PublicKey;
use bitcoin::{OutPoint, Script};

use crate::bp::chain::AssetId;
use crate::bp::Slice32;
use crate::lnp::message::{AcceptChannel, OpenChannel};
use crate::SECP256K1_PUBKEY_DUMB;

pub use super::tx::{ScriptGenerators, TxGenerators};

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
pub enum ChannelState {
    Unknown = 0,
    Proposed = 1,
    Accepted,
    Signed,
    Locked,
    Closing,
    Closed,
}

impl Default for ChannelState {
    fn default() -> Self {
        ChannelState::Unknown
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

#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Debug,
    Display,
    Error,
    StrictEncode,
    StrictDecode,
)]
#[lnpbp_crate(crate)]
#[display(doc_comments)]
/// Errors from
/// <https://github.com/lightningnetwork/lightning-rfc/blob/master/02-peer-protocol.md#requirements-1>
pub enum ChannelNegotiationError {
    // TODO: Add other errors from validation parts of open_channel message
    /// minimum depth requested by the remote peer is unreasonably large ({0});
    /// rejecting the channel according to BOLT-2
    UnreasonableMinDepth(u32),

    /// channel_reserve_satoshis ({0}) is less than dust_limit_satoshis ({1})
    /// within the open_channel message; rejecting the channel according to
    /// BOLT-2
    LocalDustExceedsRemoteReserve(u64, u64),

    /// channel_reserve_satoshis from the open_channel message ({0}) is less
    /// than dust_limit_satoshis ({1}; rejecting the channel according to
    /// BOLT-2
    RemoteDustExceedsLocalReserve(u64, u64),
}

#[derive(
    Clone, Copy, PartialEq, Eq, Debug, Default, StrictEncode, StrictDecode,
)]
#[cfg_attr(
    feature = "serde",
    derive(Display, Serialize, Deserialize),
    serde(crate = "serde_crate"),
    display(ChannelParams::to_yaml_string)
)]
#[lnpbp_crate(crate)]
pub struct ChannelParams {
    pub funding_satoshis: u64,
    pub push_msat: u64,
    pub dust_limit_satoshis: u64,
    pub max_htlc_value_in_flight_msat: u64,
    pub channel_reserve_satoshis: u64,
    pub htlc_minimum_msat: u64,
    pub feerate_per_kw: u32,
    pub minimum_depth: u32,
    pub to_self_delay: u16,
    pub max_accepted_htlcs: u16,
    pub channel_flags: u8,
}

#[cfg(feature = "serde")]
impl ToYamlString for ChannelParams {}

impl ChannelParams {
    pub fn with(
        open_channel: &OpenChannel,
    ) -> Result<Self, ChannelNegotiationError> {
        // TODO: Validate parameters according to BOLT-2 open_channel validation
        //       requirements
        Ok(Self {
            funding_satoshis: open_channel.funding_satoshis,
            push_msat: open_channel.push_msat,
            dust_limit_satoshis: open_channel.dust_limit_satoshis,
            max_htlc_value_in_flight_msat: open_channel
                .max_htlc_value_in_flight_msat,
            channel_reserve_satoshis: open_channel.channel_reserve_satoshis,
            htlc_minimum_msat: open_channel.htlc_minimum_msat,
            feerate_per_kw: open_channel.feerate_per_kw,
            minimum_depth: 0,
            to_self_delay: 0,
            max_accepted_htlcs: open_channel.max_accepted_htlcs,
            channel_flags: open_channel.channel_flags,
        })
    }

    pub fn updated(
        &self,
        accept_channel: &AcceptChannel,
        depth_upper_bound: Option<u32>,
    ) -> Result<Self, ChannelNegotiationError> {
        // The temporary_channel_id MUST be the same as the temporary_channel_id
        // in the open_channel message.

        // if minimum_depth is unreasonably large:
        //
        //     MAY reject the channel.
        if let Some(depth_upper_bound) = depth_upper_bound {
            if accept_channel.minimum_depth > depth_upper_bound {
                return Err(ChannelNegotiationError::UnreasonableMinDepth(
                    accept_channel.minimum_depth,
                ));
            }
        }

        // if channel_reserve_satoshis is less than dust_limit_satoshis within
        // the open_channel message:
        //
        //     MUST reject the channel.
        if accept_channel.channel_reserve_satoshis < self.dust_limit_satoshis {
            return Err(
                ChannelNegotiationError::LocalDustExceedsRemoteReserve(
                    accept_channel.channel_reserve_satoshis,
                    self.dust_limit_satoshis,
                ),
            );
        }

        // if channel_reserve_satoshis from the open_channel message is less
        // than dust_limit_satoshis:
        //
        //     MUST reject the channel.
        if self.dust_limit_satoshis < accept_channel.channel_reserve_satoshis {
            return Err(
                ChannelNegotiationError::RemoteDustExceedsLocalReserve(
                    self.channel_reserve_satoshis,
                    accept_channel.dust_limit_satoshis,
                ),
            );
        }

        // Other fields have the same requirements as their counterparts in
        // open_channel.
        Ok(Self {
            dust_limit_satoshis: accept_channel.dust_limit_satoshis,
            max_htlc_value_in_flight_msat: accept_channel
                .max_htlc_value_in_flight_msat,
            channel_reserve_satoshis: accept_channel.channel_reserve_satoshis,
            htlc_minimum_msat: accept_channel.htlc_minimum_msat,
            minimum_depth: accept_channel.minimum_depth,
            to_self_delay: accept_channel.to_self_delay,
            max_accepted_htlcs: accept_channel.max_accepted_htlcs,
            ..*self
        })
    }
}

#[derive(Clone, PartialEq, Eq, Debug, StrictEncode, StrictDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Display, Serialize, Deserialize),
    serde(crate = "serde_crate"),
    display(ChannelKeys::to_yaml_string)
)]
#[lnpbp_crate(crate)]
pub struct ChannelKeys {
    pub funding_pubkey: PublicKey,
    pub revocation_basepoint: PublicKey,
    pub payment_basepoint: PublicKey,
    pub delayed_payment_basepoint: PublicKey,
    pub htlc_basepoint: PublicKey,
    pub first_per_commitment_point: PublicKey,
    pub shutdown_scriptpubkey: Option<Script>,
}

#[cfg(feature = "serde")]
impl ToYamlString for ChannelKeys {}

impl From<&OpenChannel> for ChannelKeys {
    fn from(msg: &OpenChannel) -> Self {
        Self {
            funding_pubkey: msg.funding_pubkey,
            revocation_basepoint: msg.revocation_basepoint,
            payment_basepoint: msg.payment_point,
            delayed_payment_basepoint: msg.delayed_payment_basepoint,
            htlc_basepoint: msg.htlc_basepoint,
            first_per_commitment_point: msg.first_per_commitment_point,
            shutdown_scriptpubkey: msg.shutdown_scriptpubkey.clone(),
        }
    }
}

impl From<&AcceptChannel> for ChannelKeys {
    fn from(msg: &AcceptChannel) -> Self {
        Self {
            funding_pubkey: msg.funding_pubkey,
            revocation_basepoint: msg.revocation_basepoint,
            payment_basepoint: msg.payment_point,
            delayed_payment_basepoint: msg.delayed_payment_basepoint,
            htlc_basepoint: msg.htlc_basepoint,
            first_per_commitment_point: msg.first_per_commitment_point,
            shutdown_scriptpubkey: msg.shutdown_scriptpubkey.clone(),
        }
    }
}

impl DumbDefault for ChannelKeys {
    fn dumb_default() -> Self {
        Self {
            funding_pubkey: *SECP256K1_PUBKEY_DUMB,
            revocation_basepoint: *SECP256K1_PUBKEY_DUMB,
            payment_basepoint: *SECP256K1_PUBKEY_DUMB,
            delayed_payment_basepoint: *SECP256K1_PUBKEY_DUMB,
            htlc_basepoint: *SECP256K1_PUBKEY_DUMB,
            first_per_commitment_point: *SECP256K1_PUBKEY_DUMB,
            shutdown_scriptpubkey: None,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, StrictEncode, StrictDecode)]
#[lnpbp_crate(crate)]
#[display(Debug)]
pub struct OnionPacket {
    pub version: u8,
    pub public_key: bitcoin::secp256k1::PublicKey,
    pub hop_data: Vec<u8>, //[u8; 20 * 65],
    pub hmac: Hmac<sha256::Hash>,
}

impl DumbDefault for OnionPacket {
    fn dumb_default() -> Self {
        OnionPacket {
            version: 0,
            public_key: *SECP256K1_PUBKEY_DUMB,
            hop_data: empty!(),
            hmac: zero!(),
        }
    }
}

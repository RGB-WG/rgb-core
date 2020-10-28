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

use amplify::Wrapper;

pub mod channel;
mod features;
pub mod message;
mod peer_connection;
pub mod rpc_connection;

pub use features::{FeatureContext, FeatureFlag, Features};
pub use message::{Messages, LNPWP_UNMARSHALLER};
pub use peer_connection::{
    PeerConnection, PeerReceiver, PeerSender, RecvMessage, SendMessage,
};
pub use rpc_connection::RpcConnection;

use bitcoin::hashes::{sha256, Hmac};
use bitcoin_hashes::hex::{Error, FromHex};

/// Lightning network channel Id
#[derive(
    Wrapper,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Debug,
    Display,
    From,
    StrictEncode,
    StrictDecode,
)]
#[lnpbp_crate(crate)]
#[display(Debug)]
pub struct ChannelId([u8; 32]);

impl FromHex for ChannelId {
    fn from_byte_iter<I>(iter: I) -> Result<Self, Error>
    where
        I: Iterator<Item = Result<u8, Error>>
            + ExactSizeIterator
            + DoubleEndedIterator,
    {
        Ok(ChannelId(slice32_from_byte_iter(iter)?))
    }
}

/// Lightning network temporary channel Id
#[derive(
    Wrapper,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Debug,
    Display,
    From,
    StrictEncode,
    StrictDecode,
)]
#[lnpbp_crate(crate)]
#[display(Debug)]
pub struct TempChannelId([u8; 32]);

impl FromHex for TempChannelId {
    fn from_byte_iter<I>(iter: I) -> Result<Self, Error>
    where
        I: Iterator<Item = Result<u8, Error>>
            + ExactSizeIterator
            + DoubleEndedIterator,
    {
        Ok(TempChannelId(slice32_from_byte_iter(iter)?))
    }
}

/// HTLC payment hash
#[derive(
    Wrapper,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Debug,
    Display,
    From,
    StrictEncode,
    StrictDecode,
)]
#[lnpbp_crate(crate)]
#[display(Debug)]
pub struct PaymentHash([u8; 32]);

impl FromHex for PaymentHash {
    fn from_byte_iter<I>(iter: I) -> Result<Self, Error>
    where
        I: Iterator<Item = Result<u8, Error>>
            + ExactSizeIterator
            + DoubleEndedIterator,
    {
        Ok(PaymentHash(slice32_from_byte_iter(iter)?))
    }
}

/// HTLC payment preimage
#[derive(
    Wrapper,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Debug,
    Display,
    From,
    StrictEncode,
    StrictDecode,
)]
#[lnpbp_crate(crate)]
#[display(Debug)]
pub struct PaymentPreimage([u8; 32]);

impl FromHex for PaymentPreimage {
    fn from_byte_iter<I>(iter: I) -> Result<Self, Error>
    where
        I: Iterator<Item = Result<u8, Error>>
            + ExactSizeIterator
            + DoubleEndedIterator,
    {
        Ok(PaymentPreimage(slice32_from_byte_iter(iter)?))
    }
}

/// Payment secret use to authenticate sender to the receiver and tie MPP HTLCs
/// together
#[derive(
    Wrapper,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Debug,
    Display,
    From,
    StrictEncode,
    StrictDecode,
)]
#[lnpbp_crate(crate)]
#[display(Debug)]
pub struct PaymentSecret([u8; 32]);

impl FromHex for PaymentSecret {
    fn from_byte_iter<I>(iter: I) -> Result<Self, Error>
    where
        I: Iterator<Item = Result<u8, Error>>
            + ExactSizeIterator
            + DoubleEndedIterator,
    {
        Ok(PaymentSecret(slice32_from_byte_iter(iter)?))
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

fn slice32_from_byte_iter<I>(iter: I) -> Result<[u8; 32], Error>
where
    I: Iterator<Item = Result<u8, Error>>
        + ExactSizeIterator
        + DoubleEndedIterator,
{
    let vec = Vec::<u8>::from_byte_iter(iter)?;
    if vec.len() != 32 {
        return Err(Error::InvalidLength(32, vec.len()));
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&vec);
    Ok(id)
}

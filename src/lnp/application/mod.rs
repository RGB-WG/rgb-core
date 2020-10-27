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

#[derive(Clone, PartialEq, Eq, Debug, Display, StrictEncode, StrictDecode)]
#[lnpbp_crate(crate)]
#[display(Debug)]
pub struct OnionPacket {
    pub version: u8,
    pub public_key: bitcoin::secp256k1::PublicKey,
    pub hop_data: Vec<u8>, //[u8; 20 * 65],
    pub hmac: Hmac<sha256::Hash>,
}

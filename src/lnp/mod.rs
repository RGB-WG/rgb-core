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

//! Module that systematizes all Lightning network-related APIs from the
//! `lightning` library into layered & modular design

pub mod application;
pub mod presentation;
pub mod session;
pub mod transport;

pub use application::{
    channel, message, rpc_connection, ChannelId, FeatureContext, FeatureFlag,
    Features, Messages, OnionPacket, PaymentHash, PaymentPreimage,
    PaymentSecret, PeerConnection, PeerReceiver, PeerSender, RecvMessage,
    RpcConnection, SendMessage, TempChannelId, LNPWP_UNMARSHALLER,
};
pub use presentation::payload::{TypeId, TypedEnum};
pub use presentation::{
    payload, tlv, CreateUnmarshaller, Payload, UnknownTypeError, Unmarshall,
    UnmarshallFn, Unmarshaller,
};
pub use session::{
    Accept, Connect, Decrypt, Encrypt, LocalNode, NoEncryption, NodeAddr,
    NodeLocator, RemoteNodeAddr, Session, Split, ToNodeAddr, ToRemoteNodeAddr,
    Transcode,
};
pub use transport::{
    ftcp, websocket, zmqsocket, Duplex, FramingProtocol, LocalSocketAddr,
    RemoteSocketAddr, RoutedFrame, SocketAddrError,
};

pub const LNP_MSG_MAX_LEN: usize = core::u64::MAX as usize;

pub const LIGHTNING_P2P_DEFAULT_PORT: u16 = 9735;

#[cfg(feature = "zmq")]
pub use transport::{ZmqAddr, ZMQ_CONTEXT};

/// Trait used by different address types (transport-, session- and
/// presentation-based) for getting scheme part of the URL
pub trait UrlScheme {
    /// Returns full URL scheme string (i.e. including `:` or `://` parts)
    /// corresponding to the provided address
    fn url_scheme(&self) -> &'static str;
}

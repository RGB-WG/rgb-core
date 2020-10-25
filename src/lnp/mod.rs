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
mod session;
pub mod transport;

pub use application::channel;
pub use presentation::payload::{TypeId, TypedEnum, Unmarshaller};
pub use presentation::{
    payload, rpc_connection, tlv, CreateUnmarshaller, Payload, PeerConnection,
    PeerReceiver, PeerSender, RpcConnection, UnknownTypeError, Unmarshall,
    UnmarshallFn,
};
pub use session::{
    Decrypt, Encrypt, LocalNode, NoEncryption, NodeAddr, NodeEndpoint,
    NodeLocator, Session, SessionInput, SessionOutput, ToNodeAddr,
    ToNodeEndpoint, Transcode,
};
pub use transport::{
    ftcp, websocket, zmqsocket, Duplex, LocalAddr, RemoteAddr,
};

pub const LNP_MSG_MAX_LEN: usize = core::u64::MAX as usize;

pub const LIGHTNING_P2P_DEFAULT_PORT: u16 = 9735;

#[cfg(feature = "zmq")]
pub use transport::ZMQ_CONTEXT;

/// Trait used by different address types (transport-, session- and
/// presentation-based) for getting scheme part of the URL
pub trait UrlScheme {
    /// Returns full URL scheme string (i.e. including `:` or `://` parts)
    /// corresponding to the provided address
    fn url_scheme(&self) -> &'static str;
}

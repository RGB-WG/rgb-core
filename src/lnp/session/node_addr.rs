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

use core::convert::{TryFrom, TryInto};
use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;

use amplify::internet::InetSocketAddr;
use bitcoin::secp256k1;

use super::{node_locator, Connection, ConnectionError, NodeLocator};
use crate::lnp::transport::{zmqsocket, LocalAddr, RemoteAddr};
use crate::lnp::UrlScheme;

/// Node endpoint which can be represent by either some local address without
/// encryption information (i.e. node public key) or remote node address
/// containing node public key
#[derive(Clone, PartialEq, Eq, Debug, Display)]
pub enum NodeEndpoint {
    /// Local node using plain transport protocol [`LocalAddr`] information and
    /// no encryption
    #[display("{_0}", alt = "{_0:#}")]
    Local(LocalAddr),

    /// Remote node required to have a node public key used for ID and
    /// encryption
    #[display("{_0}", alt = "{_0:#}")]
    Remote(NodeAddr),
}

/// Full node address at the session-level including node encryption/id key
/// information and full [`RemoteAddr`] with transport protocol & complete
/// connection point specification.
#[cfg_attr(feature = "serde", serde_as(as = "DisplayFromStr"))]
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub struct NodeAddr {
    /// Node public key, used both as an ID and encryption key for per-session
    /// ECDH
    pub node_id: secp256k1::PublicKey,

    /// Full remote peer address including port information
    pub remote_addr: RemoteAddr,
}

impl_try_from_stringly_standard!(NodeAddr);
impl_into_stringly_standard!(NodeAddr);

impl NodeAddr {
    #[cfg(not(feature = "lightning"))]
    pub async fn connect(
        &self,
        private_key: &secp256k1::SecretKey,
        ephemeral_private_key: &secp256k1::SecretKey,
    ) -> Result<Connection, ConnectionError> {
        unimplemented!()
    }

    #[cfg(feature = "lightning")]
    pub async fn connect(
        &self,
        private_key: &secp256k1::SecretKey,
        ephemeral_private_key: &secp256k1::SecretKey,
    ) -> Result<Connection, ConnectionError> {
        Connection::new(self, private_key, ephemeral_private_key).await
    }
}

impl fmt::Display for NodeAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}@{}",
            self.remote_addr.url_scheme(),
            self.node_id,
            self.remote_addr
        )
    }
}

/// Error representing:
/// * error parsing [`NodeAddr`] from string representation, which must be in
///   `<node_id>@<node_inet_addr>[:<port>]` format, where <node_inet_addr> may
///   be IPv4, IPv6 or TOR v2, v3 address
/// * error converting [`NodeLocator`] to [`NodeAddr`]
#[derive(Clone, PartialEq, Eq, Hash, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum Error {
    /// Node id can't be decoded from the given information. Node id must be a
    /// valid Secp256k1 public key in a compact form
    #[from(bitcoin::secp256k1::Error)]
    WrongNodeId,

    /// Node address must be given as in form of
    /// `<node_id>@<node_inet_addr>[:<port>]`, where <node_inet_addr> may be
    /// IPv4, IPv6 or TORv3 address
    NoNodeId,

    /// The provided node address is incorrect; it must be IPv4, IPv6 or TOR
    /// v2, v3 address
    #[from]
    WrongInetAddr(String),

    /// Port information can't be decoded; it must be a 16-bit unsigned integer
    /// literal
    #[from(std::num::ParseIntError)]
    WrongPort,

    /// Nointerned address specified after node public key
    MissedInetAddr,

    /// Can't read string as a proper node address: it must be in
    /// `<node_id>@<node_inet_addr>[:<port>]` format, where <node_inet_addr>
    /// may be IPv4, IPv6 or Tor v3, v2 address (no `.onion` suffix)
    #[from]
    Parse(node_locator::ParseError),

    /// No port information is provided; use [`NodeLocator::with_port`] method
    /// before calling the conversion
    NoPort,

    /// Node locator of the given type can't be represented as [`NodeAddr`].
    /// Only [`NodeLocator::Native`] addresses can be converted.
    UnsupportedType,
}

impl FromStr for NodeAddr {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        NodeLocator::from_str(s)?.try_into()
    }
}

impl TryFrom<NodeLocator> for NodeAddr {
    type Error = Error;

    fn try_from(locator: NodeLocator) -> Result<Self, Self::Error> {
        match locator {
            NodeLocator::Native(.., None) => Err(Error::NoPort),
            #[cfg(feature = "websocket")]
            NodeLocator::Websocket(.., None) => Err(Error::NoPort),
            #[cfg(feature = "zmq")]
            NodeLocator::ZmqTcpEncrypted(.., None) => Err(Error::NoPort),
            NodeLocator::Native(pubkey, address, Some(port)) => Ok(NodeAddr {
                node_id: pubkey,
                remote_addr: RemoteAddr::Ftcp(InetSocketAddr { address, port }),
            }),
            #[cfg(feature = "zmq")]
            NodeLocator::ZmqTcpEncrypted(pubkey, api, ip, Some(port)) => {
                Ok(NodeAddr {
                    node_id: pubkey,
                    remote_addr: RemoteAddr::Zmq(SocketAddr::new(ip, port)),
                })
            }
            #[cfg(feature = "websocket")]
            NodeLocator::Websocket(pubkey, addr, Some(port)) => Ok(NodeAddr {
                node_id: pubkey,
                remote_addr: RemoteAddr::Websocket(InetSocketAddr::new(
                    addr, port,
                )),
            }),
            _ => Err(Error::UnsupportedType),
        }
    }
}

impl From<NodeAddr> for NodeLocator {
    fn from(node_addr: NodeAddr) -> NodeLocator {
        match node_addr.remote_addr {
            RemoteAddr::Ftcp(addr) => NodeLocator::Native(
                node_addr.node_id,
                addr.address,
                Some(addr.port),
            ),
            RemoteAddr::Posix(path) => NodeLocator::Posix(path),
            #[cfg(feature = "zmq")]
            RemoteAddr::Zmq(addr) => NodeLocator::ZmqTcpEncrypted(
                node_addr.node_id,
                zmqsocket::ApiType::Server,
                InetSocketAddr::from(addr)
                    .address
                    .try_into()
                    .expect("Conversion from just generated type can't fail"),
                Some(addr.port()),
            ),
            RemoteAddr::Http(addr) => NodeLocator::Http(
                node_addr.node_id,
                addr.address,
                Some(addr.port),
            ),
            #[cfg(feature = "websocket")]
            RemoteAddr::Websocket(addr) => NodeLocator::Websocket(
                node_addr.node_id,
                addr.address,
                Some(addr.port),
            ),
            RemoteAddr::Smtp(addr) => NodeLocator::Text(node_addr.node_id),
        }
    }
}

impl From<NodeAddr> for RemoteAddr {
    fn from(addr: NodeAddr) -> RemoteAddr {
        addr.remote_addr
    }
}

// TODO: (future) Re-implement with const generics once this rust language
//       feature will be stabilized and released
/// Trait allowing generic function arguments for application-level
/// implementations knowning default protocol port
pub trait ToNodeAddr {
    /// Constructs [`NodeAddr`] from an internal data with a default port put
    /// in place when the port details were not given is such structures as
    /// [`NodeLocator`]
    ///
    /// # Returns
    /// * `None`, if the underlying type variant can't be represented as a
    ///   complete node address (for instance, for unencrypted local socket)
    ///   Corresponds to situations when `TryInto<`[`NodeAddr`]`>` returns
    ///   [`ConversionError::UnsupportedType`] or when string conversion fails
    ///   with [`ParseError`].
    /// * `Some(`[`NodeAddr`]`)` otherwise
    fn to_node_addr(&self, default_port: u16) -> Option<NodeAddr>;
}

impl ToNodeAddr for NodeLocator {
    fn to_node_addr(&self, default_port: u16) -> Option<NodeAddr> {
        self.with_port(default_port).try_into().ok()
    }
}

impl ToNodeAddr for NodeAddr {
    fn to_node_addr(&self, default_port: u16) -> Option<NodeAddr> {
        Some(self.clone())
    }
}

impl ToNodeAddr for String {
    fn to_node_addr(&self, default_port: u16) -> Option<NodeAddr> {
        NodeAddr::from_str(self.as_str()).ok()
    }
}

impl ToNodeAddr for &str {
    fn to_node_addr(&self, default_port: u16) -> Option<NodeAddr> {
        NodeAddr::from_str(&self).ok()
    }
}

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

use super::NodeLocator;
use crate::lnp::transport::{LocalSocketAddr, RemoteSocketAddr};
#[cfg(feature = "zmq")]
use crate::lnp::zmqsocket::{ZmqAddr, ZmqType};
use crate::lnp::{AddrError, UrlScheme};

/// Node address which can be represent by either some local address without
/// encryption information (i.e. node public key) or remote node address
/// containing node public key
#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
pub enum NodeAddr {
    /// Local node using plain transport protocol [`LocalSocketAddr`]
    /// information and no encryption
    #[display("{_0}", alt = "{_0:#}")]
    Local(LocalSocketAddr),

    /// Remote node required to have a node public key used for ID and
    /// encryption
    #[display("{_0}", alt = "{_0:#}")]
    Remote(RemoteNodeAddr),
}

impl FromStr for NodeAddr {
    type Err = AddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(NodeLocator::from_str(s)?.into())
    }
}

impl From<RemoteNodeAddr> for NodeAddr {
    fn from(addr: RemoteNodeAddr) -> Self {
        NodeAddr::Remote(addr)
    }
}

impl From<LocalSocketAddr> for NodeAddr {
    fn from(addr: LocalSocketAddr) -> Self {
        NodeAddr::Local(addr)
    }
}

impl From<NodeLocator> for NodeAddr {
    fn from(locator: NodeLocator) -> Self {
        RemoteNodeAddr::try_from(locator.clone())
            .map(|addr| NodeAddr::Remote(addr))
            .unwrap_or_else(|_| {
                NodeAddr::Local(LocalSocketAddr::try_from(locator).expect(
                    "NodeLocator must convert to either NodeAddr or LocalAddr",
                ))
            })
    }
}

#[cfg(feature = "zmq")]
impl TryFrom<NodeAddr> for ZmqAddr {
    type Error = AddrError;

    fn try_from(value: NodeAddr) -> Result<Self, Self::Error> {
        Ok(match value {
            NodeAddr::Local(LocalSocketAddr::Zmq(locator)) => locator,
            NodeAddr::Remote(RemoteNodeAddr {
                node_id,
                remote_addr: RemoteSocketAddr::Zmq(addr),
            }) => ZmqAddr::Tcp(addr),
            _ => Err(AddrError::Unsupported("ZMQ socket"))?,
        })
    }
}

/// Remote node address at the session-level including node encryption/id key
/// information and full [`RemoteSocketAddr`] with transport protocol & complete
/// connection point specification.
///
/// Node address must be given as in form of
/// `<node_id>@<node_inet_addr>[:<port>]`, where <node_inet_addr> may be
/// IPv4, IPv6, Onion v2 or v3 address
#[cfg_attr(feature = "serde", serde_as(as = "DisplayFromStr"))]
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub struct RemoteNodeAddr {
    /// Node public key, used both as an ID and encryption key for per-session
    /// ECDH
    pub node_id: secp256k1::PublicKey,

    /// Full remote peer address including port information
    pub remote_addr: RemoteSocketAddr,
}

impl_try_from_stringly_standard!(NodeAddr);
impl_into_stringly_standard!(NodeAddr);

impl fmt::Display for RemoteNodeAddr {
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

impl FromStr for RemoteNodeAddr {
    type Err = AddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        NodeLocator::from_str(s)?.try_into()
    }
}

impl TryFrom<NodeLocator> for RemoteNodeAddr {
    type Error = AddrError;

    fn try_from(locator: NodeLocator) -> Result<Self, Self::Error> {
        match locator {
            NodeLocator::Native(.., None) => Err(AddrError::PortRequired),
            #[cfg(feature = "websocket")]
            NodeLocator::Websocket(.., None) => Err(AddrError::HostRequired),
            #[cfg(feature = "zmq")]
            NodeLocator::ZmqTcpEncrypted(.., None) => {
                Err(AddrError::PortRequired)
            }
            NodeLocator::Native(pubkey, address, Some(port)) => {
                Ok(RemoteNodeAddr {
                    node_id: pubkey,
                    remote_addr: RemoteSocketAddr::Ftcp(InetSocketAddr {
                        address,
                        port,
                    }),
                })
            }
            #[cfg(feature = "zmq")]
            NodeLocator::ZmqTcpEncrypted(pubkey, api, ip, Some(port)) => {
                Ok(RemoteNodeAddr {
                    node_id: pubkey,
                    remote_addr: RemoteSocketAddr::Zmq(SocketAddr::new(
                        ip, port,
                    )),
                })
            }
            #[cfg(feature = "websocket")]
            NodeLocator::Websocket(pubkey, addr, Some(port)) => {
                Ok(RemoteNodeAddr {
                    node_id: pubkey,
                    remote_addr: RemoteSocketAddr::Websocket(
                        InetSocketAddr::new(addr, port),
                    ),
                })
            }
            _ => Err(AddrError::Unsupported("NodeLocator")),
        }
    }
}

impl From<RemoteNodeAddr> for NodeLocator {
    fn from(node_addr: RemoteNodeAddr) -> NodeLocator {
        match node_addr.remote_addr {
            RemoteSocketAddr::Ftcp(addr) => NodeLocator::Native(
                node_addr.node_id,
                addr.address,
                Some(addr.port),
            ),
            #[cfg(feature = "zmq")]
            RemoteSocketAddr::Zmq(addr) => NodeLocator::ZmqTcpEncrypted(
                node_addr.node_id,
                ZmqType::Rep,
                InetSocketAddr::from(addr)
                    .address
                    .try_into()
                    .expect("Conversion from just generated type can't fail"),
                Some(addr.port()),
            ),
            RemoteSocketAddr::Http(addr) => NodeLocator::Http(
                node_addr.node_id,
                addr.address,
                Some(addr.port),
            ),
            #[cfg(feature = "websocket")]
            RemoteSocketAddr::Websocket(addr) => NodeLocator::Websocket(
                node_addr.node_id,
                addr.address,
                Some(addr.port),
            ),
            RemoteSocketAddr::Smtp(addr) => {
                NodeLocator::Text(node_addr.node_id)
            }
        }
    }
}

impl From<RemoteNodeAddr> for RemoteSocketAddr {
    fn from(addr: RemoteNodeAddr) -> RemoteSocketAddr {
        addr.remote_addr
    }
}

// TODO: (future) Re-implement with const generics once this rust language
//       feature will be stabilized and released

/// Trait allowing generic function arguments for application-level
/// implementations knowing default protocol port
pub trait ToNodeAddr {
    /// Constructs [`NodeEndpoint`] from an internal data with a default port
    /// put in place when the port details were not given is such structures
    /// as [`NodeLocator`]
    ///
    /// # Returns
    /// * `None`, if string conversion fails with [`ParseError`]
    /// * `Some(`[`NodeEndpoint`]`)` otherwise
    fn to_node_endpoint(&self, default_port: u16) -> Option<NodeAddr>;
}

impl ToNodeAddr for NodeAddr {
    #[inline]
    fn to_node_endpoint(&self, default_port: u16) -> Option<NodeAddr> {
        Some(self.clone())
    }
}

impl ToNodeAddr for RemoteNodeAddr {
    #[inline]
    fn to_node_endpoint(&self, default_port: u16) -> Option<NodeAddr> {
        Some(self.clone().into())
    }
}

impl ToNodeAddr for LocalSocketAddr {
    #[inline]
    fn to_node_endpoint(&self, default_port: u16) -> Option<NodeAddr> {
        Some(self.clone().into())
    }
}

impl ToNodeAddr for NodeLocator {
    #[inline]
    fn to_node_endpoint(&self, default_port: u16) -> Option<NodeAddr> {
        self.with_port(default_port).try_into().ok()
    }
}

impl ToNodeAddr for String {
    #[inline]
    fn to_node_endpoint(&self, default_port: u16) -> Option<NodeAddr> {
        self.as_str().to_node_endpoint(default_port)
    }
}

impl ToNodeAddr for &str {
    #[inline]
    fn to_node_endpoint(&self, default_port: u16) -> Option<NodeAddr> {
        NodeAddr::try_from(NodeLocator::from_str(&self).ok()?).ok()
    }
}

impl<T> ToNodeAddr for &T
where
    T: ToNodeAddr,
{
    #[inline]
    fn to_node_endpoint(&self, default_port: u16) -> Option<NodeAddr> {
        (*self).to_node_endpoint(default_port)
    }
}

/// Trait allowing generic function arguments for application-level
/// implementations knowing default protocol port
pub trait ToRemoteNodeAddr {
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
    fn to_node_addr(&self, default_port: u16) -> Option<RemoteNodeAddr>;
}

impl ToRemoteNodeAddr for RemoteNodeAddr {
    #[inline]
    fn to_node_addr(&self, default_port: u16) -> Option<RemoteNodeAddr> {
        Some(self.clone())
    }
}

impl ToRemoteNodeAddr for NodeLocator {
    #[inline]
    fn to_node_addr(&self, default_port: u16) -> Option<RemoteNodeAddr> {
        self.with_port(default_port).try_into().ok()
    }
}

impl ToRemoteNodeAddr for String {
    #[inline]
    fn to_node_addr(&self, default_port: u16) -> Option<RemoteNodeAddr> {
        self.as_str().to_node_addr(default_port)
    }
}

impl ToRemoteNodeAddr for &str {
    #[inline]
    fn to_node_addr(&self, default_port: u16) -> Option<RemoteNodeAddr> {
        RemoteNodeAddr::from_str(&self)
            .or_else(|_| {
                RemoteNodeAddr::from_str(&format!("{}:{}", self, default_port))
            })
            .ok()
    }
}

impl<T> ToRemoteNodeAddr for &T
where
    T: ToRemoteNodeAddr,
{
    #[inline]
    fn to_node_addr(&self, default_port: u16) -> Option<RemoteNodeAddr> {
        (*self).to_node_addr(default_port)
    }
}

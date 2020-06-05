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

use core::convert::TryFrom;
#[cfg(feature = "url")]
use core::convert::TryInto;
use core::fmt::Debug;
#[cfg(feature = "url")]
use core::fmt::{Display, Formatter};
#[cfg(feature = "url")]
use core::str::FromStr;
use std::net::{AddrParseError, IpAddr};
use std::path::PathBuf;
#[cfg(feature = "url")]
use url::Url;

use bitcoin::secp256k1;

use super::NodeAddr;
use crate::internet::{InetAddr, InetSocketAddr};
use crate::lnp::transport::zmq::ApiType as ZmqType;

/// Universal Node Locator (from LNPBP-19)
/// NB: DNS addressing is not used since it is considered insecure in terms of
/// censorship resistance.
#[derive(Clone)]
pub enum NodeLocator {
    /// Native Lightning network connection: uses end-to-end encryption and
    /// runs on top of either TCP or Tor socket
    /// # URL Scheme
    /// lnp://<node-id>@<ip>|<onion>:<port>
    Native(secp256k1::PublicKey, InetAddr, Option<u16>),

    /// UDP-based connection that uses UDP packets instead of TCP. Can't work
    /// with Tor, but may use UDP hole punching in a secure way, since the
    /// connection is still required to be encrypted.
    /// # URL Scheme
    /// lnp-udp://<node-id>@<ip>:<port>
    Udp(secp256k1::PublicKey, IpAddr, Option<u16>),

    /// Local (for inter-process communication based on POSIX sockets)
    /// connection without encryption. Relies on ZMQ IPC sockets internally;
    /// specific socket pair for ZMQ is provided via query parameter
    /// # URL Schema
    /// lnp-zmq:<file-path>?api=<p2p|rpc|sub>
    #[cfg(feature = "zmq")]
    Ipc(PathBuf, ZmqType),

    /// In-process communications (between threads of the same process using
    /// Mutex'es and other sync managing routines) without encryption.
    /// Relies on ZMQ IPC sockets internally; specific socket pair for ZMQ is
    /// provided via query parameter
    /// # URL Schema
    /// lnp-zmq:?api=<p2p|rpc|sub>#<id>
    #[cfg(feature = "zmq")]
    Inproc(String, zmq::Context, ZmqType),

    /// SHOULD be used only for DMZ area connections; otherwise Native or
    /// Webscoket-based connection MUST be used
    /// # URL Schema
    /// lnp-zmq://<node-id>@<ip>|<onion>:<port>/?api=<p2p|rpc|sub>
    #[cfg(feature = "zmq")]
    ZmqEncrypted(secp256k1::PublicKey, ZmqType, IpAddr, Option<u16>),

    /// SHOULD be used only for DMZ area connections; otherwise Native or
    /// Webscoket-based connection MUST be used
    /// # URL Schema
    /// lnp-zmq://<ip>|<onion>:<port>/?api=<p2p|rpc|sub>
    #[cfg(feature = "zmq")]
    ZmqUnencrypted(ZmqType, IpAddr, Option<u16>),

    /// # URL Schema
    /// lnp-ws://<node-id>@<ip>|<onion>:<port>
    #[cfg(feature = "websocket")]
    Websocket(secp256k1::PublicKey, IpAddr, Option<u16>),
}

impl NodeLocator {
    pub fn with_port(self, port: u16) -> Self {
        match self {
            NodeLocator::Native(a, b, _) => NodeLocator::Native(a, b, Some(port)),
            NodeLocator::Udp(a, b, _) => NodeLocator::Udp(a, b, Some(port)),
            #[cfg(feature = "zmq")]
            NodeLocator::ZmqEncrypted(a, b, c, _) => NodeLocator::ZmqEncrypted(a, b, c, Some(port)),
            #[cfg(feature = "zmq")]
            NodeLocator::ZmqUnencrypted(a, b, _) => NodeLocator::ZmqUnencrypted(a, b, Some(port)),
            #[cfg(feature = "websocket")]
            NodeLocator::Websocket(a, b, _) => NodeLocator::Websocket(a, b, Some(port)),
            _ => self,
        }
    }
}

impl From<NodeAddr> for NodeLocator {
    fn from(addr: NodeAddr) -> Self {
        Self::Native(
            addr.node_id,
            addr.inet_addr.address,
            Some(addr.inet_addr.port),
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Display, Error)]
#[display_from(Debug)]
pub enum ConversionError {
    NoPort,
    UnsupportedType,
}

impl TryFrom<NodeLocator> for NodeAddr {
    type Error = ConversionError;

    fn try_from(locator: NodeLocator) -> Result<Self, Self::Error> {
        match locator {
            NodeLocator::Native(_, _, None) => Err(ConversionError::NoPort),
            NodeLocator::Native(pubkey, address, Some(port)) => Ok(NodeAddr {
                node_id: pubkey,
                inet_addr: InetSocketAddr { address, port },
            }),
            _ => Err(ConversionError::UnsupportedType),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display, Error, From)]
#[display_from(Debug)]
pub enum UrlError {
    MalformedUrl,
    UnknownScheme(String),
    HostRequired,
    InvalidPubkey,
    #[derive_from]
    InvalidHost(String),
    #[derive_from(AddrParseError)]
    InvalidIp,
    InvalidZmqType(String),
    ApiTypeRequired,
    InprocRequireZmqContext,
}

#[cfg(feature = "url")]
impl TryFrom<Url> for NodeLocator {
    type Error = UrlError;

    fn try_from(url: Url) -> Result<Self, Self::Error> {
        let pubkey = secp256k1::PublicKey::from_str(url.username());
        let host = url.host_str();
        let ip = host.map(|host| host.parse::<IpAddr>());
        let port = url.port();
        match url.scheme() {
            "lnp" => Ok(NodeLocator::Native(
                pubkey.map_err(|_| UrlError::InvalidPubkey)?,
                host.ok_or(UrlError::HostRequired)?.parse::<InetAddr>()?,
                port,
            )),
            "lnp-udp" => Ok(NodeLocator::Udp(
                pubkey.map_err(|_| UrlError::InvalidPubkey)?,
                ip.ok_or(UrlError::HostRequired)??,
                port,
            )),
            #[cfg(feature = "websocket")]
            "lnp-ws" => Ok(NodeLocator::Websocket(
                pubkey.map_err(|_| UrlError::InvalidPubkey)?,
                ip.ok_or(UrlError::HostRequired)??,
                port,
            )),
            #[cfg(feature = "zmq")]
            "lnp-zmq" => {
                let zmq_type = match url
                    .query_pairs()
                    .find_map(|(key, val)| if key == "api" { Some(val) } else { None })
                    .ok_or(UrlError::ApiTypeRequired)?
                    .to_ascii_lowercase()
                    .as_str()
                {
                    "p2p" => Ok(ZmqType::PeerConnecting),
                    "rpc" => Ok(ZmqType::Client),
                    "sub" => Ok(ZmqType::Subscribe),
                    unknown => Err(UrlError::InvalidZmqType(unknown.to_string())),
                }?;
                Ok(match (ip, pubkey) {
                    (Some(Err(_)), _) => Err(UrlError::InvalidIp)?,
                    (_, Err(_)) if !url.username().is_empty() => Err(UrlError::InvalidIp)?,
                    (Some(Ok(ip)), Ok(pubkey)) => {
                        NodeLocator::ZmqEncrypted(pubkey, zmq_type, ip, port)
                    }
                    (Some(Ok(ip)), _) => NodeLocator::ZmqUnencrypted(zmq_type, ip, port),
                    (None, _) => {
                        if url.path().is_empty() {
                            Err(UrlError::InprocRequireZmqContext)?
                        }
                        // TODO: Check path data validity
                        let path = PathBuf::from(url.path());
                        NodeLocator::Ipc(path, zmq_type)
                    }
                })
            }
            unknown => Err(UrlError::UnknownScheme(unknown.to_string())),
        }
    }
}

#[cfg(feature = "url")]
impl From<&NodeLocator> for Url {
    fn from(locator: &NodeLocator) -> Self {
        const ERR: &'static str = "URL construction incosistency for NodeLocator";
        match locator {
            NodeLocator::Native(pubkey, inet, port) => {
                let mut url = Url::parse(&format!("lnp://{}@{}", pubkey, inet))
                    .expect("Internal URL construction error");
                url.set_port(port.clone()).expect(ERR);
                url
            }
            NodeLocator::Udp(pubkey, ip, port) => {
                let mut url = Url::parse(&format!("lnp-udp://{}@{}", pubkey, ip))
                    .expect("Internal URL construction error");
                url.set_port(port.clone()).expect(ERR);
                url
            }
            #[cfg(feature = "zmq")]
            NodeLocator::Ipc(path, zmq_type) => Url::parse(&format!(
                "lnp-zmq:{}?api={}",
                path.to_str().unwrap(),
                zmq_type
            ))
            .expect("Internal URL construction error"),
            #[cfg(feature = "zmq")]
            NodeLocator::Inproc(name, _, zmq_type) => {
                Url::parse(&format!("lnp-zmq:?api={}#{}", zmq_type, name))
                    .expect("Internal URL construction error")
            }
            #[cfg(feature = "zmq")]
            NodeLocator::ZmqEncrypted(pubkey, zmq_type, ip, port) => {
                let mut url = Url::parse(&format!("lnp-zmq://{}@{}/?api={}", pubkey, ip, zmq_type))
                    .expect("Internal URL construction error");
                url.set_port(port.clone()).expect(ERR);
                url
            }
            #[cfg(feature = "zmq")]
            NodeLocator::ZmqUnencrypted(zmq_type, ip, port) => {
                let mut url = Url::parse(&format!("lnp-zmq://{}/?api={}", ip, zmq_type))
                    .expect("Internal URL construction error");
                url.set_port(port.clone()).expect(ERR);
                url
            }
            #[cfg(feature = "websocket")]
            NodeLocator::Websocket(pubkey, ip, port) => {
                let mut url = Url::parse(&format!("lnp-ws://{}@{}", pubkey, ip))
                    .expect("Internal URL construction error");
                url.set_port(port.clone()).expect(ERR);
                url
            }
        }
    }
}

#[cfg(feature = "url")]
impl Debug for NodeLocator {
    fn fmt(&self, f: &mut Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[cfg(feature = "url")]
impl Display for NodeLocator {
    fn fmt(&self, f: &mut Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "{}", Url::from(self))
    }
}

#[cfg(feature = "url")]
impl FromStr for NodeLocator {
    type Err = UrlError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Url::from_str(s)
            .map_err(|_| UrlError::MalformedUrl)?
            .try_into()
    }
}

impl PartialEq for NodeLocator {
    fn eq(&self, other: &Self) -> bool {
        use NodeLocator::*;
        match (self, other) {
            (Native(a1, a2, a3), Native(b1, b2, b3)) => a1 == b1 && a2 == b2 && a3 == b3,
            (Udp(a1, a2, a3), Udp(b1, b2, b3)) => a1 == b1 && a2 == b2 && a3 == b3,
            #[cfg(feature = "websocket")]
            (Websocket(a1, a2, a3), Websocket(b1, b2, b3)) => a1 == b1 && a2 == b2 && a3 == b3,
            #[cfg(feature = "zmq")]
            (Ipc(a1, a2), Ipc(b1, b2)) => a1 == b1 && a2 == b2,
            #[cfg(feature = "zmq")]
            (Inproc(a1, _, a2), Inproc(b1, _, b2)) => a1 == b1 && a2 == b2,
            #[cfg(feature = "zmq")]
            (ZmqUnencrypted(a1, a2, a3), ZmqUnencrypted(b1, b2, b3)) => {
                a1 == b1 && a2 == b2 && a3 == b3
            }
            #[cfg(feature = "zmq")]
            (ZmqEncrypted(a1, a2, a3, a4), ZmqEncrypted(b1, b2, b3, b4)) => {
                a1 == b1 && a2 == b2 && a3 == b3 && a4 == b4
            }
            (_, _) => false,
        }
    }
}

impl Eq for NodeLocator {}

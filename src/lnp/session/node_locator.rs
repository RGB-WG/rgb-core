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

use amplify::internet::{InetAddr, InetSocketAddr};
use bitcoin::secp256k1;

use super::{node_addr, NodeAddr};
use crate::lnp::transport::zmq::ApiType as ZmqType;

/// Universal Node Locator for LNP protocol
/// (from [LNPBP-19](https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0019.md))
/// NB: DNS addressing is not used since it is considered insecure in terms of
///     censorship resistance.
#[derive(Clone)]
pub enum NodeLocator {
    /// Native Lightning network connection: uses end-to-end encryption and
    /// runs on top of either TCP or Tor socket
    ///
    /// # URL Scheme
    /// lnp://<node-id>@<ip>|<onion>:<port>
    Native(secp256k1::PublicKey, InetAddr, Option<u16>),

    /// UDP-based connection that uses UDP packets instead of TCP. Can't work
    /// with Tor, but may use UDP hole punching in a secure way, since the
    /// connection is still required to be encrypted.
    ///
    /// # URL Scheme
    /// lnpu://<node-id>@<ip>:<port>
    Udp(secp256k1::PublicKey, IpAddr, Option<u16>),

    /// Local (for inter-process communication based on POSIX sockets)
    /// connection without encryption. Relies on ZMQ IPC sockets internally;
    /// specific socket pair for ZMQ is provided via query parameter
    ///
    /// # URL Schema
    /// lnpz:<file-path>?api=<p2p|rpc|sub>
    #[cfg(feature = "zmq")]
    Ipc(PathBuf, ZmqType),

    /// LNP protocol supports in-process communications (between threads of the
    /// same process using Mutex'es and other sync managing routines) without
    /// encryption. It relies on ZMQ IPC sockets internally. However, such
    /// connection can be done only withing the same process, and can't be
    /// represented in the form of URL. It requires presence of ZMQ context
    /// object, which can't be encoded as a string.
    #[cfg(feature = "zmq")]
    Inproc(String, zmq::Context, ZmqType),

    /// SHOULD be used only for DMZ area connections; otherwise
    /// [`NodeLocator::Native`] or [`NodeLocator::Websocket`] connection
    /// MUST be used
    ///
    /// # URL Schema
    /// lnpz://<node-id>@<ip>|<onion>:<port>/?api=<p2p|rpc|sub>
    #[cfg(feature = "zmq")]
    ZmqEncrypted(secp256k1::PublicKey, ZmqType, IpAddr, Option<u16>),

    /// SHOULD be used only for DMZ area connections; otherwise
    /// [`NodeLocator::Native`] or [`NodeLocator::Websocket`] connection
    /// MUST be used
    ///
    /// # URL Schema
    /// lnpz://<ip>|<onion>:<port>/?api=<p2p|rpc|sub>
    #[cfg(feature = "zmq")]
    ZmqUnencrypted(ZmqType, IpAddr, Option<u16>),

    /// # URL Schema
    /// lnpws://<node-id>@<ip>|<onion>:<port>
    #[cfg(feature = "websockets")]
    Websocket(secp256k1::PublicKey, IpAddr, Option<u16>),

    /// Text (Bech32-based) connection for high latency or non-interactive
    /// protocols. Can work with SMPT, for mesh and satellite networks – or
    /// with other mediums of communications (chat messages, QR codes etc).
    ///
    /// # URL Schema
    /// lnpt://<node-id>@
    Text(secp256k1::PublicKey),
}

impl NodeLocator {
    /// Adds port information to the node locator, if it can contain port.
    /// In case if it does not, performs no action. Returns cloned `Self` with
    /// the updated data.
    pub fn with_port(&self, port: u16) -> Self {
        match self.clone() {
            NodeLocator::Native(a, b, _) => {
                NodeLocator::Native(a, b, Some(port))
            }
            NodeLocator::Udp(a, b, _) => NodeLocator::Udp(a, b, Some(port)),
            #[cfg(feature = "zmq")]
            NodeLocator::ZmqEncrypted(a, b, c, _) => {
                NodeLocator::ZmqEncrypted(a, b, c, Some(port))
            }
            #[cfg(feature = "zmq")]
            NodeLocator::ZmqUnencrypted(a, b, _) => {
                NodeLocator::ZmqUnencrypted(a, b, Some(port))
            }
            #[cfg(feature = "websockets")]
            NodeLocator::Websocket(a, b, _) => {
                NodeLocator::Websocket(a, b, Some(port))
            }
            me => me,
        }
    }

    /// Returns URL schema name for the given node locator type
    pub fn scheme(&self) -> String {
        match self {
            NodeLocator::Native(_, _, _) => s!("lnp"),
            NodeLocator::Udp(_, _, _) => s!("lnpu"),
            NodeLocator::Ipc(_, _) | NodeLocator::Inproc(_, _, _) => s!("lnpz"),
            #[cfg(feature = "zmq")]
            NodeLocator::ZmqEncrypted(_, _, _, _)
            | NodeLocator::ZmqUnencrypted(_, _, _) => s!("lnpz"),
            #[cfg(feature = "websockets")]
            NodeLocator::Websocket(_, _, _) => s!("lnpws"),
            NodeLocator::Text(_) => s!("lnpt"),
        }
    }

    /// Returns URL string representation for a given node locator. If you need
    /// full URL address, plsease use [`Url::from()`] instead (this will require
    /// `url` feature for LNP/BP Core Library).
    pub fn to_url_string(&self) -> String {
        match self {
            NodeLocator::Native(pubkey, inet, port) => {
                let p = port.map(|x| format!(":{}", x)).unwrap_or_default();
                format!("{}://{}@{}{}", self.scheme(), pubkey, inet, p)
            }
            NodeLocator::Udp(pubkey, ip, port) => {
                let p = port.map(|x| format!(":{}", x)).unwrap_or_default();
                format!("{}://{}@{}{}", self.scheme(), pubkey, ip, p)
            }
            #[cfg(feature = "zmq")]
            NodeLocator::Ipc(path, zmq_type) => format!(
                "{}:{}?api={}",
                self.scheme(),
                path.to_str().unwrap(),
                zmq_type.api_name()
            ),
            #[cfg(feature = "zmq")]
            NodeLocator::Inproc(name, _, zmq_type) => format!(
                "{}:?api={}#{}",
                self.scheme(),
                zmq_type.api_name(),
                name
            ),
            #[cfg(feature = "zmq")]
            NodeLocator::ZmqEncrypted(pubkey, zmq_type, ip, port) => {
                let p = port.map(|x| format!(":{}", x)).unwrap_or_default();
                format!(
                    "{}://{}@{}{}/?api={}",
                    self.scheme(),
                    pubkey,
                    ip,
                    p,
                    zmq_type.api_name()
                )
            }
            #[cfg(feature = "zmq")]
            NodeLocator::ZmqUnencrypted(zmq_type, ip, port) => {
                let p = port.map(|x| format!(":{}", x)).unwrap_or_default();
                format!(
                    "{}://{}{}/?api={}",
                    self.scheme(),
                    ip,
                    p,
                    zmq_type.api_name()
                )
            }
            #[cfg(feature = "websockets")]
            NodeLocator::Websocket(pubkey, ip, port) => {
                let p = port.map(|x| format!(":{}", x)).unwrap_or_default();
                format!("{}://{}@{}{}", self.scheme(), pubkey, ip, p)
            }
            NodeLocator::Text(pubkey) => {
                format!("{}://{}", self.scheme(), pubkey)
            }
        }
    }

    /// Parses [`NodeLocator`] into it's optional components, returned as a
    /// single tuple of optionals:
    /// 1) node public key,
    /// 2) [`InetAddr`] of the node,
    /// 3) port
    /// 4) file path or POSIX socket name
    /// 5) [`ZmqType`] parameter for ZMQ based locators
    pub fn components(
        &self,
    ) -> (
        Option<secp256k1::PublicKey>,
        Option<InetAddr>,
        Option<u16>,
        Option<String>, /* file or named socket */
        Option<ZmqType>,
    ) {
        match self {
            NodeLocator::Native(pubkey, inet, port) => {
                (Some(*pubkey), Some(*inet), *port, None, None)
            }
            NodeLocator::Udp(pubkey, ip, port) => {
                (Some(*pubkey), Some(InetAddr::from(*ip)), *port, None, None)
            }
            NodeLocator::Ipc(file, api) => (
                None,
                None,
                None,
                file.to_str().map(ToString::to_string),
                Some(*api),
            ),
            NodeLocator::Inproc(name, _, api) => {
                (None, None, None, Some(name.clone()), Some(*api))
            }
            #[cfg(feature = "zmq")]
            NodeLocator::ZmqEncrypted(pubkey, api, ip, port) => (
                Some(*pubkey),
                Some(InetAddr::from(*ip)),
                *port,
                None,
                Some(*api),
            ),
            #[cfg(feature = "zmq")]
            NodeLocator::ZmqUnencrypted(api, ip, port) => {
                (None, Some(InetAddr::from(*ip)), *port, None, Some(*api))
            }
            #[cfg(feature = "websockets")]
            NodeLocator::Websocket(pubkey, ip, port) => {
                (Some(*pubkey), Some(InetAddr::from(*ip)), *port, None, None)
            }
            NodeLocator::Text(pubkey) => {
                (Some(*pubkey), None, None, None, None)
            }
        }
    }

    /// Returns node id for the given locator, if any, or [`Option::None`]
    /// otherwise
    #[inline]
    pub fn node_id(&self) -> Option<secp256k1::PublicKey> {
        self.components().0
    }

    /// Returns [`InetAddr`] for the given locator, if any, or [`Option::None`]
    /// otherwise
    #[inline]
    pub fn inet_addr(&self) -> Option<InetAddr> {
        self.components().1
    }

    /// Returns port number for the given locator, if any, or [`Option::None`]
    /// otherwise
    #[inline]
    pub fn port(&self) -> Option<u16> {
        self.components().2
    }

    /// Returns socket name if for the given locator, if any, or
    /// [`Option::None`] otherwise
    #[inline]
    pub fn socket_name(&self) -> Option<String> {
        self.components().3
    }

    /// Returns [`ZmqType`] for the given locator, if any, or
    /// [`Option::None`] otherwise
    #[inline]
    pub fn api_type(&self) -> Option<ZmqType> {
        self.components().4
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

/// Error converting [`NodeLocator`] to [`NodeAddr`]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum ConversionError {
    /// No port information is provided; use [`NodeLocator::with_port`] method
    /// before calling the conversion
    NoPort,

    /// Node locator of the given type can't be represented as [`NodeAddr`].
    /// Only [`NodeLocator::Native`] addresses can be converted.
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

/// Errors from parting string data into [`NodeLocator`] type
#[derive(Clone, PartialEq, Eq, Hash, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum ParseError {
    /// Can't parse URL from the given string
    MalformedUrl,

    /// The provided URL scheme {_0} was not recognized
    UnknownUrlScheme(String),

    /// No host information found in URL, while it is required for the given
    /// schema
    HostRequired,

    /// Invalid public key data representing node id
    #[from(secp256k1::Error)]
    InvalidPubkey,

    /// Unrecognized host information ({_0}).
    /// NB: DNS addressing is not used since it is considered insecure in terms
    ///     of censorship resistance, so you need to provide it in a form of
    ///     either IPv4, IPv6 address or Tor v2, v3 address (no `.onion`
    /// suffix)
    #[from]
    InvalidHost(String),

    /// Used schema must not contain information about host
    HostPresent,

    /// Used schema must not contain information about port
    PortPresent,

    /// Invalid IP information
    #[from(AddrParseError)]
    InvalidIp,

    /// Unsupported ZMQ API type ({_0}). List of supported APIs:
    /// - `rpc`
    /// - `p2p`
    /// - `sub`
    InvalidZmqType(String),

    /// No ZMQ API type information for URL scheme that requires one.
    ApiTypeRequired,

    /// Creation of `Inproc` ZMQ locator requires ZMQ context, while no context
    /// is provided.
    InprocRequireZmqContext,

    /// Can't read string as a proper node address: it must be in
    /// `<node_id>@<node_inet_addr>[:<port>]` format, where <node_inet_addr>
    /// may be IPv4, IPv6 or Tor v3, v2 address (no `.onion` suffix)
    #[from]
    NodeAddr(node_addr::ParseError),
}

#[cfg(feature = "url")]
impl TryFrom<Url> for NodeLocator {
    type Error = ParseError;

    fn try_from(url: Url) -> Result<Self, Self::Error> {
        let pubkey = secp256k1::PublicKey::from_str(url.username());
        let host = url.host_str();
        let ip = host.map(|host| {
            host.parse::<IpAddr>()
                .map_err(|_| ParseError::InvalidHost(host.to_string()))
        });
        let port = url.port();
        match url.scheme() {
            "lnp" => Ok(NodeLocator::Native(
                pubkey?,
                host.ok_or(ParseError::HostRequired)?.parse::<InetAddr>()?,
                port,
            )),
            "lnpu" => Ok(NodeLocator::Udp(
                pubkey?,
                ip.ok_or(ParseError::HostRequired)??,
                port,
            )),
            #[cfg(feature = "websockets")]
            "lnpws" => Ok(NodeLocator::Websocket(
                pubkey?,
                ip.ok_or(ParseError::HostRequired)??,
                port,
            )),
            #[cfg(feature = "zmq")]
            "lnpz" => {
                let zmq_type = match url
                    .query_pairs()
                    .find_map(
                        |(key, val)| {
                            if key == "api" {
                                Some(val)
                            } else {
                                None
                            }
                        },
                    )
                    .ok_or(ParseError::ApiTypeRequired)?
                    .to_ascii_lowercase()
                    .as_str()
                {
                    "p2p" => Ok(ZmqType::PeerConnecting),
                    "rpc" => Ok(ZmqType::Client),
                    "sub" => Ok(ZmqType::Subscribe),
                    unknown => {
                        Err(ParseError::InvalidZmqType(unknown.to_string()))
                    }
                }?;
                Ok(match (ip, pubkey) {
                    (Some(Err(_)), _) => Err(ParseError::InvalidIp)?,
                    (_, Err(_)) if !url.username().is_empty() => {
                        Err(ParseError::InvalidIp)?
                    }
                    (Some(Ok(ip)), Ok(pubkey)) => {
                        NodeLocator::ZmqEncrypted(pubkey, zmq_type, ip, port)
                    }
                    (Some(Ok(ip)), _) => {
                        NodeLocator::ZmqUnencrypted(zmq_type, ip, port)
                    }
                    (None, _) => {
                        if url.path().is_empty() {
                            Err(ParseError::InprocRequireZmqContext)?
                        }
                        // TODO: Check path data validity
                        let path = PathBuf::from(url.path());
                        NodeLocator::Ipc(path, zmq_type)
                    }
                })
            }
            "lnpt" => {
                // In this URL scheme we must not use IP address
                if let Ok(pubkey) = pubkey {
                    Err(ParseError::HostPresent)?
                }
                // In this URL scheme we must not use IP address
                if let Some(port) = port {
                    Err(ParseError::PortPresent)?
                }
                if let Some(host) = host {
                    Ok(NodeLocator::Text(secp256k1::PublicKey::from_str(host)?))
                } else {
                    Err(ParseError::InvalidPubkey)?
                }
            }
            unknown => Err(ParseError::UnknownUrlScheme(unknown.to_string())),
        }
    }
}

#[cfg(feature = "url")]
impl From<&NodeLocator> for Url {
    fn from(locator: &NodeLocator) -> Self {
        Url::parse(&locator.to_url_string())
            .expect("Internal URL construction error")
    }
}

impl Display for NodeLocator {
    fn fmt(&self, f: &mut Formatter<'_>) -> ::core::fmt::Result {
        if f.alternate() {
            self.node_id()
                .map(|id| write!(f, "{}", id))
                .unwrap_or(Ok(()))?;
            if let Some(addr) = self.inet_addr() {
                write!(f, "@{}", addr)?;
                self.port()
                    .map(|port| write!(f, ":{}", port))
                    .unwrap_or(Ok(()))?;
            } else {
                f.write_str(&self.socket_name().expect("Socket name is always known if internet address is not given"))?;
            }
            if let Some(api) = self.api_type() {
                write!(f, "?api={}", api.api_name())?;
            }
            Ok(())
        } else {
            #[cfg(feature = "url")]
            {
                write!(f, "{}", Url::from(self))
            }
            #[cfg(not(feature = "url"))]
            {
                f.write_str(&self.to_url_string())
            }
        }
    }
}

impl Debug for NodeLocator {
    fn fmt(&self, f: &mut Formatter<'_>) -> ::core::fmt::Result {
        match self {
            NodeLocator::Native(pubkey, inet, port) => writeln!(
                f,
                "NodeLocator::Native({:?}, {:?}, {:?})",
                pubkey, inet, port
            ),
            NodeLocator::Udp(pubkey, ip, port) => writeln!(
                f,
                "NodeLocator::Udp({:?}, {:?}, {:?})",
                pubkey, ip, port
            ),
            NodeLocator::Ipc(file, api) => {
                writeln!(f, "NodeLocator::Ipc({:?}, {:?})", file, api)
            }
            NodeLocator::Inproc(name, _, api) => writeln!(
                f,
                "NodeLocator::Inproc({:?}, <zmq::Context>, {:?})",
                name, api
            ),
            #[cfg(feature = "zmq")]
            NodeLocator::ZmqEncrypted(pubkey, api, ip, port) => writeln!(
                f,
                "NodeLocator::ZmqEncrypted({:?}, {:?}, {:?}, {:?})",
                pubkey, api, ip, port
            ),
            #[cfg(feature = "zmq")]
            NodeLocator::ZmqUnencrypted(api, ip, port) => writeln!(
                f,
                "NodeLocator::ZmqUnencrypted({:?}, {:?}, {:?})",
                api, ip, port
            ),
            #[cfg(feature = "websockets")]
            NodeLocator::Websocket(pubkey, ip, port) => writeln!(
                f,
                "NodeLocator::Websocket({:?}, {:?}, {:?})",
                pubkey, ip, port
            ),
            NodeLocator::Text(pubkey) => {
                writeln!(f, "NodeLocator::Text({:?})", pubkey)
            }
        }
    }
}

#[cfg(feature = "url")]
impl FromStr for NodeLocator {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut s = s.to_string();
        if vec!["lnp:", "lnpu:", "lnpz:", "lnpws:", "lnpt:"]
            .into_iter()
            .find(|p| s.starts_with(*p))
            .is_none()
        {
            s = format!("lnp://{}", s);
        }
        Url::from_str(&s)
            .map_err(|_| ParseError::MalformedUrl)?
            .try_into()
    }
}

impl PartialEq for NodeLocator {
    fn eq(&self, other: &Self) -> bool {
        use NodeLocator::*;

        fn api_eq(a: &ZmqType, b: &ZmqType) -> bool {
            a == b
                || (*a == ZmqType::PeerListening
                    && *b == ZmqType::PeerConnecting)
                || (*b == ZmqType::PeerListening
                    && *a == ZmqType::PeerConnecting)
        }

        match (self, other) {
            (Native(a1, a2, a3), Native(b1, b2, b3)) => {
                a1 == b1 && a2 == b2 && a3 == b3
            }
            (Udp(a1, a2, a3), Udp(b1, b2, b3)) => {
                a1 == b1 && a2 == b2 && a3 == b3
            }
            #[cfg(feature = "websockets")]
            (Websocket(a1, a2, a3), Websocket(b1, b2, b3)) => {
                a1 == b1 && a2 == b2 && a3 == b3
            }
            #[cfg(feature = "zmq")]
            (Ipc(a1, a2), Ipc(b1, b2)) => a1 == b1 && api_eq(a2, b2),
            #[cfg(feature = "zmq")]
            (Inproc(a1, _, a2), Inproc(b1, _, b2)) => {
                a1 == b1 && api_eq(a2, b2)
            }
            #[cfg(feature = "zmq")]
            (ZmqUnencrypted(a1, a2, a3), ZmqUnencrypted(b1, b2, b3)) => {
                api_eq(a1, b1) && a2 == b2 && a3 == b3
            }
            #[cfg(feature = "zmq")]
            (ZmqEncrypted(a1, a2, a3, a4), ZmqEncrypted(b1, b2, b3, b4)) => {
                a1 == b1 && api_eq(a2, b2) && a3 == b3 && a4 == b4
            }
            (Text(pubkey1), Text(pubkey2)) => pubkey1 == pubkey2,
            (_, _) => false,
        }
    }
}

impl Eq for NodeLocator {}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_native() {
        let pubkey1 = secp256k1::PublicKey::from_str(
            "022e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af"
        ).unwrap();
        let pubkey2 = secp256k1::PublicKey::from_str(
            "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af"
        ).unwrap();
        let inet1 = InetAddr::from_str("127.0.0.1").unwrap();
        let inet2 = InetAddr::from_str("127.0.0.2").unwrap();
        let locator1 = NodeLocator::Native(pubkey1, inet1, None);
        let locator2 = NodeLocator::Native(pubkey2, inet2, None);

        assert_ne!(locator1, locator2);
        assert_eq!(locator1, locator1.clone());
        assert_eq!(locator2, locator2.clone());

        assert_eq!(locator1.scheme(), "lnp");
        assert_eq!(locator1.node_id(), Some(pubkey1));
        assert_eq!(locator1.port(), None);
        assert_eq!(locator1.api_type(), None);
        assert_eq!(locator1.inet_addr(), Some(inet1));
        assert_eq!(locator1.socket_name(), None);
        let locator_with_port = locator1.with_port(24);
        assert_eq!(locator_with_port.port(), Some(24));

        let socket_addr = InetSocketAddr {
            address: inet1,
            port: 24,
        };
        let node_addr = NodeAddr {
            node_id: pubkey1,
            inet_addr: socket_addr,
        };
        let l = NodeLocator::from(node_addr);
        assert_eq!(l, locator_with_port);
        assert_ne!(l, locator1);
        assert_eq!(
            NodeAddr::try_from(locator1.clone()),
            Err(ConversionError::NoPort)
        );
        assert_eq!(
            NodeAddr::try_from(locator_with_port.clone()),
            Ok(node_addr)
        );

        assert_eq!(
            locator1.to_url_string(),
            "lnp://022e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af@127.0.0.1"
        );
        assert_eq!(
            locator_with_port.to_url_string(),
            "lnp://022e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af@127.0.0.1:24"
        );
        assert_eq!(
            l.to_url_string(),
            "lnp://022e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af@127.0.0.1:24"
        );

        #[cfg(feature = "url")]
        {
            assert_eq!(
                NodeLocator::from_str(
                    "lnp://022e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af@127.0.0.1"
                ).unwrap(),
                locator1
            );
            assert_eq!(
                NodeLocator::from_str(
                    "022e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af@127.0.0.1:24"
                ).unwrap(),
                locator_with_port
            );

            #[cfg(feature = "tor")]
            {
                use torut::onion::{OnionAddressV2, OnionAddressV3};

                assert_eq!(
                    NodeLocator::from_str(
                        "lnp://022e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af\
                        @32zzibxmqi2ybxpqyggwwuwz7a3lbvtzoloti7cxoevyvijexvgsfeid"
                    ).unwrap().inet_addr().unwrap().to_onion().unwrap(),
                    OnionAddressV3::from_str(
                        "32zzibxmqi2ybxpqyggwwuwz7a3lbvtzoloti7cxoevyvijexvgsfeid"
                    ).unwrap()
                );

                assert_eq!(
                    NodeLocator::from_str(
                        "lnp://022e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af\
                        @6zdgh5a5e6zpchdz"
                    ).unwrap().inet_addr().unwrap().to_onion_v2().unwrap(),
                    OnionAddressV2::from_str(
                        "6zdgh5a5e6zpchdz"
                    ).unwrap()
                );
            }
        }
    }

    #[test]
    fn test_udp() {
        let pubkey1 = secp256k1::PublicKey::from_str(
            "022e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af"
        ).unwrap();
        let pubkey2 = secp256k1::PublicKey::from_str(
            "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af"
        ).unwrap();
        let inet1 = IpAddr::from_str("127.0.0.1").unwrap();
        let inet2 = IpAddr::from_str("127.0.0.2").unwrap();
        let locator1 = NodeLocator::Udp(pubkey1, inet1, None);
        let locator2 = NodeLocator::Udp(pubkey2, inet2, None);

        assert_ne!(locator1, locator2);
        assert_eq!(locator1, locator1.clone());
        assert_eq!(locator2, locator2.clone());

        assert_eq!(locator1.scheme(), "lnpu");
        assert_eq!(locator1.node_id(), Some(pubkey1));
        assert_eq!(locator1.port(), None);
        assert_eq!(locator1.api_type(), None);
        assert_eq!(locator1.inet_addr(), Some(InetAddr::from(inet1)));
        assert_eq!(locator1.socket_name(), None);
        let locator_with_port = locator1.with_port(24);
        assert_eq!(locator_with_port.port(), Some(24));

        assert_eq!(
            NodeAddr::try_from(locator1.clone()),
            Err(ConversionError::UnsupportedType)
        );
        assert_eq!(
            NodeAddr::try_from(locator_with_port.clone()),
            Err(ConversionError::UnsupportedType)
        );

        assert_eq!(
            locator1.to_url_string(),
            "lnpu://022e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af@127.0.0.1"
        );
        assert_eq!(
            locator_with_port.to_url_string(),
            "lnpu://022e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af@127.0.0.1:24"
        );

        #[cfg(feature = "url")]
        {
            assert_eq!(
                NodeLocator::from_str(
                    "lnpu://022e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af@127.0.0.1"
                ).unwrap(),
                locator1
            );
            assert_eq!(
                NodeLocator::from_str(
                    "lnpu://022e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af@127.0.0.1:24"
                ).unwrap(),
                locator_with_port
            );
        }
    }

    #[cfg(feature = "websockets")]
    #[test]
    fn test_websocket() {
        let pubkey1 = secp256k1::PublicKey::from_str(
            "022e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af"
        ).unwrap();
        let pubkey2 = secp256k1::PublicKey::from_str(
            "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af"
        ).unwrap();
        let inet1 = IpAddr::from_str("127.0.0.1").unwrap();
        let inet2 = IpAddr::from_str("127.0.0.2").unwrap();
        let locator1 = NodeLocator::Websocket(pubkey1, inet1, None);
        let locator2 = NodeLocator::Websocket(pubkey2, inet2, None);

        assert_ne!(locator1, locator2);
        assert_eq!(locator1, locator1.clone());
        assert_eq!(locator2, locator2.clone());

        assert_eq!(locator1.scheme(), "lnpws");
        assert_eq!(locator1.node_id(), Some(pubkey1));
        assert_eq!(locator1.port(), None);
        assert_eq!(locator1.api_type(), None);
        assert_eq!(locator1.inet_addr(), Some(InetAddr::from(inet1)));
        assert_eq!(locator1.socket_name(), None);
        let locator_with_port = locator1.with_port(24);
        assert_eq!(locator_with_port.port(), Some(24));

        assert_eq!(
            NodeAddr::try_from(locator1.clone()),
            Err(ConversionError::UnsupportedType)
        );
        assert_eq!(
            NodeAddr::try_from(locator_with_port.clone()),
            Err(ConversionError::UnsupportedType)
        );

        assert_eq!(
            locator1.to_url_string(),
            "lnpws://022e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af@127.0.0.1"
        );
        assert_eq!(
            locator_with_port.to_url_string(),
            "lnpws://022e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af@127.0.0.1:24"
        );

        #[cfg(feature = "url")]
        {
            assert_eq!(
                NodeLocator::from_str(
                    "lnpws://022e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af@127.0.0.1"
                ).unwrap(),
                locator1
            );
            assert_eq!(
                NodeLocator::from_str(
                    "lnpws://022e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af@127.0.0.1:24"
                ).unwrap(),
                locator_with_port
            );
        }
    }

    #[cfg(feature = "zmq")]
    #[test]
    fn test_zmq_encrypted() {
        let pubkey1 = secp256k1::PublicKey::from_str(
            "022e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af"
        ).unwrap();
        let pubkey2 = secp256k1::PublicKey::from_str(
            "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af"
        ).unwrap();
        let inet1 = IpAddr::from_str("127.0.0.1").unwrap();
        let inet2 = IpAddr::from_str("127.0.0.2").unwrap();
        let locator1 = NodeLocator::ZmqEncrypted(
            pubkey1,
            ZmqType::PeerListening,
            inet1,
            None,
        );
        let locator2 =
            NodeLocator::ZmqEncrypted(pubkey2, ZmqType::Client, inet2, None);
        let locator3 = NodeLocator::ZmqEncrypted(
            pubkey1,
            ZmqType::PeerConnecting,
            inet1,
            None,
        );
        let locator4 =
            NodeLocator::ZmqEncrypted(pubkey2, ZmqType::Server, inet2, None);

        assert_ne!(locator1, locator2);
        assert_ne!(locator2, locator4);
        assert_eq!(locator1, locator3);
        assert_eq!(locator1, locator1.clone());
        assert_eq!(locator2, locator2.clone());

        assert_eq!(locator1.scheme(), "lnpz");
        assert_eq!(locator1.node_id(), Some(pubkey1));
        assert_eq!(locator1.port(), None);
        assert_eq!(locator1.api_type(), Some(ZmqType::PeerListening));
        assert_eq!(locator1.inet_addr(), Some(InetAddr::from(inet1)));
        assert_eq!(locator1.socket_name(), None);
        let locator_with_port = locator1.with_port(24);
        assert_eq!(locator_with_port.port(), Some(24));

        assert_eq!(
            NodeAddr::try_from(locator1.clone()),
            Err(ConversionError::UnsupportedType)
        );
        assert_eq!(
            NodeAddr::try_from(locator_with_port.clone()),
            Err(ConversionError::UnsupportedType)
        );

        assert_eq!(
            locator1.to_url_string(),
            "lnpz://022e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af@127.0.0.1/?api=p2p"
        );
        assert_eq!(
            locator2.to_url_string(),
            "lnpz://032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af@127.0.0.2/?api=rpc"
        );
        assert_eq!(
            locator_with_port.to_url_string(),
            "lnpz://022e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af@127.0.0.1:24/?api=p2p"
        );

        #[cfg(feature = "url")]
        {
            assert_eq!(
                NodeLocator::from_str(
                    "lnpz://022e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af@127.0.0.1/?api=p2p"
                ).unwrap(),
                locator1
            );
            assert_eq!(
                NodeLocator::from_str(
                    "lnpz://022e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af@127.0.0.1:24/?api=p2p"
                ).unwrap(),
                locator_with_port
            );
        }
    }

    #[cfg(feature = "zmq")]
    #[test]
    fn test_zmq_unencrypted() {
        let inet1 = IpAddr::from_str("127.0.0.1").unwrap();
        let inet2 = IpAddr::from_str("127.0.0.2").unwrap();
        let locator1 =
            NodeLocator::ZmqUnencrypted(ZmqType::PeerListening, inet1, None);
        let locator2 =
            NodeLocator::ZmqUnencrypted(ZmqType::Client, inet2, None);
        let locator3 =
            NodeLocator::ZmqUnencrypted(ZmqType::PeerConnecting, inet1, None);
        let locator4 =
            NodeLocator::ZmqUnencrypted(ZmqType::Server, inet2, None);

        assert_ne!(locator1, locator2);
        assert_ne!(locator2, locator4);
        assert_eq!(locator1, locator3);
        assert_eq!(locator1, locator1.clone());
        assert_eq!(locator2, locator2.clone());

        assert_eq!(locator1.scheme(), "lnpz");
        assert_eq!(locator1.node_id(), None);
        assert_eq!(locator1.port(), None);
        assert_eq!(locator1.api_type(), Some(ZmqType::PeerListening));
        assert_eq!(locator1.inet_addr(), Some(InetAddr::from(inet1)));
        let locator_with_port = locator1.with_port(24);
        assert_eq!(locator_with_port.port(), Some(24));

        assert_eq!(
            NodeAddr::try_from(locator1.clone()),
            Err(ConversionError::UnsupportedType)
        );
        assert_eq!(
            NodeAddr::try_from(locator_with_port.clone()),
            Err(ConversionError::UnsupportedType)
        );

        assert_eq!(locator1.to_url_string(), "lnpz://127.0.0.1/?api=p2p");
        assert_eq!(locator2.to_url_string(), "lnpz://127.0.0.2/?api=rpc");
        assert_eq!(
            locator_with_port.to_url_string(),
            "lnpz://127.0.0.1:24/?api=p2p"
        );

        #[cfg(feature = "url")]
        {
            assert_eq!(
                NodeLocator::from_str("lnpz://127.0.0.1/?api=p2p").unwrap(),
                locator1
            );
        }
    }

    #[cfg(feature = "zmq")]
    #[test]
    fn test_zmq_inproc() {
        let context1 = zmq::Context::new();
        let context2 = zmq::Context::new();

        let locator1 = NodeLocator::Inproc(
            s!("socket1"),
            context1.clone(),
            ZmqType::PeerListening,
        );
        let locator1_1 = NodeLocator::Inproc(
            s!("socket1"),
            context2.clone(),
            ZmqType::PeerListening,
        );
        let locator2 = NodeLocator::Inproc(
            s!("socket2"),
            context2.clone(),
            ZmqType::Client,
        );
        let locator3 = NodeLocator::Inproc(
            s!("socket1"),
            context1.clone(),
            ZmqType::PeerConnecting,
        );
        let locator4 = NodeLocator::Inproc(
            s!("socket2"),
            context2.clone(),
            ZmqType::Server,
        );

        assert_eq!(locator1, locator1_1);
        assert_ne!(locator1, locator2);
        assert_ne!(locator2, locator4);
        assert_eq!(locator1, locator3);
        assert_eq!(locator1, locator1.clone());
        assert_eq!(locator2, locator2.clone());

        assert_eq!(locator1.scheme(), "lnpz");
        assert_eq!(locator1.node_id(), None);
        assert_eq!(locator1.port(), None);
        assert_eq!(locator1.api_type(), Some(ZmqType::PeerListening));
        assert_eq!(locator1.inet_addr(), None);
        assert_eq!(locator1.socket_name(), Some(s!("socket1")));
        let locator_with_port = locator1.with_port(24);
        assert_eq!(locator_with_port.port(), None);

        assert_eq!(
            NodeAddr::try_from(locator1.clone()),
            Err(ConversionError::UnsupportedType)
        );
        assert_eq!(
            NodeAddr::try_from(locator_with_port.clone()),
            Err(ConversionError::UnsupportedType)
        );

        assert_eq!(locator1.to_url_string(), "lnpz:?api=p2p#socket1");
        assert_eq!(locator2.to_url_string(), "lnpz:?api=rpc#socket2");
        assert_eq!(locator_with_port.to_url_string(), "lnpz:?api=p2p#socket1");

        #[cfg(feature = "url")]
        {
            assert_eq!(
                NodeLocator::from_str("lnpz:?api=p2p#socket1").unwrap_err(),
                ParseError::InprocRequireZmqContext
            );
        }
    }

    #[cfg(feature = "zmq")]
    #[test]
    fn test_zmq_ipc() {
        let locator1 = NodeLocator::Ipc(
            PathBuf::from_str("./socket1").unwrap(),
            ZmqType::PeerListening,
        );
        let locator2 = NodeLocator::Ipc(
            PathBuf::from_str("./socket2").unwrap(),
            ZmqType::Client,
        );
        let locator3 = NodeLocator::Ipc(
            PathBuf::from_str("./socket1").unwrap(),
            ZmqType::PeerConnecting,
        );
        let locator4 = NodeLocator::Ipc(
            PathBuf::from_str("./socket2").unwrap(),
            ZmqType::Server,
        );

        assert_ne!(locator1, locator2);
        assert_ne!(locator2, locator4);
        assert_eq!(locator1, locator3);
        assert_eq!(locator1, locator1.clone());
        assert_eq!(locator2, locator2.clone());

        assert_eq!(locator1.scheme(), "lnpz");
        assert_eq!(locator1.node_id(), None);
        assert_eq!(locator1.port(), None);
        assert_eq!(locator1.api_type(), Some(ZmqType::PeerListening));
        assert_eq!(locator1.inet_addr(), None);
        assert_eq!(locator1.socket_name(), Some(s!("./socket1")));
        let locator_with_port = locator1.with_port(24);
        assert_eq!(locator_with_port.port(), None);

        assert_eq!(
            NodeAddr::try_from(locator1.clone()),
            Err(ConversionError::UnsupportedType)
        );
        assert_eq!(
            NodeAddr::try_from(locator_with_port.clone()),
            Err(ConversionError::UnsupportedType)
        );

        assert_eq!(locator1.to_url_string(), "lnpz:./socket1?api=p2p");
        assert_eq!(locator2.to_url_string(), "lnpz:./socket2?api=rpc");
        assert_eq!(locator_with_port.to_url_string(), "lnpz:./socket1?api=p2p");

        #[cfg(feature = "url")]
        {
            assert_eq!(
                NodeLocator::from_str("lnpz:./socket1?api=p2p").unwrap(),
                locator1
            );
        }
    }

    #[test]
    fn test_text() {
        let pubkey1 = secp256k1::PublicKey::from_str(
            "022e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af"
        ).unwrap();
        let pubkey2 = secp256k1::PublicKey::from_str(
            "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af"
        ).unwrap();
        let locator1 = NodeLocator::Text(pubkey1);
        let locator2 = NodeLocator::Text(pubkey2);

        assert_ne!(locator1, locator2);
        assert_eq!(locator1, locator1.clone());
        assert_eq!(locator2, locator2.clone());

        assert_eq!(locator1.scheme(), "lnpt");
        assert_eq!(locator1.node_id(), Some(pubkey1));
        assert_eq!(locator1.port(), None);
        assert_eq!(locator1.api_type(), None);
        assert_eq!(locator1.inet_addr(), None);
        assert_eq!(locator1.socket_name(), None);
        let locator_with_port = locator1.with_port(24);
        assert_eq!(locator_with_port.port(), None);

        assert_eq!(
            NodeAddr::try_from(locator1.clone()),
            Err(ConversionError::UnsupportedType)
        );
        assert_eq!(
            NodeAddr::try_from(locator_with_port.clone()),
            Err(ConversionError::UnsupportedType)
        );

        assert_eq!(
            locator1.to_url_string(),
            "lnpt://022e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af"
        );
        assert_eq!(
            locator_with_port.to_url_string(),
            "lnpt://022e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af"
        );

        #[cfg(feature = "url")]
        {
            assert_eq!(
                NodeLocator::from_str(
                    "lnpt://022e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af"
                ).unwrap(),
                locator1
            );
            assert_eq!(
                NodeLocator::from_str(
                    "lnpt://022e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af@127.0.01"
                ).unwrap_err(),
                ParseError::HostPresent
            );
            assert_eq!(
                NodeLocator::from_str(
                    "lnpt://022e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af:1323"
                ).unwrap_err(),
                ParseError::PortPresent
            );
        }
    }
}

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
use core::fmt::{self, Debug, Display, Formatter};
#[cfg(feature = "serde")]
use serde_with::{As, DisplayFromStr};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
#[cfg(feature = "url")]
use url::Url;

use amplify::internet::{InetAddr, InetSocketAddr};
use bitcoin::secp256k1;

use crate::lnp::transport::{LocalSocketAddr, RemoteSocketAddr};
#[cfg(feature = "zmq")]
use crate::lnp::zmqsocket::{ZmqSocketAddr, ZmqType};
use crate::lnp::{AddrError, UrlString};

/// Node address which can be represent by either some local address without
/// encryption information (i.e. node public key) or remote node address
/// containing node public key
#[cfg_attr(
    feature = "serde",
    serde_as,
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(
    Clone,
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
#[lnpbp_crate(crate)]
#[display(inner)]
pub enum NodeAddr {
    /// Local node using plain transport protocol [`LocalSocketAddr`]
    /// information and no encryption
    Local(
        #[cfg_attr(feature = "serde", serde(with = "As::<DisplayFromStr>"))]
        LocalSocketAddr,
    ),

    /// Remote node required to have a node public key used for ID and
    /// encryption
    Remote(
        #[cfg_attr(feature = "serde", serde(with = "As::<DisplayFromStr>"))]
        RemoteNodeAddr,
    ),
}

impl FromStr for NodeAddr {
    type Err = AddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(PartialNodeAddr::from_str(s)?.into())
    }
}

impl UrlString for NodeAddr {
    fn url_scheme(&self) -> &'static str {
        match self {
            NodeAddr::Local(local) => local.url_scheme(),
            NodeAddr::Remote(remote) => remote.url_scheme(),
        }
    }

    fn to_url_string(&self) -> String {
        match self {
            NodeAddr::Local(local) => local.to_url_string(),
            NodeAddr::Remote(remote) => remote.to_url_string(),
        }
    }
}

#[cfg(feature = "url")]
impl From<NodeAddr> for Url {
    fn from(addr: NodeAddr) -> Self {
        Url::from(&addr)
    }
}

#[cfg(feature = "url")]
impl From<&NodeAddr> for Url {
    fn from(addr: &NodeAddr) -> Self {
        Url::parse(&addr.to_url_string())
            .expect("Parsing URL string must not fail")
    }
}

#[cfg(feature = "url")]
impl TryFrom<Url> for NodeAddr {
    type Error = AddrError;

    fn try_from(url: Url) -> Result<Self, Self::Error> {
        Ok(PartialNodeAddr::try_from(url)?.into())
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

#[cfg(feature = "zmq")]
impl TryFrom<NodeAddr> for ZmqSocketAddr {
    type Error = AddrError;

    fn try_from(value: NodeAddr) -> Result<Self, Self::Error> {
        Ok(match value {
            NodeAddr::Local(LocalSocketAddr::Zmq(locator)) => locator,
            NodeAddr::Remote(RemoteNodeAddr {
                node_id,
                remote_addr: RemoteSocketAddr::Zmq(addr),
            }) => ZmqSocketAddr::Tcp(addr),
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
#[cfg_attr(
    feature = "serde",
    serde_as,
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    StrictEncode,
    StrictDecode,
)]
#[lnpbp_crate(crate)]
pub struct RemoteNodeAddr {
    /// Node public key, used both as an ID and encryption key for per-session
    /// ECDH
    pub node_id: secp256k1::PublicKey,

    /// Full remote peer address including port information
    #[cfg_attr(feature = "serde", serde(with = "As::<DisplayFromStr>"))]
    pub remote_addr: RemoteSocketAddr,
}

impl_try_from_stringly_standard!(NodeAddr);
impl_into_stringly_standard!(NodeAddr);

impl fmt::Display for RemoteNodeAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(
                f,
                "{}{}@{}",
                self.remote_addr.url_scheme(),
                self.node_id,
                self.remote_addr
            )
        } else {
            write!(f, "{}@{}", self.node_id, self.remote_addr)
        }
    }
}

impl FromStr for RemoteNodeAddr {
    type Err = AddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PartialNodeAddr::from_str(s)?.try_into()
    }
}

impl UrlString for RemoteNodeAddr {
    fn url_scheme(&self) -> &'static str {
        self.remote_addr.url_scheme()
    }

    fn to_url_string(&self) -> String {
        format!("{:#}", self)
    }
}

#[cfg(feature = "url")]
impl From<RemoteNodeAddr> for Url {
    fn from(addr: RemoteNodeAddr) -> Self {
        Url::from(&addr)
    }
}

#[cfg(feature = "url")]
impl From<&RemoteNodeAddr> for Url {
    fn from(addr: &RemoteNodeAddr) -> Self {
        Url::parse(&addr.to_url_string())
            .expect("Parsing URL string must not fail")
    }
}

#[cfg(feature = "url")]
impl TryFrom<Url> for RemoteNodeAddr {
    type Error = AddrError;

    fn try_from(url: Url) -> Result<Self, Self::Error> {
        PartialNodeAddr::try_from(url)?.try_into()
    }
}

impl From<RemoteNodeAddr> for RemoteSocketAddr {
    fn from(addr: RemoteNodeAddr) -> RemoteSocketAddr {
        addr.remote_addr
    }
}

/// Trait allowing generic function arguments for application-level
/// implementations knowing default protocol port
pub trait ToNodeAddr {
    /// Constructs [`NodeAddr`] from an internal data with a default port
    /// put in place when the port details were not given is such structures
    /// as [`PartialNodeAddr`]
    ///
    /// # Returns
    /// * `None`, if string conversion fails with [`AddrError`]
    /// * `Some(`[`NodeAddr`]`)` otherwise
    // TODO: (future) Re-implement with const generics once this rust language
    //       feature will be stabilized and released
    fn to_node_addr(&self, default_port: u16) -> Option<NodeAddr>;
}

impl ToNodeAddr for NodeAddr {
    #[inline]
    fn to_node_addr(&self, default_port: u16) -> Option<NodeAddr> {
        Some(self.clone())
    }
}

impl ToNodeAddr for RemoteNodeAddr {
    #[inline]
    fn to_node_addr(&self, default_port: u16) -> Option<NodeAddr> {
        Some(self.clone().into())
    }
}

impl ToNodeAddr for LocalSocketAddr {
    #[inline]
    fn to_node_addr(&self, default_port: u16) -> Option<NodeAddr> {
        Some(self.clone().into())
    }
}

impl ToNodeAddr for PartialNodeAddr {
    #[inline]
    fn to_node_addr(&self, default_port: u16) -> Option<NodeAddr> {
        self.with_port(default_port).try_into().ok()
    }
}

impl ToNodeAddr for String {
    #[inline]
    fn to_node_addr(&self, default_port: u16) -> Option<NodeAddr> {
        self.as_str().to_node_addr(default_port)
    }
}

impl ToNodeAddr for &str {
    #[inline]
    fn to_node_addr(&self, default_port: u16) -> Option<NodeAddr> {
        NodeAddr::try_from(PartialNodeAddr::from_str(&self).ok()?).ok()
    }
}

impl<T> ToNodeAddr for &T
where
    T: ToNodeAddr,
{
    #[inline]
    fn to_node_addr(&self, default_port: u16) -> Option<NodeAddr> {
        (*self).to_node_addr(default_port)
    }
}

/// Trait allowing generic function arguments for application-level
/// implementations knowing default protocol port
pub trait ToRemoteNodeAddr {
    /// Constructs [`RemoteNodeAddr`] from an internal data with a default port
    /// put in place when the port details were not given is such structures
    /// as [`PartialNodeAddr`]
    ///
    /// # Returns
    /// * `None`, if the underlying type variant can't be represented as a
    ///   complete node address (for instance, for unencrypted local socket)
    ///   Corresponds to situations when `TryInto<`[`RemoteNodeAddr`]`>` returns
    ///   [`ConversionError::UnsupportedType`] or when string conversion fails
    ///   with [`AddrError`].
    /// * `Some(`[`RemoteNodeAddr`]`)` otherwise
    fn to_remote_node_addr(&self, default_port: u16) -> Option<RemoteNodeAddr>;
}

impl ToRemoteNodeAddr for RemoteNodeAddr {
    #[inline]
    fn to_remote_node_addr(&self, default_port: u16) -> Option<RemoteNodeAddr> {
        Some(self.clone())
    }
}

impl ToRemoteNodeAddr for PartialNodeAddr {
    #[inline]
    fn to_remote_node_addr(&self, default_port: u16) -> Option<RemoteNodeAddr> {
        self.with_port(default_port).try_into().ok()
    }
}

impl ToRemoteNodeAddr for String {
    #[inline]
    fn to_remote_node_addr(&self, default_port: u16) -> Option<RemoteNodeAddr> {
        self.as_str().to_remote_node_addr(default_port)
    }
}

impl ToRemoteNodeAddr for &str {
    #[inline]
    fn to_remote_node_addr(&self, default_port: u16) -> Option<RemoteNodeAddr> {
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
    fn to_remote_node_addr(&self, default_port: u16) -> Option<RemoteNodeAddr> {
        (*self).to_remote_node_addr(default_port)
    }
}
/// Universal Node Locator for LNP protocol
/// (from [LNPBP-19](https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0019.md))
///
/// Type is used for visual node and specific protocol representation or parsing
/// It is different from [`NodeAddr`](super::NodeAddr) by the fact that it may
/// not contain port information for LNP-based protocols having known default
/// port, while `NodeAddr` must always contain complete information with the
/// explicit porn number. To convert [`PartialNodeAddr`] to [`NodeAddr`] use
/// [`ToNodeAddr`](super::ToNodeAddr) trait.
///
/// NB: DNS addressing is not used since it is considered insecure in terms of
///     censorship resistance.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum PartialNodeAddr {
    /// Native Lightning network connection: uses end-to-end encryption and
    /// runs on top of either TCP socket (which may be backed by Tor
    /// connection)
    ///
    /// # URL Scheme
    /// lnp://<node-id>@<ip>|<onion>:<port>
    Native(secp256k1::PublicKey, InetAddr, Option<u16>),

    /// NB: Unfinished!
    ///
    /// UDP-based connection that uses UDP packets instead of TCP. Can't work
    /// with Tor, but may use UDP hole punching in a secure way, since the
    /// connection is still required to be encrypted.
    ///
    /// # URL Scheme
    /// lnpu://<node-id>@<ip>:<port>
    Udp(secp256k1::PublicKey, IpAddr, Option<u16>),

    /// Connection through POSIX (UNIX-type) socket. Does not use encryption.
    ///
    /// # URL Scheme
    /// lnp:<file-path>
    Posix(String),

    /// Local (for inter-process communication based on POSIX sockets)
    /// connection without encryption. Relies on ZMQ IPC sockets internally;
    /// specific socket pair for ZMQ is provided via query parameter
    ///
    /// # URL Schema
    /// lnpz:<file-path>?api=<p2p|rpc|sub>
    #[cfg(feature = "zmq")]
    ZmqIpc(String, ZmqType),

    /// LNP protocol supports in-process communications (between threads of the
    /// same process using Mutex'es and other sync managing routines) without
    /// encryption. It relies on ZMQ IPC sockets internally. However, such
    /// connection can be done only withing the same process, and can't be
    /// represented in the form of URL: it requires presence of ZMQ context
    /// object, which can't be encoded as a string (context object is taken
    /// from a global variable).
    #[cfg(feature = "zmq")]
    ZmqInproc(String, ZmqType),

    /// SHOULD be used only for DMZ area connections; otherwise
    /// [`PartialNodeAddr::Native`] or [`PartialNodeAddr::Websocket`]
    /// connection MUST be used
    ///
    /// # URL Scheme
    /// lnpz://<node-id>@<ip>[:<port>]/?api=<p2p|rpc|sub>
    #[cfg(feature = "zmq")]
    ZmqTcpEncrypted(secp256k1::PublicKey, ZmqType, IpAddr, Option<u16>),

    /// SHOULD be used only for DMZ area connections; otherwise
    /// [`PartialNodeAddr::Native`] or [`PartialNodeAddr::Websocket`]
    /// connection MUST be used
    ///
    /// # URL Schema
    /// lnpz://<ip>[:<port>]/?api=<p2p|rpc|sub>
    #[cfg(feature = "zmq")]
    ZmqTcpUnencrypted(ZmqType, IpAddr, Option<u16>),

    /// # URL Scheme
    /// lnph://<node-id>@<ip>|<onion>[:<port>]
    Http(secp256k1::PublicKey, InetAddr, Option<u16>),

    /// # URL Scheme
    /// lnpws://<node-id>@<ip>|<onion>[:<port>]
    #[cfg(feature = "websockets")]
    Websocket(secp256k1::PublicKey, InetAddr, Option<u16>),

    /// Text (Bech32-based) connection for high latency or non-interactive
    /// protocols. Can work with SMPT, for mesh and satellite networks – or
    /// with other mediums of communications (chat messages, QR codes etc).
    ///
    /// # URL Scheme
    /// lnpt://<node-id>@
    Text(secp256k1::PublicKey),
}

impl PartialNodeAddr {
    /// Adds port information to the node locator, if it can contain port.
    /// In case if it does not, performs no action. Returns cloned `Self` with
    /// the updated data.
    pub fn with_port(&self, port: u16) -> Self {
        match self.clone() {
            PartialNodeAddr::Native(a, b, _) => {
                PartialNodeAddr::Native(a, b, Some(port))
            }
            PartialNodeAddr::Udp(a, b, _) => {
                PartialNodeAddr::Udp(a, b, Some(port))
            }
            #[cfg(feature = "zmq")]
            PartialNodeAddr::ZmqTcpEncrypted(a, b, c, _) => {
                PartialNodeAddr::ZmqTcpEncrypted(a, b, c, Some(port))
            }
            #[cfg(feature = "zmq")]
            PartialNodeAddr::ZmqTcpUnencrypted(a, b, _) => {
                PartialNodeAddr::ZmqTcpUnencrypted(a, b, Some(port))
            }
            PartialNodeAddr::Http(a, b, _) => {
                PartialNodeAddr::Http(a, b, Some(port))
            }
            #[cfg(feature = "websockets")]
            PartialNodeAddr::Websocket(a, b, _) => {
                PartialNodeAddr::Websocket(a, b, Some(port))
            }
            me => me,
        }
    }

    /// Parses [`PartialNodeAddr`] into it's optional components, returned as a
    /// single tuple of optionals:
    /// 1) node public key,
    /// 2) [`InetAddr`] of the node,
    /// 3) port
    /// 4) file path or POSIX socket name
    /// 5) [`zmqsocket::ApiType`] parameter for ZMQ based locators
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
            PartialNodeAddr::Native(pubkey, inet, port) => {
                (Some(*pubkey), Some(*inet), *port, None, None)
            }
            PartialNodeAddr::Udp(pubkey, ip, port) => {
                (Some(*pubkey), Some(InetAddr::from(*ip)), *port, None, None)
            }
            PartialNodeAddr::Posix(path) => {
                (None, None, None, Some(path.clone()), None)
            }
            PartialNodeAddr::ZmqIpc(path, api) => {
                (None, None, None, Some(path.clone()), Some(*api))
            }
            PartialNodeAddr::ZmqInproc(name, api) => {
                (None, None, None, Some(name.clone()), Some(*api))
            }
            #[cfg(feature = "zmq")]
            PartialNodeAddr::ZmqTcpEncrypted(pubkey, api, ip, port) => (
                Some(*pubkey),
                Some(InetAddr::from(*ip)),
                *port,
                None,
                Some(*api),
            ),
            #[cfg(feature = "zmq")]
            PartialNodeAddr::ZmqTcpUnencrypted(api, ip, port) => {
                (None, Some(InetAddr::from(*ip)), *port, None, Some(*api))
            }
            PartialNodeAddr::Http(pubkey, inet, port) => {
                (Some(*pubkey), Some(*inet), *port, None, None)
            }
            #[cfg(feature = "websockets")]
            PartialNodeAddr::Websocket(pubkey, inet, port) => {
                (Some(*pubkey), Some(*inet), *port, None, None)
            }
            PartialNodeAddr::Text(pubkey) => {
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

    /// Returns [`zmqsocket::ApiType`] for the given locator, if any, or
    /// [`Option::None`] otherwise
    #[inline]
    pub fn api_type(&self) -> Option<ZmqType> {
        self.components().4
    }
}

impl Display for PartialNodeAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> ::core::fmt::Result {
        if !f.alternate() {
            self.node_id()
                .map(|id| write!(f, "{}", id))
                .unwrap_or(Ok(()))?;
            if let Some(addr) = self.inet_addr() {
                write!(f, "@{}", addr)?;
                self.port()
                    .map(|port| write!(f, ":{}", port))
                    .unwrap_or(Ok(()))?;
            } else {
                f.write_str(&self.socket_name().expect(
                    "Socket name is always known if internet address is given",
                ))?;
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

#[cfg(feature = "url")]
impl FromStr for PartialNodeAddr {
    type Err = AddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut s = s.to_string();
        if vec!["lnp:", "lnpu:", "lnpz:", "lnpws:", "lnpt:", "lnph:"]
            .into_iter()
            .find(|p| s.starts_with(*p))
            .is_none()
        {
            s = format!("lnp://{}", s);
        }
        Url::from_str(&s)?.try_into()
    }
}

impl UrlString for PartialNodeAddr {
    fn url_scheme(&self) -> &'static str {
        match self {
            PartialNodeAddr::Native(..) => "lnp",
            PartialNodeAddr::Udp(..) => "lnpu",
            PartialNodeAddr::Posix(..) => "lnp",
            PartialNodeAddr::ZmqIpc(..) | PartialNodeAddr::ZmqInproc(..) => {
                "lnpz"
            }
            #[cfg(feature = "zmq")]
            PartialNodeAddr::ZmqTcpEncrypted(..)
            | PartialNodeAddr::ZmqTcpUnencrypted(..) => "lnpz",
            PartialNodeAddr::Http(..) => "lnph",
            #[cfg(feature = "websockets")]
            PartialNodeAddr::Websocket(..) => "lnpws",
            PartialNodeAddr::Text(..) => "lnpt",
        }
    }

    fn to_url_string(&self) -> String {
        match self {
            PartialNodeAddr::Native(pubkey, inet, port) => {
                let p = port.map(|x| format!(":{}", x)).unwrap_or_default();
                format!("{}://{}@{}{}", self.url_scheme(), pubkey, inet, p)
            }
            PartialNodeAddr::Udp(pubkey, ip, port) => {
                let p = port.map(|x| format!(":{}", x)).unwrap_or_default();
                format!("{}://{}@{}{}", self.url_scheme(), pubkey, ip, p)
            }
            PartialNodeAddr::Posix(path) => {
                format!("{}:{}", self.url_scheme(), path)
            }
            #[cfg(feature = "zmq")]
            PartialNodeAddr::ZmqIpc(path, zmq_type) => format!(
                "{}:{}?api={}",
                self.url_scheme(),
                path,
                zmq_type.api_name()
            ),
            #[cfg(feature = "zmq")]
            PartialNodeAddr::ZmqInproc(name, zmq_type) => format!(
                "{}:?api={}#{}",
                self.url_scheme(),
                zmq_type.api_name(),
                name
            ),
            #[cfg(feature = "zmq")]
            PartialNodeAddr::ZmqTcpEncrypted(pubkey, zmq_type, ip, port) => {
                let p = port.map(|x| format!(":{}", x)).unwrap_or_default();
                format!(
                    "{}://{}@{}{}/?api={}",
                    self.url_scheme(),
                    pubkey,
                    ip,
                    p,
                    zmq_type.api_name()
                )
            }
            #[cfg(feature = "zmq")]
            PartialNodeAddr::ZmqTcpUnencrypted(zmq_type, ip, port) => {
                let p = port.map(|x| format!(":{}", x)).unwrap_or_default();
                format!(
                    "{}://{}{}/?api={}",
                    self.url_scheme(),
                    ip,
                    p,
                    zmq_type.api_name()
                )
            }
            PartialNodeAddr::Http(pubkey, inet, port) => {
                let p = port.map(|x| format!(":{}", x)).unwrap_or_default();
                format!("{}://{}@{}{}", self.url_scheme(), pubkey, inet, p)
            }
            #[cfg(feature = "websockets")]
            PartialNodeAddr::Websocket(pubkey, inet, port) => {
                let p = port.map(|x| format!(":{}", x)).unwrap_or_default();
                format!("{}://{}@{}{}", self.url_scheme(), pubkey, inet, p)
            }
            PartialNodeAddr::Text(pubkey) => {
                format!("{}://{}", self.url_scheme(), pubkey)
            }
        }
    }
}

#[cfg(feature = "url")]
impl From<PartialNodeAddr> for Url {
    fn from(addr: PartialNodeAddr) -> Self {
        Url::from(&addr)
    }
}

#[cfg(feature = "url")]
impl From<&PartialNodeAddr> for Url {
    fn from(addr: &PartialNodeAddr) -> Self {
        Url::parse(&addr.to_url_string())
            .expect("Parsing URL string must not fail")
    }
}

#[cfg(feature = "url")]
impl TryFrom<Url> for PartialNodeAddr {
    type Error = AddrError;

    fn try_from(url: Url) -> Result<Self, Self::Error> {
        let pubkey = secp256k1::PublicKey::from_str(url.username());
        let host = url.host_str();
        let ip = host
            .map(IpAddr::from_str)
            .transpose()
            .map_err(AddrError::from)
            .and_then(|o| o.ok_or(AddrError::HostRequired));
        let port = url.port();
        match url.scheme() {
            "lnp" => Ok(PartialNodeAddr::Native(
                pubkey?,
                host.ok_or(AddrError::HostRequired)?.parse::<InetAddr>()?,
                port,
            )),
            "lnpu" => Ok(PartialNodeAddr::Udp(pubkey?, ip?, port)),
            "lnph" => Ok(PartialNodeAddr::Http(
                pubkey?,
                host.ok_or(AddrError::HostRequired)?.parse::<InetAddr>()?,
                port,
            )),
            #[cfg(feature = "websockets")]
            "lnpws" => Ok(PartialNodeAddr::Websocket(
                pubkey?,
                host.ok_or(AddrError::HostRequired)?.parse::<InetAddr>()?,
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
                    .ok_or(AddrError::ZmqTypeRequired)?
                    .to_ascii_lowercase()
                    .as_str()
                {
                    "p2p" => Ok(ZmqType::Push),
                    "rpc" => Ok(ZmqType::Req),
                    "sub" => Ok(ZmqType::Sub),
                    "esb" => Ok(ZmqType::RouterBind),
                    unknown => {
                        Err(AddrError::InvalidZmqType(unknown.to_string()))
                    }
                }?;
                Ok(match (ip, pubkey) {
                    (_, Err(_)) if !url.username().is_empty() => {
                        Err(AddrError::InvalidPubkey)?
                    }
                    (Ok(ip), Ok(pubkey)) => PartialNodeAddr::ZmqTcpEncrypted(
                        pubkey, zmq_type, ip, port,
                    ),
                    (Ok(ip), _) => {
                        PartialNodeAddr::ZmqTcpUnencrypted(zmq_type, ip, port)
                    }
                    (Err(_), _) => {
                        if url.path().is_empty() {
                            Err(AddrError::ZmqContextRequired)?
                        }
                        PartialNodeAddr::ZmqIpc(
                            url.path().to_string(),
                            zmq_type,
                        )
                    }
                })
            }
            "lnpt" => {
                // In this URL scheme we must not use IP address
                if let Ok(pubkey) = pubkey {
                    Err(AddrError::UnexpectedHost)?
                }
                // In this URL scheme we must not use IP address
                if let Some(port) = port {
                    Err(AddrError::UnexpectedPort)?
                }
                if let Some(host) = host {
                    Ok(PartialNodeAddr::Text(secp256k1::PublicKey::from_str(
                        host,
                    )?))
                } else {
                    Err(AddrError::InvalidPubkey)?
                }
            }
            unknown => Err(AddrError::UnknownUrlScheme(unknown.to_string())),
        }
    }
}

impl From<PartialNodeAddr> for NodeAddr {
    fn from(locator: PartialNodeAddr) -> Self {
        RemoteNodeAddr::try_from(locator.clone())
            .map(|addr| NodeAddr::Remote(addr))
            .unwrap_or_else(|_| {
                NodeAddr::Local(LocalSocketAddr::try_from(locator).expect(
                    "PartialNodeAddr must convert to either NodeAddr or LocalAddr",
                ))
            })
    }
}

impl TryFrom<PartialNodeAddr> for LocalSocketAddr {
    type Error = AddrError;

    fn try_from(value: PartialNodeAddr) -> Result<Self, Self::Error> {
        Ok(match value {
            PartialNodeAddr::Posix(path) => LocalSocketAddr::Posix(path),
            #[cfg(feature = "zmq")]
            PartialNodeAddr::ZmqIpc(path, ..) => {
                LocalSocketAddr::Zmq(ZmqSocketAddr::Ipc(path))
            }
            #[cfg(feature = "zmq")]
            PartialNodeAddr::ZmqInproc(name, ..) => {
                LocalSocketAddr::Zmq(ZmqSocketAddr::Inproc(name))
            }
            #[cfg(feature = "zmq")]
            PartialNodeAddr::ZmqTcpUnencrypted(_, ip, Some(port)) => {
                LocalSocketAddr::Zmq(ZmqSocketAddr::Tcp(SocketAddr::new(
                    ip, port,
                )))
            }
            _ => Err(AddrError::Unsupported("local socket address"))?,
        })
    }
}

impl TryFrom<PartialNodeAddr> for RemoteNodeAddr {
    type Error = AddrError;

    fn try_from(locator: PartialNodeAddr) -> Result<Self, Self::Error> {
        match locator {
            PartialNodeAddr::Native(.., None) => Err(AddrError::PortRequired),
            #[cfg(feature = "websocket")]
            PartialNodeAddr::Websocket(.., None) => {
                Err(AddrError::HostRequired)
            }
            #[cfg(feature = "zmq")]
            PartialNodeAddr::ZmqTcpEncrypted(.., None) => {
                Err(AddrError::PortRequired)
            }
            PartialNodeAddr::Native(pubkey, address, Some(port)) => {
                Ok(RemoteNodeAddr {
                    node_id: pubkey,
                    remote_addr: RemoteSocketAddr::Ftcp(InetSocketAddr {
                        address,
                        port,
                    }),
                })
            }
            #[cfg(feature = "zmq")]
            PartialNodeAddr::ZmqTcpEncrypted(pubkey, api, ip, Some(port)) => {
                Ok(RemoteNodeAddr {
                    node_id: pubkey,
                    remote_addr: RemoteSocketAddr::Zmq(SocketAddr::new(
                        ip, port,
                    )),
                })
            }
            #[cfg(feature = "websocket")]
            PartialNodeAddr::Websocket(pubkey, addr, Some(port)) => {
                Ok(RemoteNodeAddr {
                    node_id: pubkey,
                    remote_addr: RemoteSocketAddr::Websocket(
                        InetSocketAddr::new(addr, port),
                    ),
                })
            }
            _ => Err(AddrError::Unsupported("Given PartialNodeAddr type can't be converted into RemoteNodeAddr")),
        }
    }
}

impl From<RemoteNodeAddr> for PartialNodeAddr {
    fn from(node_addr: RemoteNodeAddr) -> PartialNodeAddr {
        match node_addr.remote_addr {
            RemoteSocketAddr::Ftcp(addr) => PartialNodeAddr::Native(
                node_addr.node_id,
                addr.address,
                Some(addr.port),
            ),
            #[cfg(feature = "zmq")]
            RemoteSocketAddr::Zmq(addr) => PartialNodeAddr::ZmqTcpEncrypted(
                node_addr.node_id,
                ZmqType::Rep,
                InetSocketAddr::from(addr)
                    .address
                    .try_into()
                    .expect("Conversion from just generated type can't fail"),
                Some(addr.port()),
            ),
            RemoteSocketAddr::Http(addr) => PartialNodeAddr::Http(
                node_addr.node_id,
                addr.address,
                Some(addr.port),
            ),
            #[cfg(feature = "websocket")]
            RemoteSocketAddr::Websocket(addr) => PartialNodeAddr::Websocket(
                node_addr.node_id,
                addr.address,
                Some(addr.port),
            ),
            RemoteSocketAddr::Smtp(addr) => {
                PartialNodeAddr::Text(node_addr.node_id)
            }
        }
    }
}

#[cfg(feature = "zmq")]
impl TryFrom<PartialNodeAddr> for ZmqSocketAddr {
    type Error = AddrError;

    fn try_from(socket_addr: PartialNodeAddr) -> Result<Self, Self::Error> {
        Ok(match socket_addr {
            PartialNodeAddr::ZmqIpc(path, ty) => {
                ZmqSocketAddr::Ipc(path)
            }
            PartialNodeAddr::ZmqTcpUnencrypted(_, ip, Some(port)) |
            PartialNodeAddr::ZmqTcpEncrypted(_, _, ip, Some(port)) => {
                ZmqSocketAddr::Tcp(SocketAddr::new(ip, port))
            }
            _ => Err(AddrError::Unsupported(
                "Provided partial address can't be converted into a valid ZMQ socket"
            ))?
        })
    }
}

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
        let locator1 = PartialNodeAddr::Native(pubkey1, inet1, None);
        let locator2 = PartialNodeAddr::Native(pubkey2, inet2, None);

        assert_ne!(locator1, locator2);
        assert_eq!(locator1, locator1.clone());
        assert_eq!(locator2, locator2.clone());

        assert_eq!(locator1.url_scheme(), "lnp");
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
        let node_addr = RemoteNodeAddr {
            node_id: pubkey1,
            remote_addr: RemoteSocketAddr::Ftcp(socket_addr),
        };
        let l = PartialNodeAddr::from(node_addr.clone());
        assert_eq!(l, locator_with_port);
        assert_ne!(l, locator1);
        assert_eq!(
            RemoteNodeAddr::try_from(locator1.clone()),
            Err(AddrError::PortRequired)
        );
        assert_eq!(
            RemoteNodeAddr::try_from(locator_with_port.clone()),
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
                    PartialNodeAddr::from_str(
                        "lnp://022e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af@127.0.0.1"
                    ).unwrap(),
                    locator1
                );
            assert_eq!(
                    PartialNodeAddr::from_str(
                        "022e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af@127.0.0.1:24"
                    ).unwrap(),
                    locator_with_port
                );

            #[cfg(feature = "tor")]
            {
                use torut::onion::{OnionAddressV2, OnionAddressV3};

                assert_eq!(
                    PartialNodeAddr::from_str(
                        "lnp://022e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af\
                          @32zzibxmqi2ybxpqyggwwuwz7a3lbvtzoloti7cxoevyvijexvgsfeid"
                    ).unwrap().inet_addr().unwrap().to_onion().unwrap(),
                    OnionAddressV3::from_str(
                        "32zzibxmqi2ybxpqyggwwuwz7a3lbvtzoloti7cxoevyvijexvgsfeid"
                    ).unwrap()
                );

                assert_eq!(
                    PartialNodeAddr::from_str(
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
        let locator1 = PartialNodeAddr::Udp(pubkey1, inet1, None);
        let locator2 = PartialNodeAddr::Udp(pubkey2, inet2, None);

        assert_ne!(locator1, locator2);
        assert_eq!(locator1, locator1.clone());
        assert_eq!(locator2, locator2.clone());

        assert_eq!(locator1.url_scheme(), "lnpu");
        assert_eq!(locator1.node_id(), Some(pubkey1));
        assert_eq!(locator1.port(), None);
        assert_eq!(locator1.api_type(), None);
        assert_eq!(locator1.inet_addr(), Some(InetAddr::from(inet1)));
        assert_eq!(locator1.socket_name(), None);
        let locator_with_port = locator1.with_port(24);
        assert_eq!(locator_with_port.port(), Some(24));

        assert_eq!(
            RemoteNodeAddr::try_from(locator1.clone()),
            Err(AddrError::Unsupported("Given PartialNodeAddr type can't be converted into RemoteNodeAddr"))
        );
        assert_eq!(
            RemoteNodeAddr::try_from(locator_with_port.clone()),
            Err(AddrError::Unsupported("Given PartialNodeAddr type can't be converted into RemoteNodeAddr"))
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
                PartialNodeAddr::from_str(
                    "lnpu://022e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af@127.0.0.1"
                ).unwrap(),
                locator1
            );
            assert_eq!(
                PartialNodeAddr::from_str(
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
        let inet1 = InetAddr::from_str("127.0.0.1").unwrap();
        let inet2 = InetAddr::from_str("127.0.0.2").unwrap();
        let locator1 = PartialNodeAddr::Websocket(pubkey1, inet1, None);
        let locator2 = PartialNodeAddr::Websocket(pubkey2, inet2, None);

        assert_ne!(locator1, locator2);
        assert_eq!(locator1, locator1.clone());
        assert_eq!(locator2, locator2.clone());

        assert_eq!(locator1.url_scheme(), "lnpws");
        assert_eq!(locator1.node_id(), Some(pubkey1));
        assert_eq!(locator1.port(), None);
        assert_eq!(locator1.api_type(), None);
        assert_eq!(locator1.inet_addr(), Some(InetAddr::from(inet1)));
        assert_eq!(locator1.socket_name(), None);
        let locator_with_port = locator1.with_port(24);
        assert_eq!(locator_with_port.port(), Some(24));

        assert_eq!(
            RemoteNodeAddr::try_from(locator1.clone()),
            Err(AddrError::Unsupported("Given PartialNodeAddr type can't be converted into RemoteNodeAddr"))
        );
        assert_eq!(
            RemoteNodeAddr::try_from(locator_with_port.clone()),
            Err(AddrError::Unsupported("Given PartialNodeAddr type can't be converted into RemoteNodeAddr"))
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
                PartialNodeAddr::from_str(
                    "lnpws://022e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af@127.0.0.1"
                ).unwrap(),
                locator1
            );
            assert_eq!(
                PartialNodeAddr::from_str(
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
        let locator1 = PartialNodeAddr::ZmqTcpEncrypted(
            pubkey1,
            ZmqType::Push,
            inet1,
            None,
        );
        let locator2 = PartialNodeAddr::ZmqTcpEncrypted(
            pubkey2,
            ZmqType::Req,
            inet2,
            None,
        );
        let locator3 = PartialNodeAddr::ZmqTcpEncrypted(
            pubkey1,
            ZmqType::Pull,
            inet1,
            None,
        );
        let locator4 = PartialNodeAddr::ZmqTcpEncrypted(
            pubkey2,
            ZmqType::Rep,
            inet2,
            None,
        );

        assert_ne!(locator1, locator2);
        assert_ne!(locator2, locator4);
        assert_ne!(locator1, locator3);
        assert_eq!(locator1, locator1.clone());
        assert_eq!(locator2, locator2.clone());

        assert_eq!(locator1.url_scheme(), "lnpz");
        assert_eq!(locator1.node_id(), Some(pubkey1));
        assert_eq!(locator1.port(), None);
        assert_eq!(locator1.api_type(), Some(ZmqType::Push));
        assert_eq!(locator1.inet_addr(), Some(InetAddr::from(inet1)));
        assert_eq!(locator1.socket_name(), None);
        let locator_with_port = locator1.with_port(24);
        assert_eq!(locator_with_port.port(), Some(24));

        assert_eq!(
            RemoteNodeAddr::try_from(locator1.clone()),
            Err(AddrError::PortRequired)
        );
        assert_eq!(
            RemoteNodeAddr::try_from(locator_with_port.clone()),
            Ok(RemoteNodeAddr {
                node_id: pubkey1,
                remote_addr: RemoteSocketAddr::Zmq(SocketAddr::new(inet1, 24))
            })
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
                PartialNodeAddr::from_str(
                    "lnpz://022e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af@127.0.0.1/?api=p2p"
                ).unwrap(),
                locator1
            );
            assert_eq!(
                PartialNodeAddr::from_str(
                    "lnpz://022e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af@127.0.0.1:24/?api=p2p"
                ).unwrap(),
                locator1.with_port(24)
            );
        }
    }

    #[cfg(feature = "zmq")]
    #[test]
    fn test_zmq_unencrypted() {
        let inet1 = IpAddr::from_str("127.0.0.1").unwrap();
        let inet2 = IpAddr::from_str("127.0.0.2").unwrap();
        let locator1 =
            PartialNodeAddr::ZmqTcpUnencrypted(ZmqType::Push, inet1, None);
        let locator2 =
            PartialNodeAddr::ZmqTcpUnencrypted(ZmqType::Req, inet2, None);
        let locator3 =
            PartialNodeAddr::ZmqTcpUnencrypted(ZmqType::Pull, inet1, None);
        let locator4 =
            PartialNodeAddr::ZmqTcpUnencrypted(ZmqType::Rep, inet2, None);

        assert_ne!(locator1, locator2);
        assert_ne!(locator2, locator4);
        assert_ne!(locator1, locator3);
        assert_eq!(locator1, locator1.clone());
        assert_eq!(locator2, locator2.clone());

        assert_eq!(locator1.url_scheme(), "lnpz");
        assert_eq!(locator1.node_id(), None);
        assert_eq!(locator1.port(), None);
        assert_eq!(locator1.api_type(), Some(ZmqType::Push));
        assert_eq!(locator1.inet_addr(), Some(InetAddr::from(inet1)));
        let locator_with_port = locator1.with_port(24);
        assert_eq!(locator_with_port.port(), Some(24));

        assert_eq!(
            RemoteNodeAddr::try_from(locator1.clone()),
            Err(AddrError::Unsupported("Given PartialNodeAddr type can't be converted into RemoteNodeAddr"))
        );
        assert_eq!(
            RemoteNodeAddr::try_from(locator_with_port.clone()),
            Err(AddrError::Unsupported("Given PartialNodeAddr type can't be converted into RemoteNodeAddr"))
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
                PartialNodeAddr::from_str("lnpz://127.0.0.1/?api=p2p").unwrap(),
                locator1
            );
        }
    }

    #[cfg(feature = "zmq")]
    #[test]
    fn test_zmq_inproc() {
        let locator1 = PartialNodeAddr::ZmqInproc(s!("socket1"), ZmqType::Push);
        let locator1_1 =
            PartialNodeAddr::ZmqInproc(s!("socket1"), ZmqType::Push);
        let locator2 = PartialNodeAddr::ZmqInproc(s!("socket2"), ZmqType::Req);
        let locator3 = PartialNodeAddr::ZmqInproc(s!("socket1"), ZmqType::Pull);
        let locator4 = PartialNodeAddr::ZmqInproc(s!("socket2"), ZmqType::Rep);

        assert_eq!(locator1, locator1_1);
        assert_ne!(locator1, locator2);
        assert_ne!(locator2, locator4);
        assert_ne!(locator1, locator3);
        assert_eq!(locator1, locator1.clone());
        assert_eq!(locator2, locator2.clone());

        assert_eq!(locator1.url_scheme(), "lnpz");
        assert_eq!(locator1.node_id(), None);
        assert_eq!(locator1.port(), None);
        assert_eq!(locator1.api_type(), Some(ZmqType::Push));
        assert_eq!(locator1.inet_addr(), None);
        assert_eq!(locator1.socket_name(), Some(s!("socket1")));
        let locator_with_port = locator1.with_port(24);
        assert_eq!(locator_with_port.port(), None);

        assert_eq!(
            RemoteNodeAddr::try_from(locator1.clone()),
            Err(AddrError::Unsupported("Given PartialNodeAddr type can't be converted into RemoteNodeAddr"))
        );
        assert_eq!(
            RemoteNodeAddr::try_from(locator_with_port.clone()),
            Err(AddrError::Unsupported("Given PartialNodeAddr type can't be converted into RemoteNodeAddr"))
        );

        assert_eq!(locator1.to_url_string(), "lnpz:?api=p2p#socket1");
        assert_eq!(locator2.to_url_string(), "lnpz:?api=rpc#socket2");
        assert_eq!(locator_with_port.to_url_string(), "lnpz:?api=p2p#socket1");

        #[cfg(feature = "url")]
        {
            assert_eq!(
                PartialNodeAddr::from_str("lnpz:?api=p2p#socket1").unwrap_err(),
                AddrError::ZmqContextRequired
            );
        }
    }

    #[cfg(feature = "zmq")]
    #[test]
    fn test_zmq_ipc() {
        let locator1 = PartialNodeAddr::ZmqIpc(s!("./socket1"), ZmqType::Push);
        let locator2 = PartialNodeAddr::ZmqIpc(s!("./socket2"), ZmqType::Req);
        let locator3 = PartialNodeAddr::ZmqIpc(s!("./socket1"), ZmqType::Pull);
        let locator4 = PartialNodeAddr::ZmqIpc(s!("./socket2"), ZmqType::Rep);

        assert_ne!(locator1, locator2);
        assert_ne!(locator2, locator4);
        assert_ne!(locator1, locator3);
        assert_eq!(locator1, locator1.clone());
        assert_eq!(locator2, locator2.clone());

        assert_eq!(locator1.url_scheme(), "lnpz");
        assert_eq!(locator1.node_id(), None);
        assert_eq!(locator1.port(), None);
        assert_eq!(locator1.api_type(), Some(ZmqType::Push));
        assert_eq!(locator1.inet_addr(), None);
        assert_eq!(locator1.socket_name(), Some(s!("./socket1")));
        let locator_with_port = locator1.with_port(24);
        assert_eq!(locator_with_port.port(), None);

        assert_eq!(
            RemoteNodeAddr::try_from(locator1.clone()),
            Err(AddrError::Unsupported("Given PartialNodeAddr type can't be converted into RemoteNodeAddr"))
        );
        assert_eq!(
            RemoteNodeAddr::try_from(locator_with_port.clone()),
            Err(AddrError::Unsupported("Given PartialNodeAddr type can't be converted into RemoteNodeAddr"))
        );

        assert_eq!(locator1.to_url_string(), "lnpz:./socket1?api=p2p");
        assert_eq!(locator2.to_url_string(), "lnpz:./socket2?api=rpc");
        assert_eq!(locator_with_port.to_url_string(), "lnpz:./socket1?api=p2p");

        #[cfg(feature = "url")]
        {
            assert_eq!(
                PartialNodeAddr::from_str("lnpz:./socket1?api=p2p").unwrap(),
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
        let locator1 = PartialNodeAddr::Text(pubkey1);
        let locator2 = PartialNodeAddr::Text(pubkey2);

        assert_ne!(locator1, locator2);
        assert_eq!(locator1, locator1.clone());
        assert_eq!(locator2, locator2.clone());

        assert_eq!(locator1.url_scheme(), "lnpt");
        assert_eq!(locator1.node_id(), Some(pubkey1));
        assert_eq!(locator1.port(), None);
        assert_eq!(locator1.api_type(), None);
        assert_eq!(locator1.inet_addr(), None);
        assert_eq!(locator1.socket_name(), None);
        let locator_with_port = locator1.with_port(24);
        assert_eq!(locator_with_port.port(), None);

        assert_eq!(
            RemoteNodeAddr::try_from(locator1.clone()),
            Err(AddrError::Unsupported("Given PartialNodeAddr type can't be converted into RemoteNodeAddr"))
        );
        assert_eq!(
            RemoteNodeAddr::try_from(locator_with_port.clone()),
            Err(AddrError::Unsupported("Given PartialNodeAddr type can't be converted into RemoteNodeAddr"))
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
                PartialNodeAddr::from_str(
                    "lnpt://022e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af"
                ).unwrap(),
                locator1
            );
            assert_eq!(
                PartialNodeAddr::from_str(
                    "lnpt://022e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af@127.0.01"
                ).unwrap_err(),
                AddrError::UnexpectedHost
            );
            assert_eq!(
                PartialNodeAddr::from_str(
                    "lnpt://022e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af:1323"
                ).unwrap_err(),
                AddrError::UnexpectedPort
            );
        }
    }
}

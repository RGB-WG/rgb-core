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

//! Module supports transport-level addressing, i.e. the one used before
//! encryption/decryption of the actual data are taking place. These addresses
//! is mostly used internally and does not include information about node
//! public key (for that purpose you need to use session-level address
//! structures like [`NodeLocator`](lnp::NodeLocator) and
//! [`NodeAddress`](lnp::NodeAddr)).

use amplify::internet::{InetAddr, InetSocketAddr, NoOnionSupportError};
use core::cmp::Ordering;
#[cfg(feature = "serde")]
use serde_with::{As, DisplayFromStr};
#[cfg(feature = "url")]
use std::convert::{TryFrom, TryInto};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
#[cfg(feature = "url")]
use url::{self, Url};

#[cfg(feature = "zmq")]
use super::zmqsocket;
use crate::lnp::{AddrError, UrlString};

#[derive(
    Clone, Copy, PartialEq, Eq, Hash, Debug, Display, StrictEncode, StrictDecode,
)]
#[lnpbp_crate(crate)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "UPPERCASE")
)]
#[non_exhaustive]
/// Possible transport-layer protocols with framing support
pub enum FramingProtocol {
    /// Framed raw LNP messages according to BOLT-8 pt. 2 and LNPBP-18. Used
    /// with:
    /// * Framed TCP socket connection
    /// * Framed POSIX connections
    #[display("framed", alt = "tcp")]
    FramedRaw,

    /// Microservices connected using ZeroMQ protocol remotely (ZeroMQ
    /// Transport Protocol). Used with both IPC, Inproc and TCP-based SMQ
    /// connections.
    #[cfg(feature = "zmq")]
    #[display("ZMTP", alt = "zmq")]
    Zmtp,

    /// Text-encoded LNP messages over HTTP connection
    #[display("HTTP", alt = "http")]
    Http,

    /// Binary LNP data send over Websocket connection
    #[cfg(feature = "websocket")]
    #[display("Websocket", alt = "ws")]
    Websocket,

    /// SMTP connection: asynchronous end-to-end-over SMTP information transfer
    /// which is useful for ultra-low bandwidth non-real-time connections like
    /// satellite networks
    #[display("SMTP", alt = "smtp")]
    Smtp,
}

impl FromStr for FramingProtocol {
    type Err = AddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ftcp" | "tcp" | "ipc" | "posix" | "unix" => {
                Ok(FramingProtocol::FramedRaw)
            }
            #[cfg(feature = "zmq")]
            "zmtp" | "zmq" => Ok(FramingProtocol::Zmtp),
            "http" | "https" => Ok(FramingProtocol::Http),
            #[cfg(feature = "websocket")]
            "ws" | "wss" | "websocket" => Ok(FramingProtocol::Websocket),
            "smtp" => Ok(FramingProtocol::Smtp),
            other => Err(AddrError::UnknownProtocol(other.to_owned())),
        }
    }
}

/// Represents a connection that requires the other peer to be present on the
/// same machine as a connecting peer
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
pub enum LocalSocketAddr {
    /// Microservices connected using ZeroMQ protocol locally
    #[cfg(feature = "zmq")]
    #[display("{0}", alt = "lnpz://{0}")]
    Zmq(
        #[cfg_attr(feature = "serde", serde(with = "As::<DisplayFromStr>"))]
        zmqsocket::ZmqSocketAddr,
    ),

    /// Local node operating as a separate **process** or **threads** connected
    /// with unencrypted POSIX file I/O (like in c-lightning)
    #[display("{0}", alt = "lnp:{0}")]
    Posix(String),
}

/// Represents a connection to a generic remote peer operating with LNP protocol
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(
    Clone, Copy, PartialEq, Eq, Hash, Debug, Display, StrictEncode, StrictDecode,
)]
#[lnpbp_crate(crate)]
#[non_exhaustive]
pub enum RemoteSocketAddr {
    /// Framed TCP socket connection, that may be served either over plain IP,
    /// IPSec or Tor v2 and v3
    #[display("{0}", alt = "lnp://{0}")]
    Ftcp(InetSocketAddr),

    /// Microservices connected using ZeroMQ protocol remotely. Can be used
    /// only with TCP-based ZMQ; for other types use [`LocalAddr::Zmq`]
    #[cfg(feature = "zmq")]
    #[display("{0}", alt = "lnpz://{0}")]
    Zmq(SocketAddr),

    /// End-to-end encryption over web connection: think of this as LN protocol
    /// streamed over HTTP
    #[display("{0}", alt = "lnph://{0}")]
    Http(InetSocketAddr),

    /// End-to-end ecnruption over web connection: think of this as LN protocol
    /// streamed over Websocket
    #[cfg(feature = "websocket")]
    #[display("{0}", alt = "lnpws://{0}")]
    Websocket(InetSocketAddr),

    /// SMTP connection: asynchronous end-to-end-over SMTP information transfer
    /// which is useful for ultra-low bandwidth non-real-time connections like
    /// satellite networks
    #[display("{0}", alt = "lnpm://{0}")]
    Smtp(InetSocketAddr),
}

// Fake implementation required to use node addresses with StrictEncode
// BTreeMaps
impl PartialOrd for RemoteSocketAddr {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.to_string().partial_cmp(&other.to_string())
    }
}

impl Ord for RemoteSocketAddr {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_string().cmp(&other.to_string())
    }
}

impl RemoteSocketAddr {
    pub fn with_ip_addr(proto: FramingProtocol, ip: IpAddr, port: u16) -> Self {
        let addr = SocketAddr::new(ip, port);
        Self::with_socket_addr(proto, addr)
    }

    pub fn with_socket_addr(proto: FramingProtocol, addr: SocketAddr) -> Self {
        match proto {
            FramingProtocol::FramedRaw => Self::Ftcp(addr.into()),
            #[cfg(feature = "zmq")]
            FramingProtocol::Zmtp => Self::Zmq(addr.into()),
            FramingProtocol::Http => Self::Http(addr.into()),
            #[cfg(feature = "websocket")]
            FramingProtocol::Websocket => Self::Websocket(addr.into()),
            FramingProtocol::Smtp => Self::Smtp(addr.into()),
        }
    }

    pub fn with_inet_addr(
        proto: FramingProtocol,
        addr: InetSocketAddr,
    ) -> Result<Self, NoOnionSupportError> {
        Ok(match proto {
            FramingProtocol::FramedRaw => Self::Ftcp(addr),
            #[cfg(feature = "zmq")]
            FramingProtocol::Zmtp => Self::Zmq(addr.try_into()?),
            FramingProtocol::Http => Self::Http(addr),
            #[cfg(feature = "websocket")]
            FramingProtocol::Websocket => Self::Websocket(addr),
            FramingProtocol::Smtp => Self::Smtp(addr),
        })
    }

    pub fn framing_protocol(&self) -> FramingProtocol {
        match self {
            RemoteSocketAddr::Ftcp(_) => FramingProtocol::FramedRaw,
            #[cfg(feature = "zmq")]
            RemoteSocketAddr::Zmq(_) => FramingProtocol::Zmtp,
            RemoteSocketAddr::Http(_) => FramingProtocol::Http,
            #[cfg(feature = "websocket")]
            RemoteSocketAddr::Websocket(_) => FramingProtocol::Websocket,
            RemoteSocketAddr::Smtp(_) => FramingProtocol::Smtp,
        }
    }
}

impl From<RemoteSocketAddr> for InetSocketAddr {
    fn from(rsa: RemoteSocketAddr) -> Self {
        match rsa {
            RemoteSocketAddr::Ftcp(inet) => inet,
            #[cfg(feature = "zmq")]
            RemoteSocketAddr::Zmq(sa) => sa.into(),
            RemoteSocketAddr::Http(inet) => inet,
            #[cfg(feature = "websocket")]
            RemoteSocketAddr::Websocket(inet) => inet,
            RemoteSocketAddr::Smtp(inet) => inet,
        }
    }
}

#[cfg(feature = "url")]
impl FromStr for LocalSocketAddr {
    type Err = AddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Url::parse(s)?.try_into()
    }
}

#[cfg(feature = "url")]
impl FromStr for RemoteSocketAddr {
    type Err = AddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Url::parse(s)?.try_into()
    }
}

impl UrlString for LocalSocketAddr {
    fn url_scheme(&self) -> &'static str {
        match self {
            #[cfg(feature = "zmq")]
            LocalSocketAddr::Zmq(zmqsocket::ZmqSocketAddr::Tcp(..)) => {
                "lnpz://"
            }
            #[cfg(feature = "zmq")]
            LocalSocketAddr::Zmq(_) => "lnpz:",
            LocalSocketAddr::Posix(_) => "lnp:",
        }
    }

    fn to_url_string(&self) -> String {
        format!("{:#}", self)
    }
}

impl UrlString for RemoteSocketAddr {
    fn url_scheme(&self) -> &'static str {
        match self {
            #[cfg(feature = "zmq")]
            RemoteSocketAddr::Zmq(_) => "lnpz://",
            RemoteSocketAddr::Ftcp(_) => "lnp://",
            RemoteSocketAddr::Smtp(_) => "lnpm://",
            RemoteSocketAddr::Http(_) => "lnph://",
            #[cfg(feature = "websocket")]
            RemoteSocketAddr::Websocket(_) => "lnpws://",
        }
    }

    fn to_url_string(&self) -> String {
        format!("{:#}", self)
    }
}

impl TryFrom<Url> for LocalSocketAddr {
    type Error = AddrError;

    fn try_from(url: Url) -> Result<Self, Self::Error> {
        Ok(match url.scheme() {
            "lnp" => {
                if url.host().is_some() {
                    Err(AddrError::UnexpectedHost)?
                } else if url.has_authority() {
                    Err(AddrError::UnexpectedAuthority)?
                } else if url.port().is_some() {
                    Err(AddrError::UnexpectedPort)?
                }
                LocalSocketAddr::Posix(url.path().to_owned())
            }
            #[cfg(feature = "zmq")]
            "lnpz" => {
                LocalSocketAddr::Zmq(zmqsocket::ZmqSocketAddr::try_from(url)?)
            }
            "lnph" | "lnpws" | "lnpm" => {
                Err(AddrError::Unsupported("for local socket address"))?
            }
            other => Err(AddrError::UnknownUrlScheme(other.to_owned()))?,
        })
    }
}

#[cfg(feature = "url")]
impl TryFrom<Url> for RemoteSocketAddr {
    type Error = AddrError;

    fn try_from(url: Url) -> Result<Self, Self::Error> {
        let host = url.host_str().ok_or(AddrError::HostRequired)?.to_owned();
        let inet_addr = host.parse::<InetAddr>()?;
        let port = url.port().ok_or(AddrError::PortRequired)?;
        let inet_socket_addr = InetSocketAddr::new(inet_addr, port);
        Ok(match url.scheme() {
            "lnp" => RemoteSocketAddr::Ftcp(inet_socket_addr),
            #[cfg(feature = "zmq")]
            "lnpz" => RemoteSocketAddr::Zmq(inet_socket_addr.try_into()?),
            "lnph" => RemoteSocketAddr::Http(inet_socket_addr),
            #[cfg(feature = "websocket")]
            "lnpws" => RemoteSocketAddr::Websocket(inet_socket_addr),
            "lnpm" => RemoteSocketAddr::Smtp(inet_socket_addr),
            other => Err(AddrError::UnknownUrlScheme(other.to_owned()))?,
        })
    }
}

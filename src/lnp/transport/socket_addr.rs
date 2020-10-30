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
#[cfg(feature = "url")]
use std::convert::{TryFrom, TryInto};
use std::net::SocketAddr;
use std::str::FromStr;
#[cfg(feature = "url")]
use url::{self, Url};

#[cfg(feature = "zmq")]
use super::zmqsocket;
use crate::lnp::UrlScheme;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Display)]
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

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
/// Error parsing transport-level address types ([`FramingProtocol`],
/// [`LocalAddr`], [`RemoteAddr`]) from string
pub enum SocketAddrError {
    /// Unknown protocol name in URL scheme ({_0})
    UnknownProtocol(String),

    /// The provided URL scheme {_0} was not recognized
    UnknownUrlScheme(String),

    /// Can't parse URL from the given string
    #[cfg(feature = "url")]
    #[from]
    MalformedUrl(url::ParseError),

    /// Malformed IP or Onion address
    /// NB: DNS addressing is not used since it is considered insecure in terms
    ///     of censorship resistance, so you need to provide it in a form of
    ///     either IPv4, IPv6 address or Tor v2, v3 address (w/o `.onion`
    ///     suffix)
    #[from(std::net::AddrParseError)]
    #[from(amplify::internet::AddrParseError)]
    MalformedIp,

    /// No host information found in URL, while it is required for the given
    /// scheme
    HostRequired,

    /// No port information found in URL, while it is required for the given
    /// scheme
    PortRequired,

    /// Unexpected URL authority data (part before '@' in URL) which must be
    /// omitted
    UnexpectedAuthority,

    /// Used scheme must not contain information about host
    UnexpectedHost,

    /// Used scheme must not contain information about port
    UnexpectedPort,

    /// Unsupported ZMQ API type ({_0}). List of supported APIs:
    /// - `rpc`
    /// - `p2p`
    /// - `sub`
    /// - `esb`
    InvalidZmqType(String),

    /// No ZMQ API type information for URL scheme that requires one.
    ZmqTypeRequired,

    /// Onion addresses are not supported by this socket type
    #[from(NoOnionSupportError)]
    NoOnionSupport,
}

impl FromStr for FramingProtocol {
    type Err = SocketAddrError;

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
            other => Err(SocketAddrError::UnknownProtocol(other.to_owned())),
        }
    }
}

/// Represents a connection that requires the other peer to be present on the
/// same machine as a connecting peer
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
pub enum LocalSocketAddr {
    /// Microservices connected using ZeroMQ protocol locally
    #[cfg(feature = "zmq")]
    #[display("{_0}", alt = "lnpz://{_0}")]
    Zmq(zmqsocket::ZmqAddr),

    /// Local node operating as a separate **process** or **threads** connected
    /// with unencrypted POSIX file I/O (like in c-lightning)
    #[display("{_0}", alt = "lnp:{_0}")]
    Posix(String),
}

/// Represents a connection to a generic remote peer operating with LNP protocol
#[cfg_attr(feature = "serde", serde_as(as = "DisplayFromStr"))]
#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[non_exhaustive]
pub enum RemoteSocketAddr {
    /// Framed TCP socket connection, that may be served either over plain IP,
    /// IPSec or Tor v2 and v3
    #[display("{_0}", alt = "lnp://{_0}")]
    Ftcp(InetSocketAddr),

    /// Microservices connected using ZeroMQ protocol remotely. Can be used
    /// only with TCP-based ZMQ; for other types use [`LocalAddr::Zmq`]
    #[cfg(feature = "zmq")]
    #[display("{_0}", alt = "lnpz://{_0}")]
    Zmq(SocketAddr),

    /// End-to-end encryption over web connection: think of this as LN protocol
    /// streamed over HTTP
    #[display("{_0}", alt = "lnph://{_0}")]
    Http(InetSocketAddr),

    /// End-to-end ecnruption over web connection: think of this as LN protocol
    /// streamed over Websocket
    #[cfg(feature = "websocket")]
    #[display("{_0}", alt = "lnpws://{_0}")]
    Websocket(InetSocketAddr),

    /// SMTP connection: asynchronous end-to-end-over SMTP information transfer
    /// which is useful for ultra-low bandwidth non-real-time connections like
    /// satellite networks
    #[display("{_0}", alt = "lnpm://{_0}")]
    Smtp(InetSocketAddr),
}

#[cfg(feature = "url")]
impl FromStr for LocalSocketAddr {
    type Err = SocketAddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Url::parse(s)?.try_into()
    }
}

#[cfg(feature = "url")]
impl FromStr for RemoteSocketAddr {
    type Err = SocketAddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Url::parse(s)?.try_into()
    }
}

impl TryFrom<Url> for LocalSocketAddr {
    type Error = SocketAddrError;

    fn try_from(url: Url) -> Result<Self, Self::Error> {
        Ok(match url.scheme() {
            "lnp" => {
                if url.host().is_some() {
                    Err(SocketAddrError::UnexpectedHost)?
                } else if url.has_authority() {
                    Err(SocketAddrError::UnexpectedAuthority)?
                } else if url.port().is_some() {
                    Err(SocketAddrError::UnexpectedPort)?
                }
                LocalSocketAddr::Posix(url.path().to_owned())
            }
            #[cfg(feature = "zmq")]
            "lnpz" => LocalSocketAddr::Zmq(zmqsocket::ZmqAddr::try_from(url)?),
            other => Err(SocketAddrError::UnknownUrlScheme(other.to_owned()))?,
        })
    }
}

#[cfg(feature = "url")]
impl TryFrom<Url> for RemoteSocketAddr {
    type Error = SocketAddrError;

    fn try_from(url: Url) -> Result<Self, Self::Error> {
        let host = url
            .host_str()
            .ok_or(SocketAddrError::HostRequired)?
            .to_owned();
        let inet_addr = host.parse::<InetAddr>()?;
        let port = url.port().ok_or(SocketAddrError::PortRequired)?;
        let inet_socket_addr = InetSocketAddr::new(inet_addr, port);
        Ok(match url.scheme() {
            "lnp" => RemoteSocketAddr::Ftcp(inet_socket_addr),
            #[cfg(feature = "zmq")]
            "lnpz" => RemoteSocketAddr::Zmq(inet_socket_addr.try_into()?),
            "lnph" => RemoteSocketAddr::Http(inet_socket_addr),
            #[cfg(feature = "websocket")]
            "lnpws" => RemoteSocketAddr::Websocket(inet_socket_addr),
            "lnpm" => RemoteSocketAddr::Smtp(inet_socket_addr),
            other => Err(SocketAddrError::UnknownUrlScheme(other.to_owned()))?,
        })
    }
}

impl UrlScheme for LocalSocketAddr {
    fn url_scheme(&self) -> &'static str {
        match self {
            #[cfg(feature = "zmq")]
            LocalSocketAddr::Zmq(zmqsocket::ZmqAddr::Tcp(..)) => "lnpz://",
            #[cfg(feature = "zmq")]
            LocalSocketAddr::Zmq(_) => "lnpz:",
            LocalSocketAddr::Posix(_) => "lnp:",
        }
    }
}

impl UrlScheme for RemoteSocketAddr {
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
}

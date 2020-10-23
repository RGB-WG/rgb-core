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

use amplify::internet::InetSocketAddr;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

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

#[derive(
    Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, Error, From,
)]
#[display(doc_comments)]
/// Error parsing transport-level address types ([`FramingProtocol`],
/// [`LocalAddr`], [`RemoteAddr`]) from string
pub enum ParseError {
    /// Unknown string protocol representation
    UnknownProtocol,
}

impl FromStr for FramingProtocol {
    type Err = ParseError;

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
            _ => Err(ParseError::UnknownProtocol),
        }
    }
}

/// Represents a connection that requires the other peer to be present on the
/// same machine as a connecting peer
#[derive(Clone, PartialEq, Eq, Debug, Display)]
pub enum LocalAddr {
    /// Microservices connected using ZeroMQ protocol locally
    #[cfg(feature = "zmq")]
    #[display("{_0}", alt = "lnpz://{_0}")]
    Zmq(zmqsocket::SocketLocator),

    /// Local node operating as a separate **process** or **threads** connected
    /// with unencrypted POSIX file I/O (like in c-lightning)
    #[display("{_0:?}", alt = "lnp:{_0:?}")]
    Posix(PathBuf),
}

/// Represents a connection to a generic remote peer operating with LNP protocol
#[cfg_attr(feature = "serde", serde_as(as = "DisplayFromStr"))]
#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[non_exhaustive]
pub enum RemoteAddr {
    /// Framed TCP socket connection, that may be served either over plain IP,
    /// IPSec or Tor v2 and v3
    #[display("{_0}", alt = "lnp://{_0}")]
    Ftcp(InetSocketAddr),

    // TODO: (new) consider removing and converting `RemoteAddr` into
    //       encryption-only type
    /// POSIX socket
    #[display("{_0:?}", alt = "lnp:{_0:?}")]
    Posix(PathBuf),

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

impl UrlScheme for LocalAddr {
    fn url_scheme(&self) -> &'static str {
        match self {
            #[cfg(feature = "zmq")]
            LocalAddr::Zmq(zmqsocket::SocketLocator::Tcp(..)) => "lnpz://",
            #[cfg(feature = "zmq")]
            LocalAddr::Zmq(_) => "lnpz:",
            LocalAddr::Posix(_) => "lnp:",
        }
    }
}

impl UrlScheme for RemoteAddr {
    fn url_scheme(&self) -> &'static str {
        match self {
            RemoteAddr::Posix(_) => "lnp:",
            #[cfg(feature = "zmq")]
            RemoteAddr::Zmq(_) => "lnpz://",
            RemoteAddr::Ftcp(_) => "lnp://",
            RemoteAddr::Smtp(_) => "lnpm://",
            RemoteAddr::Http(_) => "lnph://",
            #[cfg(feature = "websocket")]
            RemoteAddr::Websocket(_) => "lnpws://",
        }
    }
}

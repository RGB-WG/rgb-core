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

use amplify::{Bipolar, Wrapper};
use core::cmp::Ordering;
#[cfg(feature = "url")]
use core::convert::TryFrom;
#[cfg(feature = "url")]
use core::str::FromStr;
#[cfg(feature = "serde")]
use serde_with::{As, DisplayFromStr};
use std::fmt::{self, Debug, Display, Formatter};
use std::net::SocketAddr;
#[cfg(feature = "url")]
use url::Url;

use super::{Duplex, RecvFrame, RoutedFrame, SendFrame};
use crate::lnp::{transport, AddrError, UrlString};

lazy_static! {
    pub static ref ZMQ_CONTEXT: zmq::Context = zmq::Context::new();
}

/// API type for node-to-node communications used by ZeroMQ
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[repr(u8)]
#[non_exhaustive]
pub enum ZmqType {
    /// Pure peer-to-peer communications done with PUSH/PULL pair of ZMQ
    /// sockets. Each node can send unordered set of messages and does not
    /// wait for a response.
    /// This part represents listening socket ([`zmq::SocketType::PULL`])
    #[display("PULL")]
    Pull = 0,

    /// Pure peer-to-peer communications done with PUSH/PULL pair of ZMQ
    /// sockets. Each node can send unordered set of messages and does not
    /// wait for a response.
    /// This part represents connected socket ([`zmq::SocketType::PUSH`])
    #[display("PUSH")]
    Push = 1,

    /// Remote procedure call communications done with REQ/REP pair of ZMQ
    /// sockets. Two roles: client and server; client sends requests and awaits
    /// for client responses.
    /// This part represents client-size socket ([`zmq::SocketType::REQ`])
    #[display("REQ")]
    Req = 2,

    /// Remote procedure call communications done with REQ/REP pair of ZMQ
    /// sockets. Two roles: client and server; client sends requests and awaits
    /// for client responses.
    /// This part represents client-size socket ([`zmq::SocketType::REP`])
    #[display("REP")]
    Rep = 3,

    /// Subscription API done with SUB/PUB pair of ZMQ sockets. Two roles:
    /// publisher (server) and subscriber (client); subscriber awaits for
    /// messages from publisher and does not communicates back.
    /// This part represents publisher part ([`zmq::SocketType::PUB`])
    #[display("PUB")]
    Pub = 4,

    /// Subscription API done with SUB/PUB pair of ZMQ sockets. Two roles:
    /// publisher (server) and subscriber (client); subscriber awaits for
    /// messages from publisher and does not communicates back.
    /// This part represents subscriber part ([`zmq::SocketType::SUB`])
    #[display("SUB")]
    Sub = 5,

    /// Message bus: each message has a receiver and sender, and multiple peers
    /// may communicate directly with each other in asynchronous mode.
    /// Represents [`zmq::SocketType::ROUTER`] socket which is bind to
    #[display("ROUTER(bind)")]
    RouterBind = 6,

    /// Message bus: each message has a receiver and sender, and multiple peers
    /// may communicate directly with each other in asynchronous mode.
    /// Represents [`zmq::SocketType::ROUTER`] socket wich is connected to
    #[display("ROUTER(connect)")]
    RouterConnect = 7,
}

/// Unknown [`ApiType`] string
#[derive(Clone, Copy, PartialEq, Eq, Debug, Display, Error)]
#[display(Debug)]
pub struct UnknownApiType;

impl ZmqType {
    /// Returns [`zmq::SocketType`] corresponding to the given [`ApiType`]
    pub fn socket_type(&self) -> zmq::SocketType {
        match self {
            ZmqType::Pull => zmq::PULL,
            ZmqType::Push => zmq::PUSH,
            ZmqType::Req => zmq::REQ,
            ZmqType::Rep => zmq::REP,
            ZmqType::Pub => zmq::PUB,
            ZmqType::Sub => zmq::SUB,
            ZmqType::RouterBind => zmq::ROUTER,
            ZmqType::RouterConnect => zmq::ROUTER,
        }
    }

    /// Returns name for the used ZMQ API type that can be used as a part of
    /// URL query
    pub fn api_name(&self) -> String {
        match self {
            ZmqType::Pull | ZmqType::Push => s!("p2p"),
            ZmqType::Req | ZmqType::Rep => s!("rpc"),
            ZmqType::Pub | ZmqType::Sub => s!("sub"),
            ZmqType::RouterBind | ZmqType::RouterConnect => s!("esb"),
        }
    }
}

impl FromStr for ZmqType {
    type Err = UnknownApiType;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.to_lowercase();
        vec![
            ZmqType::Push,
            ZmqType::Pull,
            ZmqType::Req,
            ZmqType::Rep,
            ZmqType::Pub,
            ZmqType::Sub,
            ZmqType::RouterBind,
            ZmqType::RouterConnect,
        ]
        .into_iter()
        .find(|api| api.to_string() == s)
        .ok_or(UnknownApiType)
    }
}

#[cfg_attr(
    feature = "serde",
    serde_as,
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", tag = "type")
)]
#[derive(
    Clone, PartialEq, Eq, Hash, Debug, Display, StrictEncode, StrictDecode,
)]
#[lnpbp_crate(crate)]
pub enum ZmqSocketAddr {
    #[display("inproc://{0}", alt = "zmq:{0}")]
    Inproc(String),

    #[display("ipc://{0}", alt = "lnpz:{0}")]
    Ipc(String),

    #[display("tcp://{0}", alt = "lnpz://{0}")]
    Tcp(
        #[cfg_attr(feature = "serde", serde(with = "As::<DisplayFromStr>"))]
        SocketAddr,
    ),
}

// Fake implementation required to use socket addresses with StrictEncode
// BTreeMaps
impl PartialOrd for ZmqSocketAddr {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.to_string().partial_cmp(&other.to_string())
    }
}

impl Ord for ZmqSocketAddr {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_string().cmp(&other.to_string())
    }
}

impl UrlString for ZmqSocketAddr {
    fn url_scheme(&self) -> &'static str {
        match self {
            ZmqSocketAddr::Inproc(_) => "zmq:",
            ZmqSocketAddr::Ipc(_) => "lnpz:",
            ZmqSocketAddr::Tcp(_) => "lnpz://",
        }
    }

    fn to_url_string(&self) -> String {
        format!("{:#}", self)
    }
}

impl ZmqSocketAddr {
    pub fn zmq_socket_string(&self) -> String {
        format!("{:}", self)
    }
}

#[derive(Display)]
pub enum Carrier {
    #[display(inner)]
    Locator(ZmqSocketAddr),

    #[display("zmq_socket(..)")]
    Socket(zmq::Socket),
}

#[derive(
    Wrapper, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Error, From,
)]
pub struct Error(i32);

impl From<zmq::Error> for Error {
    #[inline]
    fn from(err: zmq::Error) -> Self {
        Self(err.to_raw())
    }
}

impl From<Error> for zmq::Error {
    #[inline]
    fn from(err: Error) -> Self {
        zmq::Error::from_raw(err.into_inner())
    }
}

impl From<zmq::Error> for transport::Error {
    #[inline]
    fn from(err: zmq::Error) -> Self {
        match err {
            zmq::Error::EHOSTUNREACH => transport::Error::ServiceOffline,
            err => transport::Error::Zmq(err.into()),
        }
    }
}

impl From<Error> for transport::Error {
    #[inline]
    fn from(err: Error) -> Self {
        transport::Error::from(zmq::Error::from(err))
    }
}

impl Debug for Error {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Debug::fmt(&zmq::Error::from(*self), f)
    }
}

impl Display for Error {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&zmq::Error::from(*self), f)
    }
}

#[cfg(feature = "url")]
impl FromStr for ZmqSocketAddr {
    type Err = AddrError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url: Url = s.parse()?;
        Self::try_from(url)
    }
}

#[cfg(feature = "url")]
impl From<ZmqSocketAddr> for Url {
    fn from(addr: ZmqSocketAddr) -> Self {
        Url::from(&addr)
    }
}

#[cfg(feature = "url")]
impl From<&ZmqSocketAddr> for Url {
    fn from(addr: &ZmqSocketAddr) -> Self {
        Url::parse(&addr.to_url_string())
            .expect("Parsing URL string must not fail")
    }
}

#[cfg(feature = "url")]
impl TryFrom<Url> for ZmqSocketAddr {
    type Error = AddrError;

    fn try_from(url: Url) -> Result<Self, Self::Error> {
        match url.scheme() {
            "lnpz" => {
                if url.has_authority() {
                    Ok(ZmqSocketAddr::Tcp(SocketAddr::new(
                        url.host()
                            .ok_or(AddrError::HostRequired)?
                            .to_string()
                            .parse()?,
                        url.port().ok_or(AddrError::PortRequired)?,
                    )))
                } else {
                    Ok(ZmqSocketAddr::Ipc(url.path().to_owned()))
                }
            }
            "tcp" => Err(AddrError::UnknownUrlScheme(s!(
                "'tcp://'; use 'lnpz://' instead"
            ))),
            "inproc" => Ok(ZmqSocketAddr::Inproc(
                url.host_str().ok_or(AddrError::HostRequired)?.to_owned(),
            )),
            "ipc" => Err(AddrError::UnknownUrlScheme(s!(
                "'ipc:'; use 'lnpz:' instead"
            ))),
            unknown => Err(AddrError::UnknownUrlScheme(unknown.to_owned())),
        }
    }
}

pub struct WrappedSocket {
    api_type: ZmqType,
    socket: zmq::Socket,
}

pub struct Connection {
    api_type: ZmqType,
    input: WrappedSocket,
    output: Option<WrappedSocket>,
}

impl Connection {
    pub fn with(
        api_type: ZmqType,
        remote: &ZmqSocketAddr,
        local: Option<ZmqSocketAddr>,
        identity: Option<impl AsRef<[u8]>>,
    ) -> Result<Self, transport::Error> {
        let socket = ZMQ_CONTEXT.socket(api_type.socket_type())?;
        if let Some(identity) = identity {
            socket.set_identity(identity.as_ref())?;
        }
        let endpoint = remote.zmq_socket_string();
        match api_type {
            ZmqType::Pull
            | ZmqType::Rep
            | ZmqType::Pub
            | ZmqType::RouterBind => socket.bind(&endpoint)?,
            ZmqType::Push
            | ZmqType::Req
            | ZmqType::Sub
            | ZmqType::RouterConnect => socket.connect(&endpoint)?,
        }
        let output = match (api_type, local) {
            (ZmqType::Pull, Some(local)) => {
                let socket = ZMQ_CONTEXT.socket(zmq::SocketType::PUSH)?;
                socket.connect(&local.zmq_socket_string())?;
                Some(socket)
            }
            (ZmqType::Push, Some(local)) => {
                let socket = ZMQ_CONTEXT.socket(zmq::SocketType::PULL)?;
                socket.bind(&local.zmq_socket_string())?;
                Some(socket)
            }
            (ZmqType::Pull, None) | (ZmqType::Push, None) => {
                Err(transport::Error::RequiresLocalSocket)?
            }
            (_, _) => None,
        }
        .map(|s| WrappedSocket::from_zmq_socket(api_type, s));
        Ok(Self {
            api_type,
            input: WrappedSocket::from_zmq_socket(api_type, socket),
            output,
        })
    }

    pub fn from_zmq_socket(api_type: ZmqType, socket: zmq::Socket) -> Self {
        Self {
            api_type,
            input: WrappedSocket::from_zmq_socket(api_type, socket),
            output: None,
        }
    }

    #[inline]
    pub(crate) fn as_socket(&self) -> &zmq::Socket {
        &self.input.as_socket()
    }
}

impl WrappedSocket {
    #[inline]
    fn from_zmq_socket(api_type: ZmqType, socket: zmq::Socket) -> Self {
        Self { api_type, socket }
    }

    #[inline]
    pub(crate) fn as_socket(&self) -> &zmq::Socket {
        &self.socket
    }
}

impl Duplex for Connection {
    #[inline]
    fn as_receiver(&mut self) -> &mut dyn RecvFrame {
        &mut self.input
    }

    #[inline]
    fn as_sender(&mut self) -> &mut dyn SendFrame {
        self.output.as_mut().unwrap_or(&mut self.input)
    }

    fn split(self) -> (Box<dyn RecvFrame + Send>, Box<dyn SendFrame + Send>) {
        if self.api_type == ZmqType::Push || self.api_type == ZmqType::Pull {
            (
                Box::new(self.input),
                Box::new(self.output.expect(
                    "Splittable types always have output part present",
                )),
            )
        } else {
            // We panic here because this is a program architecture design
            // error and developer must be notified about it; the program using
            // this pattern can't work
            panic!(format!(
                "Split operation is impossible for ZMQ stream type {}",
                self.api_type
            ));
        }
    }
}

impl Bipolar for Connection {
    type Left = WrappedSocket;
    type Right = WrappedSocket;

    fn join(input: Self::Left, output: Self::Right) -> Self {
        // We panic here because this is a program architecture design
        // error and developer must be notified about it; the program using
        // this pattern can't work
        if input.api_type != output.api_type {
            panic!("ZMQ streams of different type can't be joined");
        }
        if input.api_type != ZmqType::Push || input.api_type == ZmqType::Pull {
            panic!(format!(
                "ZMQ streams of {} type can't be joined",
                input.api_type
            ));
        }
        Self {
            api_type: input.api_type.clone(),
            input,
            output: Some(output),
        }
    }

    fn split(self) -> (Self::Left, Self::Right) {
        if self.api_type == ZmqType::Push || self.api_type == ZmqType::Pull {
            (self.input, self.output.unwrap())
        } else {
            // We panic here because this is a program architecture design
            // error and developer must be notified about it; the program using
            // this pattern can't work
            panic!(format!(
                "Split operation is impossible for ZMQ stream type {}",
                self.api_type
            ));
        }
    }
}

impl RecvFrame for WrappedSocket {
    #[inline]
    fn recv_frame(&mut self) -> Result<Vec<u8>, transport::Error> {
        let data = self.socket.recv_bytes(0)?;
        let len = data.len();
        if len > super::MAX_FRAME_SIZE as usize {
            return Err(transport::Error::OversizedFrame(len));
        }
        Ok(data)
    }

    fn recv_raw(&mut self, len: usize) -> Result<Vec<u8>, transport::Error> {
        Ok(self.socket.recv_bytes(0)?)
    }

    fn recv_routed(&mut self) -> Result<RoutedFrame, transport::Error> {
        let mut multipart = self.socket.recv_multipart(0)?.into_iter();
        // Skipping previous hop data since we do not need them
        let hop = multipart.next().ok_or(transport::Error::FrameBroken(
            "zero frame parts in ZMQ multipart routed frame",
        ))?;
        let src = multipart.next().ok_or(transport::Error::FrameBroken(
            "no source part ZMQ multipart routed frame",
        ))?;
        let dst = multipart.next().ok_or(transport::Error::FrameBroken(
            "no destination part ZMQ multipart routed frame",
        ))?;
        let msg = multipart.next().ok_or(transport::Error::FrameBroken(
            "no message part in ZMQ multipart routed frame",
        ))?;
        if multipart.count() > 0 {
            Err(transport::Error::FrameBroken(
                "excessive parts in ZMQ multipart routed frame",
            ))?
        }
        let len = msg.len();
        if len > super::MAX_FRAME_SIZE as usize {
            Err(transport::Error::OversizedFrame(len))?
        }
        Ok(RoutedFrame { hop, src, dst, msg })
    }
}

impl SendFrame for WrappedSocket {
    #[inline]
    fn send_frame(&mut self, data: &[u8]) -> Result<usize, transport::Error> {
        let len = data.len();
        if len > super::MAX_FRAME_SIZE as usize {
            return Err(transport::Error::OversizedFrame(len));
        }
        self.socket.send(data, 0)?;
        Ok(len)
    }

    fn send_raw(&mut self, data: &[u8]) -> Result<usize, transport::Error> {
        self.socket.send(data, 0)?;
        Ok(data.len())
    }

    fn send_routed(
        &mut self,
        source: &[u8],
        route: &[u8],
        dest: &[u8],
        data: &[u8],
    ) -> Result<usize, transport::Error> {
        let len = data.len();
        if len > super::MAX_FRAME_SIZE as usize {
            return Err(transport::Error::OversizedFrame(len));
        }
        self.socket
            .send_multipart(&[route, source, dest, data], 0)?;
        Ok(data.len())
    }
}

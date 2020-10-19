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

use amplify::Bipolar;
#[cfg(feature = "url")]
use core::convert::TryFrom;
use core::fmt::{self, Display, Formatter};
#[cfg(feature = "url")]
use core::str::FromStr;
use std::net::SocketAddr;
use std::option::NoneError;
use std::path::PathBuf;
#[cfg(feature = "url")]
use url::Url;

use super::{Duplex, Error, Receiver, RecvFrame, SendFrame, Sender};

/// API type for node-to-node communications used by ZeroMQ
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Display)]
#[repr(u8)]
pub enum ApiType {
    /// Pure peer-to-peer communications done with PUSH/PULL pair of ZMQ
    /// sockets. Each node can send unordered set of messages and does not
    /// wait for a response.
    /// This part represents listening socket ([`zmq::SocketType::PULL`])
    #[display("p2p-listen")]
    PeerListening = 0,

    /// Pure peer-to-peer communications done with PUSH/PULL pair of ZMQ
    /// sockets. Each node can send unordered set of messages and does not
    /// wait for a response.
    /// This part represents connected socket ([`zmq::SocketType::PUSH`])
    #[display("p2p-connect")]
    PeerConnecting = 1,

    /// Remote procedure call communications done with REQ/REP pair of ZMQ
    /// sockets. Two roles: client and server; client sends requests and awaits
    /// for client responses.
    /// This part represents client-size socket ([`zmq::SocketType::REQ`])
    #[display("rpc-client")]
    Client = 2,

    /// Remote procedure call communications done with REQ/REP pair of ZMQ
    /// sockets. Two roles: client and server; client sends requests and awaits
    /// for client responses.
    /// This part represents client-size socket ([`zmq::SocketType::REP`])
    #[display("rpc-server")]
    Server = 3,

    /// Subscription API done with SUB/PUB pair of ZMQ sockets. Two roles:
    /// publisher (server) and subscriber (client); subscriber awaits for
    /// messages from publisher and does not communicates back.
    /// This part represents publisher part ([`zmq::SocketType::PUB`])
    #[display("pub")]
    Publish = 4,

    /// Subscription API done with SUB/PUB pair of ZMQ sockets. Two roles:
    /// publisher (server) and subscriber (client); subscriber awaits for
    /// messages from publisher and does not communicates back.
    /// This part represents subscriber part ([`zmq::SocketType::SUB`])
    #[display("sub")]
    Subscribe = 5,
}

impl ApiType {
    /// Returns [`zmq::SocketType`] corresponding to the given [`ApiType`]
    pub fn socket_type(&self) -> zmq::SocketType {
        match self {
            ApiType::PeerListening => zmq::PULL,
            ApiType::PeerConnecting => zmq::PUSH,
            ApiType::Client => zmq::REQ,
            ApiType::Server => zmq::REP,
            ApiType::Publish => zmq::PUB,
            ApiType::Subscribe => zmq::SUB,
        }
    }

    /// Returns name for the used ZMQ API type that can be used as a part of
    /// URL query
    pub fn api_name(&self) -> String {
        match self {
            ApiType::PeerListening | ApiType::PeerConnecting => s!("p2p"),
            ApiType::Client | ApiType::Server => s!("rpc"),
            ApiType::Publish | ApiType::Subscribe => s!("sub"),
        }
    }
}

impl FromStr for ApiType {
    type Err = NoneError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.to_lowercase();
        vec![
            ApiType::PeerConnecting,
            ApiType::PeerListening,
            ApiType::Client,
            ApiType::Server,
            ApiType::Publish,
            ApiType::Subscribe,
        ]
        .into_iter()
        .find(|api| api.to_string() == s)
        .ok_or(NoneError)
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", tag = "type")
)]
pub enum SocketLocator {
    Inproc(String),
    Ipc(PathBuf),
    Tcp(SocketAddr),
}

impl Display for SocketLocator {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            SocketLocator::Inproc(name) => {
                write!(f, "inproc://{}", name)?;
            }
            SocketLocator::Ipc(path) => {
                write!(f, "ipc://{}", path.display())?;
            }
            SocketLocator::Tcp(socket_addr) => {
                write!(f, "tcp://{}:{}", socket_addr.ip(), socket_addr.port())?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display, Error, From)]
#[display(Debug)]
pub enum UrlError {
    UnknownScheme(String),
    HostRequired,
    PortRequired,
    UnexpectedAuthority,
    #[cfg_attr(feature = "url", from(url::ParseError))]
    MalformedUrl,
    #[from(std::net::AddrParseError)]
    MalformedIp,
}

#[cfg(feature = "url")]
impl FromStr for SocketLocator {
    type Err = UrlError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url: Url = s.parse()?;
        Self::try_from(url)
    }
}

#[cfg(feature = "url")]
impl TryFrom<Url> for SocketLocator {
    type Error = UrlError;

    fn try_from(url: Url) -> Result<Self, Self::Error> {
        match url.scheme() {
            "tcp" => Ok(SocketLocator::Tcp(SocketAddr::new(
                url.host()
                    .ok_or(UrlError::HostRequired)?
                    .to_string()
                    .parse()?,
                url.port().ok_or(UrlError::PortRequired)?,
            ))),
            "inproc" => Ok(SocketLocator::Inproc(
                url.host().ok_or(UrlError::HostRequired)?.to_string(),
            )),
            "ipc" => {
                if url.has_authority() {
                    Err(UrlError::UnexpectedAuthority)
                } else {
                    Ok(SocketLocator::Ipc(PathBuf::from(url.path())))
                }
            }
            unknown => Err(UrlError::UnknownScheme(unknown.to_string())),
        }
    }
}

pub struct ConnectionInput {
    api_type: ApiType,
    input: zmq::Socket,
}

pub struct ConnectionOutput {
    api_type: ApiType,
    output: zmq::Socket,
}

pub struct Connection {
    api_type: ApiType,
    input: ConnectionInput,
    output: Option<ConnectionOutput>,
}

impl Connection {
    pub fn new(
        api_type: ApiType,
        context: &zmq::Context,
        remote: SocketLocator,
        local: Option<SocketLocator>,
    ) -> Result<Self, Error> {
        let socket = context.socket(api_type.socket_type())?;
        let endpoint = format!("{}", remote);
        match api_type {
            ApiType::PeerListening | ApiType::Server | ApiType::Publish => {
                socket.bind(endpoint.as_str())?
            }
            ApiType::PeerConnecting | ApiType::Client | ApiType::Subscribe => {
                socket.connect(endpoint.as_str())?
            }
        }
        let output = match (api_type, local) {
            (ApiType::PeerListening, Some(local)) => {
                let socket = context.socket(zmq::SocketType::PUSH)?;
                socket.connect(format!("{}", local).as_str())?;
                Some(socket)
            }
            (ApiType::PeerConnecting, Some(local)) => {
                let socket = context.socket(zmq::SocketType::PULL)?;
                socket.bind(format!("{}", local).as_str())?;
                Some(socket)
            }
            (ApiType::PeerListening, None)
            | (ApiType::PeerConnecting, None) => {
                Err(Error::RequiresLocalSocket)?
            }
            (_, _) => None,
        }
        .map(|s| ConnectionOutput::from_zmq_socket(api_type, s));
        Ok(Self {
            api_type,
            input: ConnectionInput::from_zmq_socket(api_type, socket),
            output,
        })
    }

    #[inline]
    pub(crate) fn as_socket(&self) -> &zmq::Socket {
        &self.input.as_socket()
    }
}

impl ConnectionInput {
    #[inline]
    fn from_zmq_socket(api_type: ApiType, socket: zmq::Socket) -> Self {
        Self {
            api_type,
            input: socket,
        }
    }

    #[inline]
    pub(crate) fn as_socket(&self) -> &zmq::Socket {
        &self.input
    }
}

impl ConnectionOutput {
    #[inline]
    fn from_zmq_socket(api_type: ApiType, socket: zmq::Socket) -> Self {
        Self {
            api_type,
            output: socket,
        }
    }

    #[inline]
    pub(crate) fn as_socket(&self) -> &zmq::Socket {
        &self.output
    }
}

impl Receiver for ConnectionInput {
    type Recv = zmq::Socket;

    #[inline]
    fn receiver(&mut self) -> &mut Self::Recv {
        &mut self.input
    }
}

impl Sender for ConnectionInput {
    type Send = zmq::Socket;

    #[inline]
    fn sender(&mut self) -> &mut Self::Send {
        &mut self.input
    }
}

impl Sender for ConnectionOutput {
    type Send = zmq::Socket;

    #[inline]
    fn sender(&mut self) -> &mut Self::Send {
        &mut self.output
    }
}

impl Receiver for Connection {
    type Recv = zmq::Socket;

    #[inline]
    fn receiver(&mut self) -> &mut Self::Recv {
        self.input.receiver()
    }
}

impl Sender for Connection {
    type Send = zmq::Socket;

    fn sender(&mut self) -> &mut Self::Send {
        match self.output {
            None => self.input.sender(),
            Some(ref mut output) => output.sender(),
        }
    }
}

impl Duplex for Connection {
    type Receiver = ConnectionInput;
    type Sender = ConnectionOutput;
}

impl Bipolar for Connection {
    type Left = <Self as Duplex>::Receiver;
    type Right = <Self as Duplex>::Sender;

    fn join(input: Self::Left, output: Self::Right) -> Self {
        // We panic here because this is a program architecture design
        // error and developer must be notified about it; the program using
        // this pattern can't work
        if input.api_type != output.api_type {
            panic!("ZMQ streams of different type can't be joined");
        }
        if input.api_type != ApiType::PeerConnecting
            || input.api_type == ApiType::PeerListening
        {
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
        if self.api_type == ApiType::PeerConnecting
            || self.api_type == ApiType::PeerListening
        {
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

impl RecvFrame for zmq::Socket {
    #[inline]
    fn recv_frame(&mut self) -> Result<Vec<u8>, Error> {
        let data = self.recv_bytes(0)?;
        let len = data.len();
        if len > super::MAX_FRAME_SIZE as usize {
            return Err(Error::OversizedFrame(len));
        }
        Ok(data)
    }

    fn recv_raw(&mut self, len: usize) -> Result<Vec<u8>, Error> {
        Ok(self.recv_bytes(0)?)
    }

    fn recv_addr(&mut self) -> Result<(Vec<u8>, Vec<u8>), Error> {
        unimplemented!()
    }
}

impl SendFrame for zmq::Socket {
    #[inline]
    fn send_frame(&mut self, data: impl AsRef<[u8]>) -> Result<usize, Error> {
        let data = data.as_ref();
        let len = data.len();
        if len > super::MAX_FRAME_SIZE as usize {
            return Err(Error::OversizedFrame(len));
        }
        self.send(data, 0)?;
        Ok(len)
    }

    fn send_raw(&mut self, data: impl AsRef<[u8]>) -> Result<usize, Error> {
        let data = data.as_ref();
        self.send(data, 0)?;
        Ok(data.len())
    }

    fn send_addr(
        &mut self,
        dest: impl AsRef<[u8]>,
        data: impl AsRef<[u8]>,
    ) -> Result<usize, Error> {
        unimplemented!()
    }
}

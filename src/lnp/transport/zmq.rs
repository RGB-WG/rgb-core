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

use core::borrow::Borrow;
use core::fmt::{self, Display, Formatter};
use std::net::SocketAddr;
use std::path::PathBuf;

use super::{Bidirect, Error, Input, Output, Read, Write};
use crate::Bipolar;

/// API type for node-to-node communications used by ZeroMQ
#[derive(Clone, PartialEq, Eq, Hash, Debug, Display, Copy)]
#[display_from(Debug)]
#[repr(u8)]
pub enum ApiType {
    /// Pure peer-to-peer communications done with PUSH/PULL pair of ZMQ sockets.
    /// Each node can send unordered set of messages and does not wait for a
    /// response.
    PeerListening = 0,
    PeerConnecting = 1,

    /// Remote procedure call communications done with REQ/REP pair of ZMQ
    /// sockets. Two roles: client and server; client sends requests and awaits
    /// for client responses.
    Client = 2,
    Server = 3,

    /// Subscription API done with SUB/PUB pair of ZMQ sockets. Two roles:
    /// publisher (server) and subscriber (client); subscriber awaits for
    /// messages from publisher and does not communicates back.
    Publish = 4,
    Subscribe = 5,
}

impl ApiType {
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
}

pub enum SocketLocator {
    Inproc(String),
    Posix(PathBuf),
    Tcp(SocketAddr),
}

impl Display for SocketLocator {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            SocketLocator::Inproc(name) => {
                write!(f, "inproc://{}", name)?;
            }
            SocketLocator::Posix(path) => {
                write!(f, "ipc://{}", path.display())?;
            }
            SocketLocator::Tcp(socket_addr) => {
                write!(f, "tcp://{}:{}", socket_addr.ip(), socket_addr.port())?;
            }
        }
        Ok(())
    }
}

pub struct InputStream {
    api_type: ApiType,
    input: zmq::Socket,
}

pub struct OutputStream {
    api_type: ApiType,
    output: zmq::Socket,
}

pub struct Connection {
    api_type: ApiType,
    input: InputStream,
    output: Option<OutputStream>,
}

impl Connection {
    pub fn new(
        api_type: ApiType,
        context: &mut zmq::Context,
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
            (ApiType::PeerListening, None) | (ApiType::PeerConnecting, None) => {
                Err(Error::RequiresLocalSocket)?
            }
            (_, _) => None,
        }
        .map(|s| OutputStream::from_zmq_socket(api_type, s));
        Ok(Self {
            api_type,
            input: InputStream::from_zmq_socket(api_type, socket),
            output,
        })
    }
}

impl InputStream {
    fn from_zmq_socket(api_type: ApiType, socket: zmq::Socket) -> Self {
        Self {
            api_type,
            input: socket,
        }
    }
}

impl OutputStream {
    fn from_zmq_socket(api_type: ApiType, socket: zmq::Socket) -> Self {
        Self {
            api_type,
            output: socket,
        }
    }
}

impl Input for InputStream {
    type Reader = zmq::Socket;

    fn reader(&self) -> &Self::Reader {
        &self.input
    }
}

impl Output for InputStream {
    type Writer = zmq::Socket;

    fn writer(&self) -> &Self::Writer {
        &self.input
    }
}

impl Output for OutputStream {
    type Writer = zmq::Socket;

    fn writer(&self) -> &Self::Writer {
        &self.output
    }
}

impl Input for Connection {
    type Reader = zmq::Socket;

    fn reader(&self) -> &Self::Reader {
        self.input.reader()
    }
}

impl Output for Connection {
    type Writer = zmq::Socket;

    fn writer(&self) -> &Self::Writer {
        match self.output {
            None => &self.input.writer(),
            Some(ref output) => &output.writer(),
        }
    }
}

impl Bidirect for Connection {
    type Input = InputStream;
    type Output = OutputStream;
}

impl Bipolar for Connection {
    type Left = <Self as Bidirect>::Input;
    type Right = <Self as Bidirect>::Output;

    fn split(self) -> (Self::Left, Self::Right) {
        if self.api_type == ApiType::PeerConnecting || self.api_type == ApiType::PeerListening {
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

    fn join(input: Self::Left, output: Self::Right) -> Self {
        // We panic here because this is a program architecture design
        // error and developer must be notified about it; the program using
        // this pattern can't work
        if input.api_type != output.api_type {
            panic!("ZMQ streams of different type can't be joined");
        }
        if input.api_type != ApiType::PeerConnecting || input.api_type == ApiType::PeerListening {
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
}

impl Read for zmq::Socket {
    fn read(&mut self) -> Result<Vec<u8>, Error> {
        Ok(self.recv_bytes(0)?)
    }
}

impl Write for zmq::Socket {
    fn write(&mut self, data: impl Borrow<[u8]>) -> Result<usize, Error> {
        self.send(data.borrow(), 0)?;
        Ok(data.borrow().len())
    }
}

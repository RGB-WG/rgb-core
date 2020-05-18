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
use std::net::SocketAddr;
use std::path::PathBuf;

use super::{Bidirect, Error, Input, Output, Read, Write};

/// API type for node-to-node communications used by ZeroMQ
#[derive(Clone, PartialEq, Eq, Hash, Debug, Display)]
#[display_from(Debug)]
#[repr(u8)]
pub enum ApiType {
    /// Pure peer-to-peer communications done with PUSH/PULL pair of ZMQ sockets.
    /// Each node can send unordered set of messages and does not wait for a
    /// response.
    P2p = 0,

    /// Remote procedure call communications done with REQ/REP pair of ZMQ
    /// sockets. Two roles: client and server; client sends requests and awaits
    /// for client responses.
    Rpc = 1,

    /// Subscription API done with SUB/PUB pair of ZMQ sockets. Two roles:
    /// publisher (server) and subscriber (client); subscriber awaits for
    /// messages from publisher and does not communicates back.
    Sub = 2,
}

pub enum SocketLocator {
    Inproc(String),
    Posix(PathBuf),
    Tcp(SocketAddr),
}

pub struct InputStream {
    input: zmq::Socket,
}

pub struct OutputStream {
    output: zmq::Socket,
}

pub struct Connection {
    input: InputStream,
    output: OutputStream,
}

impl Connection {
    pub fn new(
        api_type: ApiType,
        remote: SocketLocator,
        local: SocketLocator,
    ) -> Result<Self, Error> {
        unimplemented!()
    }
}

impl From<zmq::Socket> for InputStream {
    fn from(socket: zmq::Socket) -> Self {
        Self { input: socket }
    }
}

impl From<zmq::Socket> for OutputStream {
    fn from(socket: zmq::Socket) -> Self {
        Self { output: socket }
    }
}

impl Input for InputStream {
    type Reader = zmq::Socket;

    fn reader(&self) -> &Self::Reader {
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
        self.output.writer()
    }
}

impl Bidirect for Connection {
    type Input = InputStream;
    type Output = OutputStream;

    fn split(self) -> (Self::Input, Self::Output) {
        (self.input, self.output)
    }

    fn join(input: Self::Input, output: Self::Output) -> Self {
        Self { input, output }
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

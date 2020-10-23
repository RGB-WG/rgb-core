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
use core::borrow::Borrow;

use super::{Decrypt, Encrypt, Transcode};
use crate::lnp::session::{LocalNode, NoEncryption, NodeAddr};
use crate::lnp::transport::{
    ftcp, zmqsocket, AsReceiver, AsSender, Connection, Error, RecvFrame,
    RemoteAddr, SendFrame,
};
use amplify::internet::InetSocketAddr;

pub struct Session<T, C>
where
    T: Transcode,
    T::Left: Decrypt,
    T::Right: Encrypt,
    C: Connection + AsReceiver + AsSender + Bipolar,
    C::Left: RecvFrame,
    C::Right: SendFrame,
{
    transcoder: T,
    connection: C,
}

pub struct SessionInput<D, R>
where
    D: Decrypt,
    R: RecvFrame,
{
    pub(self) decryptor: D,
    pub(self) input: R,
}

pub struct SessionOutput<E, S>
where
    E: Encrypt,
    S: SendFrame,
{
    pub(self) encryptor: E,
    pub(self) output: S,
}

impl<T, C> AsReceiver for Session<T, C>
where
    T: Transcode,
    T::Left: Decrypt,
    T::Right: Encrypt,
    C: Connection + AsReceiver + AsSender + Bipolar,
    C::Left: RecvFrame,
    C::Right: SendFrame,
{
    type Receiver = C::Receiver;

    fn as_receiver(&mut self) -> &mut Self::Receiver {
        self.connection.as_receiver()
    }
}

impl<T, C> AsSender for Session<T, C>
where
    T: Transcode,
    T::Left: Decrypt,
    T::Right: Encrypt,
    C: Connection + AsReceiver + AsSender + Bipolar,
    C::Left: RecvFrame,
    C::Right: SendFrame,
{
    type Sender = C::Sender;

    fn as_sender(&mut self) -> &mut Self::Sender {
        self.connection.as_sender()
    }
}

impl<T, C> Bipolar for Session<T, C>
where
    T: Transcode,
    T::Left: Decrypt,
    T::Right: Encrypt,
    C: Connection + AsReceiver + AsSender + Bipolar,
    C::Left: RecvFrame,
    C::Right: SendFrame,
{
    type Left = SessionInput<T::Left, C::Left>;
    type Right = SessionOutput<T::Right, C::Right>;

    fn join(_left: Self::Left, _right: Self::Right) -> Self {
        unimplemented!()
    }

    fn split(self) -> (Self::Left, Self::Right) {
        unimplemented!()
    }
}

impl Session<NoEncryption, ftcp::Connection> {
    pub(self) fn with_ftcp_unencrypted(
        socket_addr: InetSocketAddr,
    ) -> Result<Self, Error> {
        unimplemented!()
    }
}

impl Session<NoEncryption, zmqsocket::Connection> {
    /*
    pub fn with_zmq_unencrypted(
        zmq_type: zmqsocket::ApiType,
        context: &zmq::Context,
        remote: zmqsocket::SocketLocator,
        local: Option<zmqsocket::SocketLocator>,
    ) -> Result<Self, transport::Error> {
        Ok(Self {
            transcoder: NoEncryption,
            transport: zmqsocket::Connection::new(
                zmq_type, context, remote, local,
            )?,
        })
    }
     */

    pub fn as_socket(&self) -> &zmq::Socket {
        &self.connection.as_socket()
    }
}

impl<T, C> Session<T, C>
where
    T: Transcode,
    T::Left: Decrypt,
    T::Right: Encrypt,
    C: Connection + AsReceiver + AsSender + Bipolar,
    C::Left: RecvFrame,
    C::Right: SendFrame,
    // TODO: (new) Use session-level error type
    Error: From<T::Error>,
{
    pub fn recv_raw_message(&mut self) -> Result<Vec<u8>, Error> {
        let reader = self.connection.as_receiver();
        Ok(self.transcoder.decrypt(reader.recv_frame()?)?)
    }

    pub fn send_raw_message(
        &mut self,
        raw: impl Borrow<[u8]>,
    ) -> Result<usize, Error> {
        let writer = self.connection.as_sender();
        Ok(writer.send_frame(self.transcoder.encrypt(raw))?)
    }
}

impl NodeAddr {
    pub fn connect(
        &self,
        local: LocalNode,
    ) -> Result<Box<dyn Connection>, Error> {
        Ok(match self.remote_addr {
            RemoteAddr::Ftcp(inet) => {
                Box::new(Session::with_ftcp_unencrypted(inet)?)
            }
            RemoteAddr::Posix(_) => unimplemented!(),
            #[cfg(feature = "zmq")]
            RemoteAddr::Zmq(_) => unimplemented!(),
            RemoteAddr::Http(_) => unimplemented!(),
            #[cfg(feature = "websocket")]
            RemoteAddr::Websocket(_) => unimplemented!(),
            RemoteAddr::Smtp(_) => unimplemented!(),
        })
    }
}

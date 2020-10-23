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
use crate::lnp::session::NoEncryption;
use crate::lnp::transport::{
    zmqsocket, AsReceiver, AsSender, Connection, Error, RecvFrame, SendFrame,
};

pub struct Session<T, C>
where
    T: Transcode,
    C: Connection,
{
    transcoder: T,
    transport: C,
}

pub struct SessionInput<D, R>
where
    D: Decrypt,
    R: AsReceiver,
{
    pub(self) decryptor: D,
    pub(self) input: R,
}

pub struct SessionOutput<E, S>
where
    E: Encrypt,
    S: AsSender,
{
    pub(self) encryptor: E,
    pub(self) output: S,
}

impl Session<NoEncryption, zmqsocket::Connection> {
    /*
    pub fn new_zmq_unencrypted(
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
        &self.transport.as_socket()
    }
}

impl<T, C> Bipolar for Session<T, C>
where
    T: Transcode,
    T::Left: Decrypt,
    T::Right: Encrypt,
    C: Connection,
    C::Left: AsReceiver,
    C::Right: AsSender,
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

impl<T, C> Session<T, C>
where
    T: Transcode,
    C: Connection,
    // TODO: (new) Use session-level error type
    Error: From<T::Error>,
{
    pub fn recv_raw_message(&mut self) -> Result<Vec<u8>, Error> {
        let reader = self.transport.as_receiver();
        Ok(self.transcoder.decrypt(reader.recv_frame()?)?)
    }

    pub fn send_raw_message(
        &mut self,
        raw: impl Borrow<[u8]>,
    ) -> Result<usize, Error> {
        let writer = self.transport.as_sender();
        Ok(writer.send_frame(self.transcoder.encrypt(raw))?)
    }
}

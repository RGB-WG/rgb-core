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

use super::{Decrypt, Encrypt, NodeLocator, Transcode};
use crate::lnp::session::NoEncryption;
use crate::lnp::transport::{
    self, zmqsocket, AsReceiver, AsSender, Duplex, RecvFrame, SendFrame,
};

pub struct Session<Transcoder, Transport>
where
    Transcoder: Transcode,
    Transport: transport::Duplex,
{
    transcoder: Transcoder,
    transport: Transport,
}

pub struct SessionInput<Decryptor, Input>
where
    Decryptor: Decrypt,
    Input: AsReceiver,
{
    pub(self) decryptor: Decryptor,
    pub(self) input: Input,
}

pub struct SessionOutput<Encryptor, Output>
where
    Encryptor: Encrypt,
    Output: AsSender,
{
    pub(self) encryptor: Encryptor,
    pub(self) output: Output,
}

impl<Trascoder, Transport> Session<Trascoder, Transport>
where
    Trascoder: Transcode,
    Transport: transport::Duplex,
{
    pub fn new(_node_locator: NodeLocator) -> Result<Self, transport::Error> {
        unimplemented!()
    }
}

impl Session<NoEncryption, zmqsocket::Connection> {
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

    pub fn as_socket(&self) -> &zmq::Socket {
        &self.transport.as_socket()
    }
}

impl<Transcoder, Transport> Bipolar for Session<Transcoder, Transport>
where
    Transcoder: Transcode,
    Transcoder::Left: Decrypt,
    Transcoder::Right: Encrypt,
    Transport: Duplex,
    Transport::Left: AsReceiver,
    Transport::Right: AsSender,
{
    type Left = SessionInput<Transcoder::Left, Transport::Left>;
    type Right = SessionOutput<Transcoder::Right, Transport::Right>;

    fn join(_left: Self::Left, _right: Self::Right) -> Self {
        unimplemented!()
    }

    fn split(self) -> (Self::Left, Self::Right) {
        unimplemented!()
    }
}

impl<Transcoder, Transport> Session<Transcoder, Transport>
where
    Transcoder: Transcode,
    Transport: Duplex,
    // TODO: (new) Use session-level error type
    transport::Error: From<Transcoder::Error>,
{
    pub fn recv_raw_message(&mut self) -> Result<Vec<u8>, transport::Error> {
        let reader = self.transport.as_receiver();
        Ok(self.transcoder.decrypt(reader.recv_frame()?)?)
    }

    pub fn send_raw_message(
        &mut self,
        raw: impl Borrow<[u8]>,
    ) -> Result<usize, transport::Error> {
        let writer = self.transport.as_sender();
        Ok(writer.send_frame(self.transcoder.encrypt(raw))?)
    }
}

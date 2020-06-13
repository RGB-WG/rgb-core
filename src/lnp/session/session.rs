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

use amplify::AsAny;
use core::borrow::Borrow;

use super::{Decrypt, Encrypt, NodeLocator, Transcode};
use crate::lnp::session::NoEncryption;
use crate::lnp::transport::zmq::{ApiType as ZmqType, Connection, SocketLocator};
use crate::lnp::transport::{self, Bidirect, Error, Input, Output, Read, Write};
use crate::Bipolar;

pub trait SessionTrait: Bipolar + AsAny {}

pub struct Session<T, S>
where
    T: Transcode,
    S: Bidirect,
{
    transcoder: T,
    stream: S,
}

pub struct Inbound<D, I>
where
    D: Decrypt,
    I: Input,
{
    pub(self) decryptor: D,
    pub(self) input: I,
}

pub struct Outbound<E, O>
where
    E: Encrypt,
    O: Output,
{
    pub(self) encryptor: E,
    pub(self) output: O,
}

impl<T, S> Session<T, S>
where
    T: Transcode,
    S: Bidirect,
{
    pub fn new(_node_locator: NodeLocator) -> Result<Self, Error> {
        unimplemented!()
    }
}

impl Session<NoEncryption, transport::zmq::Connection> {
    pub fn new_zmq_unencrypted(
        zmq_type: ZmqType,
        context: &mut zmq::Context,
        remote: SocketLocator,
        local: Option<SocketLocator>,
    ) -> Result<Self, Error> {
        Ok(Self {
            transcoder: NoEncryption,
            stream: Connection::new(zmq_type, context, remote, local)?,
        })
    }
}

impl<T, S> Bipolar for Session<T, S>
where
    T: Transcode,
    T::Left: Decrypt,
    T::Right: Encrypt,
    S: Bidirect,
    S::Left: Input,
    S::Right: Output,
{
    type Left = Inbound<T::Left, S::Left>;
    type Right = Outbound<T::Right, S::Right>;

    fn join(_left: Self::Left, _right: Self::Right) -> Self {
        unimplemented!()
    }

    fn split(self) -> (Self::Left, Self::Right) {
        unimplemented!()
    }
}

impl<T, S> Session<T, S>
where
    T: Transcode,
    S: Bidirect,
    Error: From<T::Error>,
{
    pub fn recv_raw_message(&mut self) -> Result<Vec<u8>, Error> {
        let reader = self.stream.reader();
        Ok(self.transcoder.decrypt(reader.read()?)?)
    }

    pub fn send_raw_message(&mut self, raw: impl Borrow<[u8]>) -> Result<usize, Error> {
        let writer = self.stream.writer();
        Ok(writer.write(self.transcoder.encrypt(raw))?)
    }
}

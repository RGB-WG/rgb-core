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

use amplify::{internet::InetSocketAddr, Bipolar};
use core::any::Any;

use super::{Decrypt, Encrypt, Transcode};
use crate::lnp::session::NoEncryption;
use crate::lnp::transport::{
    ftcp, zmqsocket, Duplex, Error, RecvFrame, SendFrame,
};

// Generics prevents us from using session as `&dyn` reference, so we have
// to avoid `where Self: Input + Output` and generic parameters, unlike with
// `Transcode`
pub trait Session {
    fn recv_raw_message(&mut self) -> Result<Vec<u8>, Error>;
    fn send_raw_message(&mut self, raw: &[u8]) -> Result<usize, Error>;
    fn into_any(self: Box<Self>) -> Box<dyn Any>;
}

pub trait Split {
    fn split(self) -> (Box<dyn Input + Send>, Box<dyn Output + Send>);
}

pub trait Input {
    fn recv_raw_message(&mut self) -> Result<Vec<u8>, Error>;
}

pub trait Output {
    fn send_raw_message(&mut self, raw: &[u8]) -> Result<usize, Error>;
}

pub struct Raw<T, C>
where
    T: Transcode,
    T::Left: Decrypt,
    T::Right: Encrypt,
    C: Duplex + Bipolar,
    C::Left: RecvFrame,
    C::Right: SendFrame,
{
    pub(self) transcoder: T,
    pub(self) connection: C,
}

pub struct RawInput<D, R>
where
    D: Decrypt,
    R: RecvFrame,
{
    pub(self) decryptor: D,
    pub(self) input: R,
}

pub struct RawOutput<E, S>
where
    E: Encrypt,
    S: SendFrame,
{
    pub(self) encryptor: E,
    pub(self) output: S,
}

impl<T, C> Session for Raw<T, C>
where
    T: Transcode + 'static,
    T::Left: Decrypt,
    T::Right: Encrypt,
    C: Duplex + Bipolar + 'static,
    C::Left: RecvFrame,
    C::Right: SendFrame,
    Error: From<T::Error> + From<<T::Left as Decrypt>::Error>,
{
    #[inline]
    fn recv_raw_message(&mut self) -> Result<Vec<u8>, Error> {
        let reader = self.connection.as_receiver();
        Ok(self.transcoder.decrypt(reader.recv_frame()?)?)
    }

    #[inline]
    fn send_raw_message(&mut self, raw: &[u8]) -> Result<usize, Error> {
        let writer = self.connection.as_sender();
        Ok(writer.send_frame(&self.transcoder.encrypt(raw))?)
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

impl<T, C> Split for Raw<T, C>
where
    T: Transcode,
    T::Left: Decrypt + Send + 'static,
    T::Right: Encrypt + Send + 'static,
    C: Duplex + Bipolar,
    C::Left: RecvFrame + Send + 'static,
    C::Right: SendFrame + Send + 'static,
    Error: From<T::Error> + From<<T::Left as Decrypt>::Error>,
{
    #[inline]
    fn split(self) -> (Box<dyn Input + Send>, Box<dyn Output + Send>) {
        let (decryptor, encryptor) = self.transcoder.split();
        let (input, output) = Bipolar::split(self.connection);
        (
            Box::new(RawInput { decryptor, input }),
            Box::new(RawOutput { encryptor, output }),
        )
    }
}

impl Raw<NoEncryption, ftcp::Connection> {
    pub fn with_ftcp_unencrypted(
        stream: std::net::TcpStream,
        socket_addr: InetSocketAddr,
    ) -> Result<Self, Error> {
        Ok(Self {
            transcoder: NoEncryption,
            connection: ftcp::Connection::with(stream, socket_addr),
        })
    }

    pub fn connect_ftcp_unencrypted(
        socket_addr: InetSocketAddr,
    ) -> Result<Self, Error> {
        Ok(Self {
            transcoder: NoEncryption,
            connection: ftcp::Connection::connect(socket_addr)?,
        })
    }

    pub fn accept_ftcp_unencrypted(
        socket_addr: InetSocketAddr,
    ) -> Result<Self, Error> {
        Ok(Self {
            transcoder: NoEncryption,
            connection: ftcp::Connection::accept(socket_addr)?,
        })
    }
}

impl Raw<NoEncryption, zmqsocket::Connection> {
    pub fn with_zmq_unencrypted(
        zmq_type: zmqsocket::ApiType,
        remote: &zmqsocket::SocketLocator,
        local: Option<zmqsocket::SocketLocator>,
        identity: Option<&[u8]>,
    ) -> Result<Self, Error> {
        Ok(Self {
            transcoder: NoEncryption,
            connection: zmqsocket::Connection::with(
                zmq_type, remote, local, identity,
            )?,
        })
    }

    pub fn from_pair_socket(
        zmq_type: zmqsocket::ApiType,
        socket: zmq::Socket,
    ) -> Self {
        Self {
            transcoder: NoEncryption,
            connection: zmqsocket::Connection::from_zmq_socket(
                zmq_type, socket,
            ),
        }
    }

    pub fn recv_addr_message(&mut self) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let mut multipart = self.as_socket().recv_multipart(0)?.into_iter();
        let addr = multipart.next().ok_or(zmq::Error::EPROTO)?;
        let msg = self
            .transcoder
            .decrypt(multipart.next().ok_or(zmq::Error::EPROTO)?)?;
        Ok((addr, msg))
    }

    pub fn send_addr_message(
        &mut self,
        addr: impl AsRef<[u8]>,
        raw: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        let encrypted = self.transcoder.encrypt(raw.as_ref());
        self.as_socket()
            .send_multipart(&[addr.as_ref(), &encrypted], 0)?;
        Ok(())
    }

    pub fn as_socket(&self) -> &zmq::Socket {
        &self.connection.as_socket()
    }
}

impl<T, C> Input for RawInput<T, C>
where
    T: Decrypt,
    C: RecvFrame,
    // TODO: (new) Use session-level error type
    Error: From<T::Error>,
{
    fn recv_raw_message(&mut self) -> Result<Vec<u8>, Error> {
        Ok(self.decryptor.decrypt(self.input.recv_frame()?)?)
    }
}

impl<T, C> Output for RawOutput<T, C>
where
    T: Encrypt,
    C: SendFrame,
    // TODO: (new) Use session-level error type
{
    fn send_raw_message(&mut self, raw: &[u8]) -> Result<usize, Error> {
        Ok(self.output.send_frame(&self.encryptor.encrypt(raw))?)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_zmq_no_encryption() {
        let locator = zmqsocket::SocketLocator::Inproc(s!("test"));
        let mut rx = Raw::with_zmq_unencrypted(
            zmqsocket::ApiType::Server,
            &locator,
            None,
            None,
        )
        .unwrap();
        let mut tx = Raw::with_zmq_unencrypted(
            zmqsocket::ApiType::Client,
            &locator,
            None,
            None,
        )
        .unwrap();

        let msg = b"Some message";
        tx.send_raw_message(msg).unwrap();
        assert_eq!(rx.recv_raw_message().unwrap(), msg);

        let msg = b"";
        rx.send_raw_message(msg).unwrap();
        assert_eq!(tx.recv_raw_message().unwrap(), msg);
    }
}

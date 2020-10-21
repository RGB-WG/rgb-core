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

//! LNP transport level works with framed messages of defined size. This
//! messages can be put into different underlying transport protocols, including
//! streaming protocols (like TCP), or overlayed over application-level
//! protocols like HTTP, Websockets, SMTP (for high-latency communication
//! networks). Current mod implements such overlayes and provides TCP with
//! the required framing functionality (this variant is called FTCP). It also
//! integrates with ZMQ such that the upper level can abstract for a particular
//! transport protocol used.

pub mod ftcp;
mod remote_addr;
pub mod websocket;
#[cfg(feature = "zmq")]
pub mod zmqsocket;

pub use remote_addr::RemoteAddr;

use amplify::Bipolar;

/// Maximum size of the transport frame; chosen in compliance with LN specs
pub const MAX_FRAME_SIZE: usize =
    FRAME_PREFIX_SIZE + MAX_FRAME_PAYLOAD_SIZE + GRAME_SUFFIX_SIZE;

/// Size of the frame prefix which is not included into payload size, consisting
/// of the 2-bytes message size data and 16-byte MAC of the payload length
pub const FRAME_PREFIX_SIZE: usize = 2 + 16;

/// Size of the frame suffix represented by a 16-byte MAC of the frame payload
pub const GRAME_SUFFIX_SIZE: usize = 16;

/// Maximum size of the frame payload which may be expressed by two bytes
pub const MAX_FRAME_PAYLOAD_SIZE: usize = 0xFFFF;

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display, Error, From)]
#[display(Debug)]
pub enum Error {
    #[from(zmq::Error)]
    #[from(std::io::Error)]
    SocketError,

    RequiresLocalSocket,

    // TODO: (v0.2) Make session-specific error type and move there
    #[from(crate::lnp::session::NoError)]
    EncodingError,

    /// The provided frame size ({_0}) exceeds frame size limit of
    /// MAX_FRAME_SIZE bytes
    OversizedFrame(usize),
}

pub trait Receiver {
    type Recv: RecvFrame;
    fn receiver(&mut self) -> &mut Self::Recv;
}

pub trait Sender {
    type Send: SendFrame;
    fn sender(&mut self) -> &mut Self::Send;
}

pub trait Duplex: Receiver + Sender + Bipolar {
    type Receiver: Receiver;
    type Sender: Sender;
}

pub trait RecvFrame {
    fn recv_frame(&mut self) -> Result<Vec<u8>, Error>;
    fn recv_raw(&mut self, len: usize) -> Result<Vec<u8>, Error>;
    fn recv_addr(&mut self) -> Result<(Vec<u8>, Vec<u8>), Error> {
        // We panic here because this is a program architecture design
        // error and developer must be notified about it; the program using
        // this pattern can't work
        panic!("Multipeer sockets are not possible with the chosen  transport")
    }
}

pub trait SendFrame {
    fn send_frame(&mut self, data: impl AsRef<[u8]>) -> Result<usize, Error>;
    fn send_raw(&mut self, data: impl AsRef<[u8]>) -> Result<usize, Error>;
    fn send_addr(
        &mut self,
        dest: impl AsRef<[u8]>,
        data: impl AsRef<[u8]>,
    ) -> Result<usize, Error> {
        // We panic here because this is a program architecture design
        // error and developer must be notified about it; the program using
        // this pattern can't work
        panic!("Multipeer sockets are not possible with the chosen  transport")
    }
}

#[cfg(feature = "async")]
#[async_trait]
pub trait AsyncRecvFrame {
    async fn recv_frame(&mut self) -> Result<Vec<u8>, Error>;
    async fn recv_raw(&mut self, len: usize) -> Result<Vec<u8>, Error>;
    async fn recv_addr(&mut self) -> Result<(Vec<u8>, Vec<u8>), Error> {
        // We panic here because this is a program architecture design
        // error and developer must be notified about it; the program using
        // this pattern can't work
        panic!("Multipeer sockets are not possible with the chosen  transport")
    }
}

#[cfg(feature = "async")]
#[async_trait]
pub trait AsyncSendFrame {
    async fn send_frame(&mut self, data: &[u8]) -> Result<usize, Error>;

    async fn send_raw(&mut self, data: &[u8]) -> Result<usize, Error>;

    async fn send_addr(
        &mut self,
        dest: &[u8],
        data: &[u8],
    ) -> Result<usize, Error> {
        // We panic here because this is a program architecture design
        // error and developer must be notified about it; the program using
        // this pattern can't work
        panic!("Multipeer sockets are not possible with the chosen  transport")
    }
}

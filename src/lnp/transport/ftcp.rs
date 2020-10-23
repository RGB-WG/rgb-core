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

//! Framed TCP protocol: reads & writes frames (corresponding to LNP messages)
//! from TCP stream

use amplify::Bipolar;
use bitcoin::consensus::encode::ReadExt;
use std::io::{Read, Write};

use super::{AsReceiver, AsSender, Error, RecvFrame, SendFrame};

/// Wraps TcpStream
///
/// We need this wrapper structure since we can't implement foreign traits, such
/// as Bipolar, for a foreign type.
#[derive(Debug)]
pub struct Connection(std::net::TcpStream);

impl AsReceiver for Connection {
    type Receiver = std::net::TcpStream;

    fn as_receiver(&mut self) -> &mut Self::Receiver {
        &mut self.0
    }
}

impl AsSender for Connection {
    type Sender = std::net::TcpStream;

    fn as_sender(&mut self) -> &mut Self::Sender {
        &mut self.0
    }
}

impl Bipolar for Connection {
    type Left = std::net::TcpStream;
    type Right = std::net::TcpStream;

    fn join(left: Self::Left, right: Self::Right) -> Self {
        #[cfg(not(target_os = "windows"))]
        use std::os::unix::io::AsRawFd;
        #[cfg(target_os = "windows")]
        use std::os::windows::io::AsRawSocket;

        #[cfg(not(target_os = "windows"))]
        assert_eq!(
            left.as_raw_fd(),
            right.as_raw_fd(),
            "Two independent TCP sockets can't be joined"
        );
        #[cfg(target_os = "windows")]
        assert_eq!(
            left.as_raw_socket(),
            right.as_raw_socket(),
            "Two independent TCP sockets can't be joined"
        );
        Self(left)
    }

    fn split(self) -> (Self::Left, Self::Right) {
        (
            self.0.try_clone().expect("TcpStream cloning failed"),
            self.0,
        )
    }
}

impl RecvFrame for std::net::TcpStream {
    fn recv_frame(&mut self) -> Result<Vec<u8>, Error> {
        let len16 = self.read_u16().map_err(|_| Error::SocketError)?;
        let len = len16 as usize;
        let mut buf: Vec<u8> = vec![
            0u8;
            len + super::FRAME_PREFIX_SIZE
                + super::GRAME_SUFFIX_SIZE
        ];
        buf[0..2].copy_from_slice(&len16.to_be_bytes());
        self.read_exact(&mut buf[2..])?;
        Ok(buf)
    }

    fn recv_raw(&mut self, len: usize) -> Result<Vec<u8>, Error> {
        let mut buf: Vec<u8> = vec![0u8; len];
        self.read_exact(&mut buf)?;
        Ok(buf)
    }
}

impl SendFrame for std::net::TcpStream {
    fn send_frame(&mut self, data: impl AsRef<[u8]>) -> Result<usize, Error> {
        let data = data.as_ref();
        let len = data.len();
        if len > super::MAX_FRAME_SIZE {
            return Err(Error::OversizedFrame(len));
        }
        self.write_all(data)?;
        Ok(len)
    }

    fn send_raw(&mut self, data: impl AsRef<[u8]>) -> Result<usize, Error> {
        let data = data.as_ref();
        self.write_all(data)?;
        Ok(data.len())
    }
}

// TODO: (v1) Do Async... implementations for FTCP based on
//       tokio::net::TcpStream

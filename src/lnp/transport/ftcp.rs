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

use amplify::internet::InetSocketAddr;
use amplify::Bipolar;
use core::convert::TryFrom;
use core::time::Duration;
use std::io::{Read, Write};
use std::net::SocketAddr;

use super::{Duplex, Error, RecvFrame, SendFrame};

/// Wraps TcpStream
///
/// We need this wrapper structure since we can't implement foreign traits, such
/// as Bipolar, for a foreign type.
#[derive(Debug)]
pub struct Connection {
    pub(self) stream: std::net::TcpStream,
    pub(self) remote_addr: InetSocketAddr,
}

impl Connection {
    pub fn with(
        stream: std::net::TcpStream,
        remote_addr: InetSocketAddr,
    ) -> Self {
        Self {
            stream,
            remote_addr,
        }
    }

    pub fn connect(inet_addr: InetSocketAddr) -> Result<Self, Error> {
        if let Ok(socket_addr) = SocketAddr::try_from(inet_addr) {
            let stream = std::net::TcpStream::connect(socket_addr)?;
            // NB: This is how we handle ping-pong cycles
            stream.set_read_timeout(Some(Duration::from_secs(30)))?;
            Ok(Self::with(stream, inet_addr))
        } else {
            Err(Error::TorNotSupportedYet)
        }
    }

    // TODO: (v0.2) Transform into bind method + special Listener object wuth
    //       accept method
    pub fn accept(inet_addr: InetSocketAddr) -> Result<Self, Error> {
        if let Ok(socket_addr) = SocketAddr::try_from(inet_addr) {
            let listener = std::net::TcpListener::bind(socket_addr)?;
            let (stream, remote_addr) = listener.accept()?;
            // NB: This is how we handle ping-pong cycles
            stream.set_read_timeout(Some(Duration::from_secs(30)))?;
            Ok(Self::with(stream, remote_addr.into()))
        } else {
            Err(Error::TorNotSupportedYet)
        }
    }
}

impl Duplex for Connection {
    #[inline]
    fn as_receiver(&mut self) -> &mut dyn RecvFrame {
        &mut self.stream
    }

    #[inline]
    fn as_sender(&mut self) -> &mut dyn SendFrame {
        &mut self.stream
    }

    #[inline]
    fn split(self) -> (Box<dyn RecvFrame + Send>, Box<dyn SendFrame + Send>) {
        (
            Box::new(
                self.stream.try_clone().expect("Error cloning TCP socket"),
            ),
            Box::new(self.stream),
        )
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
        Self {
            stream: left,
            // TODO: (v1) Replace with remote address, wbich will require
            //       creation of TcpSocket wrapper type
            remote_addr: Default::default(),
        }
    }

    fn split(self) -> (Self::Left, Self::Right) {
        (
            self.stream.try_clone().expect("TcpStream cloning failed"),
            self.stream,
        )
    }
}

impl RecvFrame for std::net::TcpStream {
    fn recv_frame(&mut self) -> Result<Vec<u8>, Error> {
        let mut len_buf = [0u8; 2];
        self.read_exact(&mut len_buf)?;
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut buf: Vec<u8> = vec![
            0u8;
            len + super::FRAME_PREFIX_SIZE
                + super::FRAME_SUFFIX_SIZE
        ];
        buf[0..2].copy_from_slice(&len_buf);
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
    fn send_frame(&mut self, data: &[u8]) -> Result<usize, Error> {
        let len = data.len();
        if len > super::MAX_FRAME_SIZE {
            return Err(Error::OversizedFrame(len));
        }
        self.write_all(data)?;
        Ok(len)
    }

    fn send_raw(&mut self, data: &[u8]) -> Result<usize, Error> {
        self.write_all(data)?;
        Ok(data.len())
    }
}

// TODO: (v1) Do Async... implementations for FTCP based on
//       tokio::net::TcpStream

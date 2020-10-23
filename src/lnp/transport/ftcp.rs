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

use bitcoin::consensus::encode::ReadExt;
use std::io::{Read, Write};

use super::{Error, RecvFrame, SendFrame};

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

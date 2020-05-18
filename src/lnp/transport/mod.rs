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

mod error;
pub mod tcp;
pub mod websocket;
pub mod zmq;

//pub(self) use super::Message;
pub use error::Error;

use core::borrow::Borrow;

pub trait Input {
    type Reader: Read;
    fn reader(&self) -> &Self::Reader;
}

pub trait Output {
    type Writer: Write;
    fn writer(&self) -> &Self::Writer;
}

pub trait Bidirect: Input + Output {
    type Input: Input;
    type Output: Output;
    fn split(self) -> (Self::Input, Self::Output);
    fn join(input: Self::Input, output: Self::Output) -> Self;
}

pub trait Read {
    fn read(&mut self) -> Result<Vec<u8>, Error>;
}

pub trait Write {
    fn write(&mut self, data: impl Borrow<[u8]>) -> Result<usize, Error>;
}

#[cfg(feature = "tokio")]
#[async_trait]
pub trait AsyncRead {
    async fn read(&mut self) -> Result<Vec<u8>, Error>;
}

#[cfg(feature = "tokio")]
#[async_trait]
pub trait AsyncWrite {
    async fn write(&mut self, data: impl Borrow<[u8]>) -> Result<usize, Error>;
}

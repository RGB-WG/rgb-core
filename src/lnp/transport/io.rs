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

use core::borrow::Borrow;

use super::Error;
use crate::Bipolar;

pub trait Input {
    type Reader: Read;
    fn reader(&mut self) -> &mut Self::Reader;
}

pub trait Output {
    type Writer: Write;
    fn writer(&mut self) -> &mut Self::Writer;
}

pub trait Bidirect: Input + Output + Bipolar {
    type Input: Input;
    type Output: Output;
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

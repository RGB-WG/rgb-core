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

/*
#[cfg(feature = "tokio")]
use tokio::io::AsyncReadExt;
#[cfg(feature = "tokio")]
use tokio::io::AsyncWriteExt;
#[cfg(feature = "tokio")]
use tokio::net::TcpStream;
 */

use std::io::{Read as IoRead, Write as IoWrite};

use super::{Error, Read, Write};

impl Read for dyn AsRef<::std::net::TcpStream> {
    fn read(&mut self) -> Result<Vec<u8>, Error> {
        let mut buf: Vec<u8> = vec![];
        self.as_ref().read_to_end(&mut buf)?;
        Ok(buf)
    }
}

impl Write for dyn AsRef<::std::net::TcpStream> {
    fn write(&mut self, data: impl Borrow<[u8]>) -> Result<usize, Error> {
        self.as_ref().write_all(data.borrow())?;
        Ok(data.borrow().len())
    }
}

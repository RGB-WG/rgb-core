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

use amplify::IoError;
use core::any::Any;
use core::borrow::Borrow;
use std::io;
use std::sync::Arc;

use super::payload;

#[derive(Clone, PartialEq, Eq, Hash, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum Error {
    /// I/O error
    #[from(io::Error)]
    #[from(io::ErrorKind)]
    #[display(inner)]
    Io(IoError),

    /// decoded BigSize is not canonical
    BigSizeNotCanonical,

    /// unexpected EOF while decoding BigSize value
    BigSizeEof,
}

pub trait Encode {
    fn encode(&self) -> Result<Vec<u8>, Error>;
}

pub trait Decode {
    fn decode(data: &dyn Borrow<[u8]>) -> Result<Self, Error>
    where
        Self: Sized;
}

pub trait Unmarshall {
    type Data;
    type Error: std::error::Error;
    fn unmarshall(
        &self,
        data: &dyn Borrow<[u8]>,
    ) -> Result<Self::Data, Self::Error>;
}

pub type UnmarshallFn<E> =
    fn(reader: &mut dyn io::Read) -> Result<Arc<dyn Any>, E>;

pub trait CreateUnmarshaller: Sized + payload::TypedEnum {
    fn create_unmarshaller() -> payload::Unmarshaller<Self>;
}

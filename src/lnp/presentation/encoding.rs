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

    /// Returned by the convenience method [`Decode::deserialize()`] if not all
    /// provided data were consumed during decoding process
    DataNotEntirelyConsumed,
}

/// Lightning-network specific encoding as defined in BOLT-1, 2, 3...
pub trait Encode {
    fn encode<E: io::Write>(&self, e: E) -> Result<usize, Error>;
    fn serialize(&self) -> Result<Vec<u8>, Error> {
        let mut encoder = io::Cursor::new(vec![]);
        self.encode(&mut encoder)?;
        Ok(encoder.into_inner())
    }
}

/// Lightning-network specific encoding as defined in BOLT-1, 2, 3...
pub trait Decode
where
    Self: Sized,
{
    fn decode<D: io::Read>(d: D) -> Result<Self, Error>;
    fn deserialize(data: &dyn AsRef<[u8]>) -> Result<Self, Error> {
        let mut decoder = io::Cursor::new(data);
        let rv = Self::decode(&mut decoder)?;
        let consumed = decoder.position() as usize;

        // Fail if data are not consumed entirely.
        if consumed == data.as_ref().len() {
            Ok(rv)
        } else {
            Err(Error::DataNotEntirelyConsumed)?
        }
    }
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

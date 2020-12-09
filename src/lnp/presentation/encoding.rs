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
use crate::strict_encoding;

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

    /// Errors from underlying strict encoding
    #[display(inner)]
    StrictEncoding(strict_encoding::Error),
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

/// Implemented after concept by Martin Habovštiak <martin.habovstiak@gmail.com>
pub mod strategies {
    use std::io;

    use super::{Decode, Encode, Error};
    use crate::lnp::presentation::BigSize;
    use crate::strict_encoding::{self, StrictDecode, StrictEncode};

    // Defining strategies:
    pub struct StrictEncoding;
    pub struct AsBigSize;

    pub trait Strategy {
        type Strategy;
    }

    impl<T> Encode for T
    where
        T: Strategy + Clone,
        amplify::Holder<T, <T as Strategy>::Strategy>: Encode,
    {
        #[inline]
        fn encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
            amplify::Holder::new(self.clone()).encode(e)
        }
    }

    impl<T> Decode for T
    where
        T: Strategy,
        amplify::Holder<T, <T as Strategy>::Strategy>: Decode,
    {
        #[inline]
        fn decode<D: io::Read>(d: D) -> Result<Self, Error> {
            Ok(amplify::Holder::decode(d)?.into_inner())
        }
    }

    impl<T> Encode for amplify::Holder<T, StrictEncoding>
    where
        T: StrictEncode<Error = strict_encoding::Error>,
    {
        #[inline]
        fn encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
            self.as_inner().strict_encode(e).map_err(Error::from)
        }
    }

    impl<T> Decode for amplify::Holder<T, AsBigSize>
    where
        T: From<BigSize>,
    {
        #[inline]
        fn decode<D: io::Read>(d: D) -> Result<Self, Error> {
            Ok(Self::new(T::from(BigSize::decode(d)?)))
        }
    }

    impl<T> Encode for amplify::Holder<T, AsBigSize>
    where
        T: Into<BigSize>,
        T: Copy,
    {
        #[inline]
        fn encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
            (*self.as_inner()).into().encode(e)
        }
    }

    impl<T> Decode for amplify::Holder<T, StrictEncoding>
    where
        T: StrictDecode<Error = strict_encoding::Error>,
    {
        #[inline]
        fn decode<D: io::Read>(d: D) -> Result<Self, Error> {
            Ok(Self::new(T::strict_decode(d)?))
        }
    }

    impl From<strict_encoding::Error> for Error {
        #[inline]
        fn from(e: strict_encoding::Error) -> Self {
            if let strict_encoding::Error::Io(err) = e {
                Error::Io(err)
            } else {
                Error::StrictEncoding(e)
            }
        }
    }

    impl Strategy for u8 {
        type Strategy = AsBigSize;
    }

    impl Strategy for u16 {
        type Strategy = AsBigSize;
    }

    impl Strategy for u32 {
        type Strategy = AsBigSize;
    }

    impl Strategy for u64 {
        type Strategy = AsBigSize;
    }
}
pub use strategies::Strategy;

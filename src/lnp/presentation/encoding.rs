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

use amplify::{IoError, Wrapper};
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

    /// Convenience type never for data structures using StrictDecode
    #[display(inner)]
    DataIntegrityError(String),
}

/// Lightning-network specific encoding as defined in BOLT-1, 2, 3...
pub trait LightningEncode {
    fn lightning_encode<E: io::Write>(&self, e: E) -> Result<usize, io::Error>;
    fn lightning_serialize(&self) -> Vec<u8> {
        let mut encoder = vec![];
        self.lightning_encode(&mut encoder)
            .expect("Memory encoders can't fail");
        encoder
    }
}

/// Lightning-network specific encoding as defined in BOLT-1, 2, 3...
pub trait LightningDecode
where
    Self: Sized,
{
    fn lightning_decode<D: io::Read>(d: D) -> Result<Self, Error>;
    fn lightning_deserialize(data: &impl AsRef<[u8]>) -> Result<Self, Error> {
        let mut decoder = io::Cursor::new(data);
        let rv = Self::lightning_decode(&mut decoder)?;
        let consumed = decoder.position() as usize;

        // Fail if data are not consumed entirely.
        if consumed == data.as_ref().len() {
            Ok(rv)
        } else {
            Err(Error::DataNotEntirelyConsumed)?
        }
    }
}

pub fn lightning_serialize<T>(data: &T) -> Vec<u8>
where
    T: LightningEncode,
{
    data.lightning_serialize()
}

pub fn lightning_deserialize<T>(data: &impl AsRef<[u8]>) -> Result<T, Error>
where
    T: LightningDecode,
{
    T::lightning_deserialize(data)
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

    use super::{Error, LightningDecode, LightningEncode};
    use crate::lnp::presentation::BigSize;
    use crate::strict_encoding::{self, StrictDecode, StrictEncode};

    // Defining strategies:
    pub struct AsStrict;
    pub struct AsBigSize;
    pub struct AsBitcoinHash;
    pub struct AsWrapped;

    pub trait Strategy {
        type Strategy;
    }

    impl<T> LightningEncode for T
    where
        T: Strategy + Clone,
        amplify::Holder<T, <T as Strategy>::Strategy>: LightningEncode,
    {
        #[inline]
        fn lightning_encode<E: io::Write>(
            &self,
            e: E,
        ) -> Result<usize, io::Error> {
            amplify::Holder::new(self.clone()).lightning_encode(e)
        }
    }

    impl<T> LightningDecode for T
    where
        T: Strategy,
        amplify::Holder<T, <T as Strategy>::Strategy>: LightningDecode,
    {
        #[inline]
        fn lightning_decode<D: io::Read>(d: D) -> Result<Self, Error> {
            Ok(amplify::Holder::lightning_decode(d)?.into_inner())
        }
    }

    impl<T> LightningEncode for amplify::Holder<T, AsStrict>
    where
        T: StrictEncode,
    {
        #[inline]
        fn lightning_encode<E: io::Write>(
            &self,
            e: E,
        ) -> Result<usize, io::Error> {
            self.as_inner().strict_encode(e).map_err(|err| match err {
                strict_encoding::Error::Io(io_err) => io_err.into(),
                _ => io::Error::from(io::ErrorKind::InvalidData),
            })
        }
    }

    impl<T> LightningDecode for amplify::Holder<T, AsStrict>
    where
        T: StrictDecode,
    {
        #[inline]
        fn lightning_decode<D: io::Read>(d: D) -> Result<Self, Error> {
            Ok(Self::new(T::strict_decode(d)?))
        }
    }

    impl<T> LightningEncode for amplify::Holder<T, AsBitcoinHash>
    where
        T: bitcoin::hashes::Hash + strict_encoding::StrictEncode,
    {
        #[inline]
        fn lightning_encode<E: io::Write>(
            &self,
            e: E,
        ) -> Result<usize, io::Error> {
            self.as_inner().strict_encode(e).map_err(|err| match err {
                strict_encoding::Error::Io(io_err) => io_err.into(),
                _ => io::Error::from(io::ErrorKind::InvalidData),
            })
        }
    }

    impl<T> LightningDecode for amplify::Holder<T, AsBitcoinHash>
    where
        T: bitcoin::hashes::Hash + strict_encoding::StrictDecode,
    {
        #[inline]
        fn lightning_decode<D: io::Read>(d: D) -> Result<Self, Error> {
            Ok(Self::new(T::strict_decode(d).map_err(|err| {
                Error::DataIntegrityError(err.to_string())
            })?))
        }
    }

    impl<T> LightningEncode for amplify::Holder<T, AsWrapped>
    where
        T: amplify::Wrapper,
        T::Inner: LightningEncode,
    {
        #[inline]
        fn lightning_encode<E: io::Write>(
            &self,
            e: E,
        ) -> Result<usize, io::Error> {
            self.as_inner().as_inner().lightning_encode(e)
        }
    }

    impl<T> LightningDecode for amplify::Holder<T, AsWrapped>
    where
        T: amplify::Wrapper,
        T::Inner: LightningDecode,
    {
        #[inline]
        fn lightning_decode<D: io::Read>(d: D) -> Result<Self, Error> {
            Ok(Self::new(T::from_inner(T::Inner::lightning_decode(d)?)))
        }
    }

    impl<T> LightningDecode for amplify::Holder<T, AsBigSize>
    where
        T: From<BigSize>,
    {
        #[inline]
        fn lightning_decode<D: io::Read>(d: D) -> Result<Self, Error> {
            Ok(Self::new(T::from(BigSize::lightning_decode(d)?)))
        }
    }

    impl<T> LightningEncode for amplify::Holder<T, AsBigSize>
    where
        T: Into<BigSize>,
        T: Copy,
    {
        #[inline]
        fn lightning_encode<E: io::Write>(
            &self,
            e: E,
        ) -> Result<usize, io::Error> {
            (*self.as_inner()).into().lightning_encode(e)
        }
    }

    impl From<strict_encoding::Error> for Error {
        #[inline]
        fn from(err: strict_encoding::Error) -> Self {
            match err {
                strict_encoding::Error::Io(io_err) => Error::Io(io_err),
                strict_encoding::Error::DataNotEntirelyConsumed => {
                    Error::DataNotEntirelyConsumed
                }
                strict_encoding::Error::DataIntegrityError(msg) => {
                    Error::DataIntegrityError(msg)
                }
                other => Error::DataIntegrityError(other.to_string()),
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

    impl Strategy for usize {
        type Strategy = AsBigSize;
    }

    impl Strategy for bitcoin::hashes::ripemd160::Hash {
        type Strategy = AsBitcoinHash;
    }

    impl Strategy for bitcoin::hashes::hash160::Hash {
        type Strategy = AsBitcoinHash;
    }

    impl Strategy for bitcoin::hashes::sha256::Hash {
        type Strategy = AsBitcoinHash;
    }

    impl Strategy for bitcoin::hashes::sha256d::Hash {
        type Strategy = AsBitcoinHash;
    }

    impl<T> Strategy for bitcoin::hashes::sha256t::Hash<T>
    where
        T: bitcoin::hashes::sha256t::Tag,
    {
        type Strategy = AsBitcoinHash;
    }

    impl<T> Strategy for bitcoin::hashes::hmac::Hmac<T>
    where
        T: bitcoin::hashes::Hash,
    {
        type Strategy = AsBitcoinHash;
    }

    impl Strategy for bitcoin::Txid {
        type Strategy = AsBitcoinHash;
    }

    impl Strategy for crate::bp::HashLock {
        type Strategy = AsWrapped;
    }

    impl Strategy for crate::bp::HashPreimage {
        type Strategy = AsWrapped;
    }

    impl Strategy for bitcoin::OutPoint {
        type Strategy = AsStrict;
    }

    impl Strategy for bitcoin::Script {
        // NB: Existing BOLTs define script length as u16, not BigSize, so we
        // can use this trick for now
        type Strategy = AsStrict;
    }

    impl Strategy for bitcoin::PublicKey {
        type Strategy = AsStrict;
    }

    use bitcoin::secp256k1;
    impl Strategy for secp256k1::PublicKey {
        type Strategy = AsStrict;
    }

    impl Strategy for secp256k1::Signature {
        type Strategy = AsStrict;
    }

    #[cfg(feature = "rgb")]
    impl Strategy for crate::rgb::Consignment {
        type Strategy = AsStrict;
    }
}
pub use strategies::Strategy;

mod byte_strings {
    use super::{Error, LightningDecode, LightningEncode};
    use std::io;
    use std::ops::Deref;

    impl LightningEncode for &[u8] {
        fn lightning_encode<E: io::Write>(
            &self,
            mut e: E,
        ) -> Result<usize, io::Error> {
            let mut len = self.len();
            // We handle oversize problems at the level of `usize` value
            // serializaton
            len += len.lightning_encode(&mut e)?;
            e.write_all(self)?;
            Ok(len)
        }
    }

    impl LightningEncode for [u8; 32] {
        fn lightning_encode<E: io::Write>(
            &self,
            mut e: E,
        ) -> Result<usize, io::Error> {
            e.write_all(self)?;
            Ok(self.len())
        }
    }

    impl LightningDecode for [u8; 32] {
        fn lightning_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
            let mut ret = [0u8; 32];
            d.read_exact(&mut ret)?;
            Ok(ret)
        }
    }

    impl LightningEncode for Box<[u8]> {
        fn lightning_encode<E: io::Write>(
            &self,
            e: E,
        ) -> Result<usize, io::Error> {
            self.deref().lightning_encode(e)
        }
    }

    impl LightningDecode for Box<[u8]> {
        fn lightning_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
            let len = usize::lightning_decode(&mut d)?;
            let mut ret = vec![0u8; len];
            d.read_exact(&mut ret)?;
            Ok(ret.into_boxed_slice())
        }
    }

    impl LightningEncode for &str {
        fn lightning_encode<E: io::Write>(
            &self,
            e: E,
        ) -> Result<usize, io::Error> {
            self.as_bytes().lightning_encode(e)
        }
    }

    impl LightningEncode for String {
        fn lightning_encode<E: io::Write>(
            &self,
            e: E,
        ) -> Result<usize, io::Error> {
            self.as_bytes().lightning_encode(e)
        }
    }

    impl LightningDecode for String {
        fn lightning_decode<D: io::Read>(d: D) -> Result<Self, Error> {
            Ok(String::from_utf8_lossy(&Vec::<u8>::lightning_decode(d)?)
                .to_string())
        }
    }
}

mod collections {
    use super::{Error, LightningDecode, LightningEncode};

    use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
    use std::io;

    impl<T> LightningEncode for Vec<T>
    where
        T: LightningEncode,
    {
        fn lightning_encode<E: io::Write>(
            &self,
            mut e: E,
        ) -> Result<usize, io::Error> {
            let len = self.len().lightning_encode(&mut e)?;
            self.iter().try_fold(len, |len, item| {
                Ok(len + item.lightning_encode(&mut e)?)
            })
        }
    }

    impl<T> LightningDecode for Vec<T>
    where
        T: LightningDecode,
    {
        fn lightning_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
            let count = usize::lightning_decode(&mut d)?;
            let mut vec = Vec::with_capacity(count);
            for _ in 0..count {
                vec.push(T::lightning_decode(&mut d)?)
            }
            Ok(vec)
        }
    }

    impl<T> LightningEncode for HashSet<T>
    where
        T: LightningEncode,
    {
        fn lightning_encode<E: io::Write>(
            &self,
            mut e: E,
        ) -> Result<usize, io::Error> {
            let len = self.len().lightning_encode(&mut e)?;
            self.iter().try_fold(len, |len, item| {
                Ok(len + item.lightning_encode(&mut e)?)
            })
        }
    }

    impl<T> LightningDecode for HashSet<T>
    where
        T: LightningDecode + Eq + std::hash::Hash,
    {
        fn lightning_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
            let count = usize::lightning_decode(&mut d)?;
            let mut set = HashSet::with_capacity(count);
            for _ in 0..count {
                set.insert(T::lightning_decode(&mut d)?);
            }
            Ok(set)
        }
    }

    impl<K, V> LightningEncode for HashMap<K, V>
    where
        K: LightningEncode,
        V: LightningEncode,
    {
        fn lightning_encode<E: io::Write>(
            &self,
            mut e: E,
        ) -> Result<usize, io::Error> {
            let len = self.len().lightning_encode(&mut e)?;
            self.iter().try_fold(len, |len, (k, v)| {
                Ok(len
                    + k.lightning_encode(&mut e)?
                    + v.lightning_encode(&mut e)?)
            })
        }
    }

    impl<K, V> LightningDecode for HashMap<K, V>
    where
        K: LightningDecode + Eq + std::hash::Hash,
        V: LightningDecode,
    {
        fn lightning_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
            let count = usize::lightning_decode(&mut d)?;
            let mut set = HashMap::with_capacity(count);
            for _ in 0..count {
                set.insert(
                    K::lightning_decode(&mut d)?,
                    V::lightning_decode(&mut d)?,
                );
            }
            Ok(set)
        }
    }

    impl<T> LightningEncode for BTreeSet<T>
    where
        T: LightningEncode,
    {
        fn lightning_encode<E: io::Write>(
            &self,
            mut e: E,
        ) -> Result<usize, io::Error> {
            let len = self.len().lightning_encode(&mut e)?;
            self.iter().try_fold(len, |len, item| {
                Ok(len + item.lightning_encode(&mut e)?)
            })
        }
    }

    impl<T> LightningDecode for BTreeSet<T>
    where
        T: LightningDecode + Ord,
    {
        fn lightning_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
            let count = usize::lightning_decode(&mut d)?;
            let mut set = BTreeSet::new();
            for _ in 0..count {
                set.insert(T::lightning_decode(&mut d)?);
            }
            Ok(set)
        }
    }

    impl<K, V> LightningEncode for BTreeMap<K, V>
    where
        K: LightningEncode,
        V: LightningEncode,
    {
        fn lightning_encode<E: io::Write>(
            &self,
            mut e: E,
        ) -> Result<usize, io::Error> {
            let len = self.len().lightning_encode(&mut e)?;
            self.iter().try_fold(len, |len, (k, v)| {
                Ok(len
                    + k.lightning_encode(&mut e)?
                    + v.lightning_encode(&mut e)?)
            })
        }
    }

    impl<K, V> LightningDecode for BTreeMap<K, V>
    where
        K: LightningDecode + Ord,
        V: LightningDecode,
    {
        fn lightning_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
            let count = usize::lightning_decode(&mut d)?;
            let mut set = BTreeMap::new();
            for _ in 0..count {
                set.insert(
                    K::lightning_decode(&mut d)?,
                    V::lightning_decode(&mut d)?,
                );
            }
            Ok(set)
        }
    }
}

use crate::lnp::ChannelId;
// With ChannelId we have a special situation when zero-based channel id
// represents "all channels" and is encoded in LNP as an Option::None
impl LightningEncode for Option<ChannelId> {
    fn lightning_encode<E: io::Write>(
        &self,
        mut e: E,
    ) -> Result<usize, io::Error> {
        match self {
            Some(id) => id.lightning_encode(e),
            None => {
                e.write_all(&[0u8; 32])?;
                Ok(32)
            }
        }
    }
}

impl LightningDecode for Option<ChannelId> {
    fn lightning_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        let channel_id = ChannelId::lightning_decode(d)?;
        if channel_id.into_inner() == [0u8; 32].into() {
            Ok(None)
        } else {
            Ok(Some(channel_id))
        }
    }
}

// TODO: Replace this temporary solution with proper TLV processing
mod temp_before_tlv {
    use super::*;
    use crate::bp::chain::AssetId;

    impl LightningEncode for Option<AssetId> {
        fn lightning_encode<E: io::Write>(
            &self,
            e: E,
        ) -> Result<usize, io::Error> {
            match self {
                Some(id) => id.lightning_encode(e),
                None => Ok(0),
            }
        }
    }

    impl LightningDecode for Option<AssetId> {
        fn lightning_decode<D: io::Read>(d: D) -> Result<Self, Error> {
            AssetId::lightning_decode(d).map(|id| Some(id)).or(Ok(None))
        }
    }
}

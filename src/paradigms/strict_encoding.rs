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

use core::ops::Range;
use std::fmt::{self, Display, Formatter};
use std::io;

/// Re-exporting extended read and write functions from bitcoin consensus module
/// so others may use semantic convenience `lnpbp::strict_encode::ReadExt`
pub use bitcoin::consensus::encode::{ReadExt, WriteExt};

/// Binary encoding according to the strict rules that usually apply to
/// consensus-critical data structures. May be used for network communications;
/// in some circumstances may be used for commitment procedures; however it must
/// be kept in mind that sometime commitment may follow "fold" scheme
/// (Merklization or nested commitments) and in such cases this trait can't be
/// applied. It is generally recommended for consensus-related commitments to
/// utilize [CommitVerify], [TryCommitVerify] and [EmbedCommitVerify] traits  
/// from [paradigms::commit_verify] module.
pub trait StrictEncode {
    /// Implementation-dependent error type
    type Error: std::error::Error + From<Error> = Error;

    /// Encode with the given [std::io::Writer] instance; must return result
    /// with either amount of bytes encoded – or implementation-specific
    /// error type.
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Self::Error>;
}

/// Binary decoding according to the strict rules that usually apply to
/// consensus-critical data structures. May be used for network communications.
/// MUST NOT be used for commitment verification: even if the commit procedure
/// uses [StrictEncode], the actual commit verification MUST be done with
/// [CommitVerify], [TryCommitVerify] and [EmbedCommitVerify] traits, which,
/// instead of deserializing (nonce operation for commitments) repeat the
/// commitment procedure for the revealed message and verify it against the
/// provided commitment.
pub trait StrictDecode: Sized {
    /// Implementation-dependent error type
    type Error: std::error::Error + From<Error> = Error;

    /// Decode with the given [std::io::Reader] instance; must either
    /// construct an instance or return implementation-specific error type.
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, Self::Error>;
}

/// Convenience method for strict encoding of data structures implementing
/// [StrictEncode] into a byte vector. To support this method a
/// type must implement `From<strict_encode::Error>` for an error type
/// provided as the associated type [StrictDecode::Error].
pub fn strict_encode<T>(data: &T) -> Result<Vec<u8>, T::Error>
where
    T: StrictEncode,
    T::Error: std::error::Error + From<Error>,
{
    let mut encoder = io::Cursor::new(vec![]);
    data.strict_encode(&mut encoder)?;
    Ok(encoder.into_inner())
}

/// Convenience method for strict decoding of data structures implementing
/// [StrictDecode] from any byt data source. To support this method a
/// type must implement `From<strict_encode::Error>` for an error type
/// provided as the associated type [StrictDecode::Error].
pub fn strict_decode<T>(data: &impl AsRef<[u8]>) -> Result<T, T::Error>
where
    T: StrictDecode,
    T::Error: std::error::Error + From<Error>,
{
    let mut decoder = io::Cursor::new(data);
    let rv = T::strict_decode(&mut decoder)?;
    let consumed = decoder.position() as usize;

    // Fail if data are not consumed entirely.
    if consumed == data.as_ref().len() {
        Ok(rv)
    } else {
        Err(Error::DataNotEntirelyConsumed)?
    }
}

/// Possible errors during strict encoding and decoding process
#[derive(Debug, From, Error)]
pub enum Error {
    /// I/O Error
    #[derive_from]
    Io(io::Error),

    /// UTF8 Conversion Error
    #[derive_from(std::str::Utf8Error, std::string::FromUtf8Error)]
    Utf8Conversion,

    /// A collection (slice, vector or other type) has more items than
    /// 2^16 (i.e. maximum value which may be held by `u16` `size`
    /// representation according to the LNPBP-6 spec)
    ExceedMaxItems(usize),

    /// In terms of strict encoding, we interpret `Option` as a zero-length
    /// `Vec` (for `Optional::None`) or single-item `Vec` (for `Optional::Some`).
    /// For decoding an attempt to read `Option` from a encoded non-0
    /// or non-1 length Vec will result in `Error::WrongOptionalEncoding`.
    WrongOptionalEncoding(u8),

    // TODO: (new) replace all `String` in errors with `&'static str`
    /// Enums are encoded as a `u8`-based values; the provided enum has
    /// underlying primitive type that does not fit into `u8` value
    EnumValueOverflow(String),

    /// An unsupported value for enum encountered during decode operation
    EnumValueNotKnown(String, u8),

    /// The data are correct, however their structure indicate that they were
    /// created with the future software version which has functional absent in
    /// the current implementation
    UnsupportedDataStructure(&'static str),

    /// Found a value during decoding operation that does not fits into
    /// the supported range
    ValueOutOfRange(&'static str, Range<u128>, u128),

    /// A repeated value found during set collection deserialization
    RepeatedValue(String),

    /// Returned by the convenience method [strict_decode] if not all
    /// provided data were consumed during decoding process
    DataNotEntirelyConsumed,

    /// Convenience type never for data structures using StrictDecode
    DataIntegrityError(String),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use Error::*;
        match self {
            Io(e) => write!(f, "I/O error: {}", e),
            Utf8Conversion => write!(f, "String data are not in valid UTF-8 encoding"),
            ExceedMaxItems(size) => write!(
                f,
                "A collection (slice, vector or other type) has {} items, which \
                exceeds maximum allowed value for `u16` type representing \
                collection size according to LNPBP-6 spec)",
                size
            ),
            WrongOptionalEncoding(significator) => write!(
                f,
                "Invalid value {} met as a significator byte, which must be \
                equal to either 0 (no value) or 1",
                significator
            ),
            EnumValueOverflow(enum_name) => write!(
                f,
                "Enums are encoded as a `u8`-based values; the provided enum {} \
                has underlying primitive type that does not fit into `u8` value",
                enum_name
            ),
            EnumValueNotKnown(enum_name, value) => write!(
                f,
                "An unsupported value {} for enum {} encountered during decode \
                operation",
                value, enum_name
            ),
            UnsupportedDataStructure(details) => write!(
                f,
                "The data are correct, however their structure indicate that \
                 they were created with the future software version which has  \
                 functional absent in the current implementation. Here is more \
                 details: {}",
                details
            ),
            ValueOutOfRange(data_type, range, value) => write!(
                f,
                "Decoding resulted in value {} for type {} that exceeds the \
                supported range {:#?}",
                value, data_type, range
            ),
            RepeatedValue(value) => write!(
                f,
                "A repeated value {} found during set collection deserialization",
                value
            ),
            DataNotEntirelyConsumed => write!(
                f,
                "Data were not consumed entirely during strict decoding procedure"
            ),
            DataIntegrityError(str) => write!(f, "Data integrity error: {}", str),
        }
    }
}

#[macro_export]
macro_rules! strict_encode_list {
    ( $encoder:ident; $($item:expr),+ ) => {
        {
            let mut len = 0usize;
            $(
                len += $item.strict_encode(&mut $encoder)?;
            )+
            len
        }
    };

    ( $encoder:ident; $len:ident; $($item:expr),+ ) => {
        {
            $(
                $len += $item.strict_encode(&mut $encoder)?;
            )+
            $len
        }
    }
}

#[macro_export]
macro_rules! strict_decode_self {
    ( $decoder:ident; $($item:ident),+ ) => {
        {
            Self {
            $(
                $item: StrictDecode::strict_decode(&mut $decoder)?,
            )+
            }
        }
    };
}

#[macro_export]
macro_rules! impl_enum_strict_encoding {
    ($type:ty) => {
        impl $crate::strict_encoding::StrictEncode for $type {
            type Error = $crate::strict_encoding::Error;

            #[inline]
            fn strict_encode<E: ::std::io::Write>(&self, e: E) -> Result<usize, Self::Error> {
                use ::num_traits::ToPrimitive;

                match self.to_u8() {
                    Some(result) => result.strict_encode(e),
                    None => Err($crate::strict_encoding::Error::EnumValueOverflow(
                        stringify!($type).to_string(),
                    )),
                }
            }
        }

        impl $crate::strict_encoding::StrictDecode for $type {
            type Error = $crate::strict_encoding::Error;

            #[inline]
            fn strict_decode<D: ::std::io::Read>(d: D) -> Result<Self, Self::Error> {
                use ::num_traits::FromPrimitive;

                let value = u8::strict_decode(d)?;
                match Self::from_u8(value) {
                    Some(result) => Ok(result),
                    None => Err($crate::strict_encoding::Error::EnumValueNotKnown(
                        stringify!($type).to_string(),
                        value,
                    )),
                }
            }
        }
    };
}

/// Implemented after concept by Martin Habovštiak <martin.habovstiak@gmail.com>
pub mod strategies {
    use super::{Error, StrictDecode, StrictEncode};
    use amplify::Wrapper;
    use std::io;

    // Defining strategies:
    pub struct HashFixedBytes;
    pub struct BitcoinConsensus;
    pub struct Wrapped;

    pub trait Strategy {
        type Strategy;
    }

    impl<T> StrictEncode for T
    where
        T: Strategy + Clone,
        amplify::Holder<T, <T as Strategy>::Strategy>: StrictEncode,
    {
        type Error = <amplify::Holder<T, T::Strategy> as StrictEncode>::Error;

        #[inline]
        fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Self::Error> {
            amplify::Holder::new(self.clone()).strict_encode(e)
        }
    }

    impl<T> StrictDecode for T
    where
        T: Strategy,
        amplify::Holder<T, <T as Strategy>::Strategy>: StrictDecode,
    {
        type Error = <amplify::Holder<T, T::Strategy> as StrictDecode>::Error;

        #[inline]
        fn strict_decode<D: io::Read>(d: D) -> Result<Self, Self::Error> {
            Ok(amplify::Holder::strict_decode(d)?.into_inner())
        }
    }

    impl<T> StrictEncode for amplify::Holder<T, Wrapped>
    where
        T: Wrapper,
        T::Inner: StrictEncode,
    {
        type Error = <T::Inner as StrictEncode>::Error;

        #[inline]
        fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Self::Error> {
            Ok(self.as_inner().to_inner().strict_encode(e)?)
        }
    }

    impl<T> StrictDecode for amplify::Holder<T, Wrapped>
    where
        T: Wrapper,
        T::Inner: StrictDecode,
    {
        type Error = <T::Inner as StrictDecode>::Error;

        #[inline]
        fn strict_decode<D: io::Read>(d: D) -> Result<Self, Self::Error> {
            Ok(Self::new(T::from_inner(T::Inner::strict_decode(d)?)))
        }
    }

    impl<T> StrictEncode for amplify::Holder<T, HashFixedBytes>
    where
        T: bitcoin::hashes::Hash,
    {
        type Error = Error;

        #[inline]
        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
            e.write_all(&self.as_inner()[..])?;
            Ok(T::LEN)
        }
    }

    impl<T> StrictDecode for amplify::Holder<T, HashFixedBytes>
    where
        T: bitcoin::hashes::Hash,
    {
        type Error = Error;

        #[inline]
        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
            let mut buf = vec![0u8; T::LEN];
            d.read_exact(&mut buf)?;
            Ok(Self::new(T::from_slice(&buf)?))
        }
    }

    impl<T> StrictEncode for amplify::Holder<T, BitcoinConsensus>
    where
        T: bitcoin::consensus::Encodable,
    {
        type Error = Error;

        #[inline]
        fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Self::Error> {
            self.as_inner().consensus_encode(e).map_err(Error::from)
        }
    }

    impl<T> StrictDecode for amplify::Holder<T, BitcoinConsensus>
    where
        T: bitcoin::consensus::Decodable,
    {
        type Error = Error;

        #[inline]
        fn strict_decode<D: io::Read>(d: D) -> Result<Self, Self::Error> {
            Ok(Self::new(T::consensus_decode(d).map_err(Error::from)?))
        }
    }

    impl From<bitcoin::hashes::Error> for Error {
        #[inline]
        fn from(_: bitcoin::hashes::Error) -> Self {
            Error::DataIntegrityError("Incorrect hash length".to_string())
        }
    }

    impl From<bitcoin::consensus::encode::Error> for Error {
        #[inline]
        fn from(e: bitcoin::consensus::encode::Error) -> Self {
            Error::Io(if let bitcoin::consensus::encode::Error::Io(io_err) = e {
                io_err
            } else {
                io::Error::new(io::ErrorKind::Other, "")
            })
        }
    }
}
pub use strategies::Strategy;

/// Taking implementation of little-endian integer encoding
mod number_little_endian {
    use super::{strategies, Error, Strategy, StrictDecode, StrictEncode};
    use bitcoin::util::uint::{Uint128, Uint256};
    use std::io;

    impl Strategy for u8 {
        type Strategy = strategies::BitcoinConsensus;
    }
    impl Strategy for u16 {
        type Strategy = strategies::BitcoinConsensus;
    }
    impl Strategy for u32 {
        type Strategy = strategies::BitcoinConsensus;
    }
    impl Strategy for u64 {
        type Strategy = strategies::BitcoinConsensus;
    }
    impl Strategy for Uint128 {
        type Strategy = strategies::BitcoinConsensus;
    }
    impl Strategy for Uint256 {
        type Strategy = strategies::BitcoinConsensus;
    }
    impl Strategy for i8 {
        type Strategy = strategies::BitcoinConsensus;
    }
    impl Strategy for i16 {
        type Strategy = strategies::BitcoinConsensus;
    }
    impl Strategy for i32 {
        type Strategy = strategies::BitcoinConsensus;
    }
    impl Strategy for i64 {
        type Strategy = strategies::BitcoinConsensus;
    }

    impl StrictEncode for bool {
        type Error = Error;
        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
            (*self as u8).strict_encode(&mut e)
        }
    }

    impl StrictDecode for bool {
        type Error = Error;
        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
            match u8::strict_decode(&mut d)? {
                0 => Ok(false),
                1 => Ok(true),
                v => Err(Error::ValueOutOfRange("boolean", 0..1, v as u128)),
            }
        }
    }

    impl StrictEncode for usize {
        type Error = Error;
        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
            if *self > std::u16::MAX as usize {
                Err(Error::ExceedMaxItems(*self))?;
            }
            let size = *self as u16;
            size.strict_encode(&mut e)
        }
    }

    impl StrictDecode for usize {
        type Error = Error;
        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
            u16::strict_decode(&mut d).map(|val| val as usize)
        }
    }

    impl StrictEncode for f32 {
        type Error = Error;
        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
            e.write_all(&self.to_le_bytes())?;
            Ok(4)
        }
    }

    impl StrictDecode for f32 {
        type Error = Error;
        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
            let mut buf: [u8; 4] = [0; 4];
            d.read_exact(&mut buf)?;
            Ok(Self::from_le_bytes(buf))
        }
    }

    impl StrictEncode for f64 {
        type Error = Error;
        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
            e.write_all(&self.to_le_bytes())?;
            Ok(8)
        }
    }

    impl StrictDecode for f64 {
        type Error = Error;
        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
            let mut buf: [u8; 8] = [0; 8];
            d.read_exact(&mut buf)?;
            Ok(Self::from_le_bytes(buf))
        }
    }
}

mod byte_strings {
    use super::{Error, StrictDecode, StrictEncode};
    use std::io;
    use std::ops::Deref;

    impl StrictEncode for &[u8] {
        type Error = Error;
        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
            let mut len = self.len();
            // We handle oversize problems at the level of `usize` value serializaton
            len += len.strict_encode(&mut e)?;
            e.write_all(self)?;
            Ok(len)
        }
    }

    impl StrictEncode for Box<[u8]> {
        type Error = Error;
        fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
            self.deref().strict_encode(e)
        }
    }

    impl StrictDecode for Box<[u8]> {
        type Error = Error;
        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
            let len = usize::strict_decode(&mut d)?;
            let mut ret = vec![0u8; len];
            d.read_exact(&mut ret)?;
            Ok(ret.into_boxed_slice())
        }
    }

    impl StrictEncode for &str {
        type Error = Error;
        fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
            self.as_bytes().strict_encode(e)
        }
    }

    impl StrictEncode for String {
        type Error = Error;
        fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
            self.as_bytes().strict_encode(e)
        }
    }

    impl StrictDecode for String {
        type Error = Error;
        fn strict_decode<D: io::Read>(d: D) -> Result<Self, Error> {
            String::from_utf8(Vec::<u8>::strict_decode(d)?).map_err(Error::from)
        }
    }
}

mod compositional_types {
    use super::{Error, StrictDecode, StrictEncode};
    use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
    use std::fmt::Debug;
    use std::hash::Hash;
    use std::io;

    /// In terms of strict encoding, `Option` (optional values) are  
    /// represented by a *significator byte*, which MUST be either `0` (for no
    /// value present) or `1`, followed by the value strict encoding.
    impl<T> StrictEncode for Option<T>
    where
        T: StrictEncode,
        T::Error: From<Error>,
    {
        type Error = T::Error;
        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
            Ok(match self {
                None => strict_encode_list!(e; 0u8),
                Some(val) => strict_encode_list!(e; 1u8, val),
            })
        }
    }

    /// In terms of strict encoding, `Option` (optional values) are  
    /// represented by a *significator byte*, which MUST be either `0` (for no
    /// value present) or `1`, followed by the value strict encoding.
    /// For decoding an attempt to read `Option` from a encoded non-0
    /// or non-1 length Vec will result in `Error::WrongOptionalEncoding`.
    impl<T> StrictDecode for Option<T>
    where
        T: StrictDecode,
        T::Error: From<Error>,
    {
        type Error = T::Error;
        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
            let len = u8::strict_decode(&mut d)?;
            match len {
                0 => Ok(None),
                1 => Ok(Some(T::strict_decode(&mut d)?)),
                invalid => Err(Error::WrongOptionalEncoding(invalid))?,
            }
        }
    }

    /// In terms of strict encoding, `Vec` is stored in form of
    /// usize-encoded length (see `StrictEncode` implementation for `usize`
    /// type for encoding platform-independent constant-length
    /// encoding rules) followed by a consequently-encoded vec items,
    /// according to their type.
    impl<T> StrictEncode for Vec<T>
    where
        T: StrictEncode,
        T::Error: From<Error>,
    {
        type Error = T::Error;
        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
            let len = self.len() as usize;
            let mut encoded = len.strict_encode(&mut e)?;
            for item in self {
                encoded += item.strict_encode(&mut e)?;
            }
            Ok(encoded)
        }
    }

    /// In terms of strict encoding, `Vec` is stored in form of
    /// usize-encoded length (see `StrictEncode` implementation for `usize`
    /// type for encoding platform-independent constant-length
    /// encoding rules) followed by a consequently-encoded vec items,
    /// according to their type.
    ///
    /// An attempt to encode `Vec` with more items than can fit in `usize`
    /// encoding rules will result in `Error::ExceedMaxItems`.
    impl<T> StrictDecode for Vec<T>
    where
        T: StrictDecode,
        T::Error: From<Error>,
    {
        type Error = T::Error;
        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
            let len = usize::strict_decode(&mut d)?;
            let mut data = Vec::<T>::with_capacity(len as usize);
            for _ in 0..len {
                data.push(T::strict_decode(&mut d)?);
            }
            Ok(data)
        }
    }

    /// Strict encoding for a unique value collection represented by a rust
    /// `HashSet` type is performed in the same way as `Vec` encoding.
    /// NB: Array members must are ordered with the sort operation, so type
    /// `T` must implement `Ord` trait in such a way that it produces
    /// deterministically-sorted result
    impl<T> StrictEncode for HashSet<T>
    where
        T: StrictEncode + Eq + Ord + Hash + Debug,
        T::Error: From<Error>,
    {
        type Error = T::Error;
        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
            let len = self.len() as usize;
            let mut encoded = len.strict_encode(&mut e)?;
            let mut vec: Vec<&T> = self.iter().collect();
            vec.sort();
            for item in vec {
                encoded += item.strict_encode(&mut e)?;
            }
            Ok(encoded)
        }
    }

    /// Strict decoding of a unique value collection represented by a rust
    /// `HashSet` type is performed alike `Vec` decoding with the only
    /// exception: if the repeated value met a [Error::RepeatedValue] is
    /// returned.
    impl<T> StrictDecode for HashSet<T>
    where
        T: StrictDecode + Eq + Ord + Hash + Debug,
        T::Error: From<Error>,
    {
        type Error = T::Error;
        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
            let len = usize::strict_decode(&mut d)?;
            let mut data = HashSet::<T>::with_capacity(len as usize);
            for _ in 0..len {
                let val = T::strict_decode(&mut d)?;
                if data.contains(&val) {
                    Err(Error::RepeatedValue(format!("{:?}", val)))?;
                } else {
                    data.insert(val);
                }
            }
            Ok(data)
        }
    }

    /// Strict encoding for a unique value collection represented by a rust
    /// `BTreeSet` type is performed in the same way as `Vec` encoding.
    /// NB: Array members must are ordered with the sort operation, so type
    /// `T` must implement `Ord` trait in such a way that it produces
    /// deterministically-sorted result
    impl<T> StrictEncode for BTreeSet<T>
    where
        T: StrictEncode + Eq + Ord + Debug,
        T::Error: From<Error>,
    {
        type Error = T::Error;
        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
            let len = self.len() as usize;
            let mut encoded = len.strict_encode(&mut e)?;
            let mut vec: Vec<&T> = self.iter().collect();
            vec.sort();
            for item in vec {
                encoded += item.strict_encode(&mut e)?;
            }
            Ok(encoded)
        }
    }

    /// Strict decoding of a unique value collection represented by a rust
    /// `BTreeSet` type is performed alike `Vec` decoding with the only
    /// exception: if the repeated value met a [Error::RepeatedValue] is
    /// returned.
    impl<T> StrictDecode for BTreeSet<T>
    where
        T: StrictDecode + Eq + Ord + Debug,
        T::Error: From<Error>,
    {
        type Error = T::Error;
        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
            let len = usize::strict_decode(&mut d)?;
            let mut data = BTreeSet::<T>::new();
            for _ in 0..len {
                let val = T::strict_decode(&mut d)?;
                if data.contains(&val) {
                    Err(Error::RepeatedValue(format!("{:?}", val)))?;
                } else {
                    data.insert(val);
                }
            }
            Ok(data)
        }
    }

    /// LNP/BP library uses `HashMap<usize, T: StrictEncode>`s to encode
    /// ordered lists, where the position of the list item must be fixed, since
    /// the item is referenced from elsewhere by its index. Thus, the library
    /// does not supports and recommends not to support strict encoding
    /// of any other `HashMap` variants.
    ///
    /// Strict encoding of the `HashMap<usize, T>` type is performed by
    /// converting into a fixed-order `Vec<T>` and serializing it according to
    /// the `Vec` strict encoding rules. This operation is internally
    /// performed via conversion into `BTreeMap<usize, T: StrictEncode>`.
    impl<T> StrictEncode for HashMap<usize, T>
    where
        T: StrictEncode + Clone,
        T::Error: From<Error>,
    {
        type Error = T::Error;
        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
            let ordered: BTreeMap<usize, T> =
                self.iter().map(|(key, val)| (*key, val.clone())).collect();
            ordered.strict_encode(&mut e)
        }
    }

    /// LNP/BP library uses `HashMap<usize, T: StrictEncode>`s to encode
    /// ordered lists, where the position of the list item must be fixed, since
    /// the item is referenced from elsewhere by its index. Thus, the library
    /// does not supports and recommends not to support strict encoding
    /// of any other `HashMap` variants.
    ///
    /// Strict encoding of the `HashMap<usize, T>` type is performed by
    /// converting into a fixed-order `Vec<T>` and serializing it according to
    /// the `Vec` strict encoding rules. This operation is internally
    /// performed via conversion into `BTreeMap<usize, T: StrictEncode>`.
    impl<T> StrictDecode for HashMap<usize, T>
    where
        T: StrictDecode + Clone,
        T::Error: From<Error>,
    {
        type Error = T::Error;
        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
            let map: HashMap<usize, T> = BTreeMap::<usize, T>::strict_decode(&mut d)?
                .iter()
                .map(|(key, val)| (*key, val.clone()))
                .collect();
            Ok(map)
        }
    }

    /// LNP/BP library uses `BTreeMap<usize, T: StrictEncode>`s to encode
    /// ordered lists, where the position of the list item must be fixed, since
    /// the item is referenced from elsewhere by its index. Thus, the library
    /// does not supports and recommends not to support strict encoding
    /// of any other `BTreeMap` variants.
    ///
    /// Strict encoding of the `BTreeMap<usize, T>` type is performed
    /// by converting into a fixed-order `Vec<T>` and serializing it according
    /// to the `Vec` strict encoding rules.
    impl<K, V> StrictEncode for BTreeMap<K, V>
    where
        K: StrictEncode + Ord + Clone,
        V: StrictEncode + Clone,
        K::Error: From<Error>,
        V::Error: From<Error> + From<K::Error>,
    {
        type Error = V::Error;
        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
            let len = self.len() as usize;
            let encoded = len.strict_encode(&mut e)?;

            self.iter().try_fold(encoded, |mut acc, (key, val)| {
                acc += key.strict_encode(&mut e)?;
                acc += val.strict_encode(&mut e)?;
                Ok(acc)
            })
        }
    }

    /// LNP/BP library uses `BTreeMap<usize, T: StrictEncode>`s to encode
    /// ordered lists, where the position of the list item must be fixed, since
    /// the item is referenced from elsewhere by its index. Thus, the library
    /// does not supports and recommends not to support strict encoding
    /// of any other `BTreeMap` variants.
    ///
    /// Strict encoding of the `BTreeMap<usize, T>` type is performed
    /// by converting into a fixed-order `Vec<T>` and serializing it according
    /// to the `Vec` strict encoding rules.
    impl<K, V> StrictDecode for BTreeMap<K, V>
    where
        K: StrictDecode + Ord + Clone,
        V: StrictDecode + Clone,
        K::Error: From<Error>,
        V::Error: From<Error> + From<K::Error>,
    {
        type Error = V::Error;
        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
            let len = usize::strict_decode(&mut d)?;
            let mut map = BTreeMap::<K, V>::new();
            for _ in 0..len {
                let key = K::strict_decode(&mut d)?;
                let val = V::strict_decode(&mut d)?;
                map.insert(key, val);
            }
            Ok(map)
        }
    }

    /// Two-component tuples are encoded as they were fields in the parent
    /// data structure
    impl<K, V> StrictEncode for (K, V)
    where
        K: StrictEncode + Clone,
        V: StrictEncode + Clone,
        K::Error: From<Error>,
        V::Error: From<Error> + From<K::Error>,
    {
        type Error = V::Error;
        fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
            Ok(self.0.strict_encode(&mut e)? + self.1.strict_encode(&mut e)?)
        }
    }

    /// Two-component tuples are decoded as they were fields in the parent
    /// data structure
    impl<K, V> StrictDecode for (K, V)
    where
        K: StrictDecode + Clone,
        V: StrictDecode + Clone,
        K::Error: From<Error>,
        V::Error: From<Error> + From<K::Error>,
    {
        type Error = V::Error;
        fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
            let a = K::strict_decode(&mut d)?;
            let b = V::strict_decode(&mut d)?;
            Ok((a, b))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn gen_strings() -> Vec<&'static str> {
        vec![
            "",
            "0",
            " ",
            "A string slice (&str) is made of bytes (u8), and a byte slice \
            (&[u8]) is made of bytes, so this function converts between the two.\
             Not all byte slices are valid string slices, however: &str requires \
             that it is valid UTF-8. from_utf8() checks to ensure that the bytes \
             are valid UTF-8, and then does the conversion.",
        ]
    }

    #[test]
    fn test_encode_decode() {
        gen_strings().into_iter().for_each(|s| {
            let r = strict_encode(&s).unwrap();
            let p: String = strict_decode(&r).unwrap();
            assert_eq!(s, p);
        })
    }

    #[test]
    #[should_panic(expected = "DataNotEntirelyConsumed")]
    fn test_consumation() {
        gen_strings().into_iter().for_each(|s| {
            let mut r = strict_encode(&s).unwrap();
            r.extend_from_slice("data".as_ref());
            let _: String = strict_decode(&r).unwrap();
        })
    }

    #[test]
    fn test_error_propagation() {
        gen_strings().into_iter().for_each(|s| {
            let r = strict_encode(&s).unwrap();
            let p: Result<String, _> = strict_decode(&r[..1].to_vec());
            assert!(p.is_err());
        })
    }

    /// Checking that byte encoding and decoding works correctly for the most common
    /// marginal and middle-probability cases
    #[test]
    fn test_u8_encode() {
        let zero: u8 = 0;
        let one: u8 = 1;
        let thirteen: u8 = 13;
        let confusing: u8 = 0xEF;
        let nearly_full: u8 = 0xFE;
        let full: u8 = 0xFF;

        let byte_0 = &[0u8][..];
        let byte_1 = &[1u8][..];
        let byte_13 = &[13u8][..];
        let byte_ef = &[0xEFu8][..];
        let byte_fe = &[0xFEu8][..];
        let byte_ff = &[0xFFu8][..];

        assert_eq!(strict_encode(&zero).unwrap(), byte_0);
        assert_eq!(strict_encode(&one).unwrap(), byte_1);
        assert_eq!(strict_encode(&thirteen).unwrap(), byte_13);
        assert_eq!(strict_encode(&confusing).unwrap(), byte_ef);
        assert_eq!(strict_encode(&nearly_full).unwrap(), byte_fe);
        assert_eq!(strict_encode(&full).unwrap(), byte_ff);

        assert_eq!(u8::strict_decode(byte_0).unwrap(), zero);
        assert_eq!(u8::strict_decode(byte_1).unwrap(), one);
        assert_eq!(u8::strict_decode(byte_13).unwrap(), thirteen);
        assert_eq!(u8::strict_decode(byte_ef).unwrap(), confusing);
        assert_eq!(u8::strict_decode(byte_fe).unwrap(), nearly_full);
        assert_eq!(u8::strict_decode(byte_ff).unwrap(), full);
    }

    /// Test for checking the following rule from LNPBP-5:
    ///
    /// `Option<T>` of any type T, which are set to `Option::None` value MUST encode as two
    /// zero bytes and it MUST be possible to decode optional of any type from two zero bytes
    /// which MUST result in `Option::None` value.
    #[test]
    fn test_option_encode_none() {
        let o1: Option<u8> = None;
        let o2: Option<u64> = None;

        let two_zero_bytes = &vec![0u8][..];

        assert_eq!(strict_encode(&o1).unwrap(), two_zero_bytes);
        assert_eq!(strict_encode(&o2).unwrap(), two_zero_bytes);

        assert_eq!(Option::<u8>::strict_decode(two_zero_bytes).unwrap(), None);
        assert_eq!(Option::<u64>::strict_decode(two_zero_bytes).unwrap(), None);
    }

    /// Test for checking the following rule from LNPBP-5:
    ///
    /// `Option<T>` of any type T, which are set to `Option::Some<T>` value MUST encode as a
    /// `Vec<T>` structure containing a single item equal to the `Option::unwrap()` value.
    #[test]
    fn test_option_encode_some() {
        let o1: Option<u8> = Some(0);
        let o2: Option<u8> = Some(13);
        let o3: Option<u8> = Some(0xFF);
        let o4: Option<u64> = Some(13);
        let o5: Option<u64> = Some(0x1FF);
        let o6: Option<u64> = Some(0xFFFFFFFFFFFFFFFF);
        let o7: Option<usize> = Some(13);
        let o8: Option<usize> = Some(0xFFFFFFFFFFFFFFFF);

        let byte_0 = &[1u8, 0u8][..];
        let byte_13 = &[1u8, 13u8][..];
        let byte_255 = &[1u8, 0xFFu8][..];
        let word_13 = &[1u8, 13u8, 0u8][..];
        let qword_13 = &[1u8, 13u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8][..];
        let qword_256 = &[1u8, 0xFFu8, 0x01u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8][..];
        let qword_max = &[
            1u8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8,
        ][..];

        assert_eq!(strict_encode(&o1).unwrap(), byte_0);
        assert_eq!(strict_encode(&o2).unwrap(), byte_13);
        assert_eq!(strict_encode(&o3).unwrap(), byte_255);
        assert_eq!(strict_encode(&o4).unwrap(), qword_13);
        assert_eq!(strict_encode(&o5).unwrap(), qword_256);
        assert_eq!(strict_encode(&o6).unwrap(), qword_max);
        assert_eq!(strict_encode(&o7).unwrap(), word_13);
        assert!(strict_encode(&o8).err().is_some());

        assert_eq!(Option::<u8>::strict_decode(byte_0).unwrap(), Some(0));
        assert_eq!(Option::<u8>::strict_decode(byte_13).unwrap(), Some(13));
        assert_eq!(Option::<u8>::strict_decode(byte_255).unwrap(), Some(0xFF));
        assert_eq!(Option::<u64>::strict_decode(qword_13).unwrap(), Some(13));
        assert_eq!(
            Option::<u64>::strict_decode(qword_256).unwrap(),
            Some(0x1FF)
        );
        assert_eq!(
            Option::<u64>::strict_decode(qword_max).unwrap(),
            Some(0xFFFFFFFFFFFFFFFF)
        );
        assert_eq!(Option::<usize>::strict_decode(word_13).unwrap(), Some(13));
        assert_eq!(
            Option::<usize>::strict_decode(qword_max).unwrap(),
            Some(0xFFFF)
        );
    }

    /// Test trying decoding of non-zero and non-single item vector structures, which MUST
    /// fail with a specific error.
    #[test]
    fn test_option_decode_vec() {
        assert!(Option::<u8>::strict_decode(&[2u8, 0u8, 0u8, 0u8][..])
            .err()
            .is_some());
        assert!(Option::<u8>::strict_decode(&[3u8, 0u8, 0u8, 0u8][..])
            .err()
            .is_some());
        assert!(Option::<u8>::strict_decode(&[0xFFu8, 0u8, 0u8, 0u8][..])
            .err()
            .is_some());
    }

    /// Test for checking the following rule from LNPBP-5:
    ///
    /// Array of any commitment-serializable type T MUST contain strictly less than `0x10000` items
    /// and must encode as 16-bit little-endian value corresponding to the number of items
    /// followed by a direct encoding of each of the items.
    #[test]
    fn test_vec_encode() {
        let v1: Vec<u8> = vec![0, 13, 0xFF];
        let v2: Vec<u8> = vec![13];
        let v3: Vec<u64> = vec![0, 13, 13, 0x1FF, 0xFFFFFFFFFFFFFFFF];
        let v4: Vec<u8> = (0..0x1FFFF).map(|item| (item % 0xFF) as u8).collect();

        let s1 = &[3u8, 0u8, 0u8, 13u8, 0xFFu8][..];
        let s2 = &[1u8, 0u8, 13u8][..];
        let s3 = &[
            5u8, 0u8, 0, 0, 0, 0, 0, 0, 0, 0, 13, 0, 0, 0, 0, 0, 0, 0, 13, 0, 0, 0, 0, 0, 0, 0,
            0xFF, 1, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ][..];

        assert_eq!(strict_encode(&v1).unwrap(), s1);
        assert_eq!(strict_encode(&v2).unwrap(), s2);
        assert_eq!(strict_encode(&v3).unwrap(), s3);
        assert!(strict_encode(&v4).err().is_some());

        assert_eq!(Vec::<u8>::strict_decode(s1).unwrap(), v1);
        assert_eq!(Vec::<u8>::strict_decode(s2).unwrap(), v2);
        assert_eq!(Vec::<u64>::strict_decode(s3).unwrap(), v3);
    }
}

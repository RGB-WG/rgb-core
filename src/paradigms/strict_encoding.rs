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

use std::fmt::{self, Display, Formatter};
use std::io;

/// Re-exporting extended read and write functions from bitcoin consensus module
/// so others may use semantic convenience `lnpbp::strict_serialize::ReadExt`
pub use bitcoin::consensus::encode::{ReadExt, WriteExt};

/// Binary serialization according to the strict rules that usually apply to
/// consensus-critical data structures. May be used for network communications;
/// in some circumstances may be used for commitment procedures; however it must
/// be kept in mind that sometime commitment may follow "fold" scheme
/// (Merklization or nested commitments) and in such cases this trait can't be
/// applied. It is generally recommended for consensus-related commitments to
/// utilize [CommitVerify], [TryCommitVerify] and [EmbedCommitVerify] traits  
/// from [paradigms::commit_verify] module.
pub trait StrictSerialize {
    /// Implementation-dependent error type
    type Error: std::error::Error + From<Error>;

    /// Serialize with the given [std::io::Writer] instance; must return result
    /// with either amount of bytes serialized – or implementation-specific
    /// error type.
    fn strict_serialize<E: io::Write>(&self, e: E) -> Result<usize, Self::Error>;
}

/// Binary deserialization according to the strict rules that usually apply to
/// consensus-critical data structures. May be used for network communications.
/// MUST NOT be used for commitment verification: even if the commit procedure
/// uses [StrictSerialize], the actual commit verification MUST be done with
/// [CommitVerify], [TryCommitVerify] and [EmbedCommitVerify] traits, which,
/// instead of deserializing (nonce operation for commitments) repeat the
/// commitment procedure for the revealed message and verify it against the
/// provided commitment.
pub trait StrictDeserialize: Sized {
    /// Implementation-dependent error type
    type Error: std::error::Error + From<Error>;

    /// Deserialize with the given [std::io::Reader] instance; must either
    /// construct an instance or return implementation-specific error type.
    fn strict_deserialize<D: io::Read>(d: D) -> Result<Self, Self::Error>;
}

/// Convenience method for strict serialization of data structures implementing
/// [StrictSerialize] into a byte vector. To support this method a
/// type must implement `From<strict_serialize::Error>` for an error type
/// provided as the associated type [StrictDeserialize::Error].
pub fn strict_serialize<T>(data: &T) -> Result<Vec<u8>, T::Error>
where
    T: StrictSerialize,
    T::Error: std::error::Error + From<Error>,
{
    let mut encoder = io::Cursor::new(vec![]);
    data.strict_serialize(&mut encoder)?;
    Ok(encoder.into_inner())
}

/// Convenience method for strict deserialization of data structures implementing
/// [StrictDeserialize] from any byt data source. To support this method a
/// type must implement `From<strict_serialize::Error>` for an error type
/// provided as the associated type [StrictDeserialize::Error].
pub fn strict_deserialize<T>(data: &impl AsRef<[u8]>) -> Result<T, T::Error>
where
    T: StrictDeserialize,
    T::Error: std::error::Error + From<Error>,
{
    let mut decoder = io::Cursor::new(data);
    let rv = T::strict_deserialize(&mut decoder)?;
    let consumed = decoder.position() as usize;

    // Fail if data are not consumed entirely.
    if consumed == data.as_ref().len() {
        Ok(rv)
    } else {
        Err(Error::DataNotEntirelyConsumed)?
    }
}

/// Possible errors during strict serialization and deserialization process
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

    /// In terms of strict serialization, we interpret `Option` as a zero-length
    /// `Vec` (for `Optional::None`) or single-item `Vec` (for `Optional::Some`).
    /// For deserialization an attempt to read `Option` from a serialized non-0
    /// or non-1 length Vec will result in `Error::WrongOptionalEncoding`.
    WrongOptionalEncoding(u8),

    /// Returned by the convenience method [strict_deserialize] if not all
    /// provided data were consumed during deserialization process
    DataNotEntirelyConsumed,
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
            DataNotEntirelyConsumed => write!(
                f,
                "Data were not consumed entirely during strict deserialization procedure"
            ),
        }
    }
}

#[macro_export]
macro_rules! strict_serialize_list {
    ( $encoder:ident; $($item:expr),+ ) => {
        {
            let mut len = 0usize;
            $(
                len += $item.strict_serialize(&mut $encoder)?;
            )+
            len
        }
    }
}

mod bitcoin_based {
    use super::{Error, StrictDeserialize, StrictSerialize};
    use std::io;

    /// Marker trait for serialization as it is done in bitcoin consensus
    pub trait WithBitcoinEncoding:
        bitcoin::consensus::Encodable + bitcoin::consensus::Decodable
    {
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

    impl<T> StrictSerialize for T
    where
        T: WithBitcoinEncoding,
    {
        type Error = Error;

        #[inline]
        fn strict_serialize<E: io::Write>(&self, e: E) -> Result<usize, Self::Error> {
            self.consensus_encode(e).map_err(Error::from)
        }
    }

    impl<T> StrictDeserialize for T
    where
        T: WithBitcoinEncoding,
    {
        type Error = Error;

        #[inline]
        fn strict_deserialize<D: io::Read>(d: D) -> Result<Self, Self::Error> {
            Self::consensus_decode(d).map_err(Error::from)
        }
    }
}
pub use bitcoin_based::WithBitcoinEncoding;

/// Taking implementation of little-endian integer serialization
mod number_little_endian {
    use super::{Error, StrictDeserialize, StrictSerialize, WithBitcoinEncoding};
    use bitcoin::util::uint::{Uint128, Uint256};
    use std::io;

    impl WithBitcoinEncoding for u8 {}
    impl WithBitcoinEncoding for u16 {}
    impl WithBitcoinEncoding for u32 {}
    impl WithBitcoinEncoding for u64 {}
    impl WithBitcoinEncoding for Uint128 {}
    impl WithBitcoinEncoding for Uint256 {}
    impl WithBitcoinEncoding for i8 {}
    impl WithBitcoinEncoding for i16 {}
    impl WithBitcoinEncoding for i32 {}
    impl WithBitcoinEncoding for i64 {}

    impl StrictSerialize for usize {
        type Error = Error;
        fn strict_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
            if *self > std::u16::MAX as usize {
                Err(Error::ExceedMaxItems(*self))?;
            }
            let size = *self as u16;
            size.strict_serialize(&mut e)
        }
    }

    impl StrictDeserialize for usize {
        type Error = Error;
        fn strict_deserialize<D: io::Read>(mut d: D) -> Result<Self, Error> {
            u16::strict_deserialize(&mut d).map(|val| val as usize)
        }
    }

    impl StrictSerialize for f32 {
        type Error = Error;
        fn strict_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
            e.write_all(&self.to_le_bytes())?;
            Ok(4)
        }
    }

    impl StrictDeserialize for f32 {
        type Error = Error;
        fn strict_deserialize<D: io::Read>(mut d: D) -> Result<Self, Error> {
            let mut buf: [u8; 4] = [0; 4];
            d.read_exact(&mut buf)?;
            Ok(Self::from_le_bytes(buf))
        }
    }

    impl StrictSerialize for f64 {
        type Error = Error;
        fn strict_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
            e.write_all(&self.to_le_bytes())?;
            Ok(8)
        }
    }

    impl StrictDeserialize for f64 {
        type Error = Error;
        fn strict_deserialize<D: io::Read>(mut d: D) -> Result<Self, Error> {
            let mut buf: [u8; 8] = [0; 8];
            d.read_exact(&mut buf)?;
            Ok(Self::from_le_bytes(buf))
        }
    }
}

mod byte_strings {
    use super::{Error, StrictDeserialize, StrictSerialize};
    use std::io;
    use std::ops::Deref;

    impl StrictSerialize for &[u8] {
        type Error = Error;
        fn strict_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
            let mut len = self.len();
            // We handle oversize problems at the level of `usize` value serializaton
            len += len.strict_serialize(&mut e)?;
            e.write_all(self)?;
            Ok(len)
        }
    }

    impl StrictSerialize for Box<[u8]> {
        type Error = Error;
        fn strict_serialize<E: io::Write>(&self, e: E) -> Result<usize, Error> {
            self.deref().strict_serialize(e)
        }
    }

    impl StrictDeserialize for Box<[u8]> {
        type Error = Error;
        fn strict_deserialize<D: io::Read>(mut d: D) -> Result<Self, Error> {
            let len = usize::strict_deserialize(&mut d)?;
            let mut ret = vec![0u8; len];
            d.read_exact(&mut ret)?;
            Ok(ret.into_boxed_slice())
        }
    }

    impl StrictSerialize for &str {
        type Error = Error;
        fn strict_serialize<E: io::Write>(&self, e: E) -> Result<usize, Error> {
            self.as_bytes().strict_serialize(e)
        }
    }

    impl StrictSerialize for String {
        type Error = Error;
        fn strict_serialize<E: io::Write>(&self, e: E) -> Result<usize, Error> {
            self.as_bytes().strict_serialize(e)
        }
    }

    impl StrictDeserialize for String {
        type Error = Error;
        fn strict_deserialize<D: io::Read>(d: D) -> Result<Self, Error> {
            String::from_utf8(Vec::<u8>::strict_deserialize(d)?).map_err(Error::from)
        }
    }
}

mod compositional_types {
    use super::{Error, StrictDeserialize, StrictSerialize};
    use std::collections::{BTreeMap, HashMap};
    use std::io;

    /// In terms of strict encoding, `Option` (optional values) are  
    /// represented by a *significator byte*, which MUST be either `0` (for no
    /// value present) or `1`, followed by the value strict encoding.
    impl<T> StrictSerialize for Option<T>
    where
        T: StrictSerialize,
        T::Error: From<Error>,
    {
        type Error = T::Error;
        fn strict_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
            Ok(match self {
                None => strict_serialize_list!(e; 0u8),
                Some(val) => strict_serialize_list!(e; 1u8, val),
            })
        }
    }

    /// In terms of strict encoding, `Option` (optional values) are  
    /// represented by a *significator byte*, which MUST be either `0` (for no
    /// value present) or `1`, followed by the value strict encoding.
    /// For deserialization an attempt to read `Option` from a serialized non-0
    /// or non-1 length Vec will result in `Error::WrongOptionalEncoding`.
    impl<T> StrictDeserialize for Option<T>
    where
        T: StrictDeserialize,
        T::Error: From<Error>,
    {
        type Error = T::Error;
        fn strict_deserialize<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
            let len = u8::strict_deserialize(&mut d)?;
            match len {
                0 => Ok(None),
                1 => Ok(Some(T::strict_deserialize(&mut d)?)),
                invalid => Err(Error::WrongOptionalEncoding(invalid))?,
            }
        }
    }

    /// In terms of strict serialization, `Vec` is stored in form of
    /// usize-serialized length (see `StrictSerialize` implementation for `usize`
    /// type for serialization platform-independent constant-length
    /// serialization rules) followed by a consequently-serialized vec items,
    /// according to their type.
    ///
    /// An attempt to serialize `Vec` with more items than can fit in `usize`
    /// serialization rules will result in `Error::ExceedMaxItems`.
    impl<T> StrictSerialize for Vec<T>
    where
        T: StrictSerialize,
        T::Error: From<Error>,
    {
        type Error = T::Error;
        fn strict_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
            let len = self.len() as usize;
            let mut serialized = len.strict_serialize(&mut e)?;
            for item in self {
                serialized += item.strict_serialize(&mut e)?;
            }
            Ok(serialized)
        }
    }

    impl<T> StrictDeserialize for Vec<T>
    where
        T: StrictDeserialize,
        T::Error: From<Error>,
    {
        type Error = T::Error;
        fn strict_deserialize<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
            let len = usize::strict_deserialize(&mut d)?;
            let mut data = Vec::<T>::with_capacity(len as usize);
            for _ in 0..len {
                data.push(T::strict_deserialize(&mut d)?);
            }
            Ok(data)
        }
    }

    /// LNP/BP library uses `HashMap<usize, T: StrictSerialize>`s to serialize
    /// ordered lists, where the position of the list item must be fixed, since
    /// the item is referenced from elsewhere by its index. Thus, the library
    /// does not supports and recommends not to support strict serialization
    /// of any other `HashMap` variants.
    ///
    /// Strict serialization of the `HashMap<usize, T>` type is performed by
    /// converting into a fixed-order `Vec<T>` and serializing it according to
    /// the `Vec` strict serialization rules. This operation is internally
    /// performed via conversion into `BTreeMap<usize, T: StrictSerialize>`.
    impl<T> StrictSerialize for HashMap<usize, T>
    where
        T: StrictSerialize + Clone,
        T::Error: From<Error>,
    {
        type Error = T::Error;
        fn strict_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
            let ordered: BTreeMap<usize, T> =
                self.iter().map(|(key, val)| (*key, val.clone())).collect();
            ordered.strict_serialize(&mut e)
        }
    }

    impl<T> StrictDeserialize for HashMap<usize, T>
    where
        T: StrictDeserialize + Clone,
        T::Error: From<Error>,
    {
        type Error = T::Error;
        fn strict_deserialize<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
            let map: HashMap<usize, T> = BTreeMap::<usize, T>::strict_deserialize(&mut d)?
                .iter()
                .map(|(key, val)| (*key, val.clone()))
                .collect();
            Ok(map)
        }
    }

    /// LNP/BP library uses `BTreeMap<usize, T: StrictSerialize>`s to serialize
    /// ordered lists, where the position of the list item must be fixed, since
    /// the item is referenced from elsewhere by its index. Thus, the library
    /// does not supports and recommends not to support strict serialization
    /// of any other `BTreeMap` variants.
    ///
    /// Strict serialization of the `BTreeMap<usize, T>` type is performed
    /// by converting into a fixed-order `Vec<T>` and serializing it according
    /// to the `Vec` strict serialization rules.
    impl<T> StrictSerialize for BTreeMap<usize, T>
    where
        T: StrictSerialize,
        T::Error: From<Error>,
    {
        type Error = T::Error;
        fn strict_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
            let len = self.len() as usize;
            let serialized = len.strict_serialize(&mut e)?;

            self.values().try_fold(serialized, |acc, item| {
                item.strict_serialize(&mut e).map(|len| acc + len)
            })
        }
    }

    impl<T> StrictDeserialize for BTreeMap<usize, T>
    where
        T: StrictDeserialize,
        T::Error: From<Error>,
    {
        type Error = T::Error;
        fn strict_deserialize<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
            let len = usize::strict_deserialize(&mut d)?;
            let mut map = BTreeMap::<usize, T>::new();
            for index in 0..len {
                map.insert(index, T::strict_deserialize(&mut d)?);
            }
            Ok(map)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::bytes;

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
    fn test_serialize_deserialize() {
        gen_strings().into_iter().for_each(|s| {
            let r = strict_serialize(&s).unwrap();
            let p: String = strict_deserialize(&r).unwrap();
            assert_eq!(s, p);
        })
    }

    #[test]
    #[should_panic(expected = "DataNotEntirelyConsumed")]
    fn test_consumation() {
        gen_strings().into_iter().for_each(|s| {
            let mut r = strict_serialize(&s).unwrap();
            r.extend_from_slice("data".as_ref());
            let _: String = strict_deserialize(&r).unwrap();
        })
    }

    #[test]
    fn test_error_propagation() {
        gen_strings().into_iter().for_each(|s| {
            let r = strict_serialize(&s).unwrap();
            let p: Result<String, _> = strict_deserialize(&r[..1].to_vec());
            assert!(p.is_err());
        })
    }

    /// Checking that byte serialization and deserialization works correctly for the most common
    /// marginal and middle-probability cases
    #[test]
    fn test_u8_serialize() {
        let zero: u8 = 0;
        let one: u8 = 1;
        let thirteen: u8 = 13;
        let confusing: u8 = 0xEF;
        let nearly_full: u8 = 0xFE;
        let full: u8 = 0xFF;

        let byte_0 = bytes![0u8];
        let byte_1 = bytes![1u8];
        let byte_13 = bytes![13u8];
        let byte_ef = bytes![0xEFu8];
        let byte_fe = bytes![0xFEu8];
        let byte_ff = bytes![0xFFu8];

        assert_eq!(strict_serialize(&zero).unwrap(), byte_0);
        assert_eq!(strict_serialize(&one).unwrap(), byte_1);
        assert_eq!(strict_serialize(&thirteen).unwrap(), byte_13);
        assert_eq!(strict_serialize(&confusing).unwrap(), byte_ef);
        assert_eq!(strict_serialize(&nearly_full).unwrap(), byte_fe);
        assert_eq!(strict_serialize(&full).unwrap(), byte_ff);

        assert_eq!(u8::strict_deserialize(byte_0).unwrap(), zero);
        assert_eq!(u8::strict_deserialize(byte_1).unwrap(), one);
        assert_eq!(u8::strict_deserialize(byte_13).unwrap(), thirteen);
        assert_eq!(u8::strict_deserialize(byte_ef).unwrap(), confusing);
        assert_eq!(u8::strict_deserialize(byte_fe).unwrap(), nearly_full);
        assert_eq!(u8::strict_deserialize(byte_ff).unwrap(), full);
    }

    /// Test for checking the following rule from LNPBP-5:
    ///
    /// `Option<T>` of any type T, which are set to `Option::None` value MUST serialize as two
    /// zero bytes and it MUST be possible to deserialize optional of any type from two zero bytes
    /// which MUST result in `Option::None` value.
    #[test]
    fn test_option_serialize_none() {
        let o1: Option<u8> = None;
        let o2: Option<u64> = None;

        let two_zero_bytes = &vec![0u8][..];

        assert_eq!(strict_serialize(&o1).unwrap(), two_zero_bytes);
        assert_eq!(strict_serialize(&o2).unwrap(), two_zero_bytes);

        assert_eq!(
            Option::<u8>::strict_deserialize(two_zero_bytes).unwrap(),
            None
        );
        assert_eq!(
            Option::<u64>::strict_deserialize(two_zero_bytes).unwrap(),
            None
        );
    }

    /// Test for checking the following rule from LNPBP-5:
    ///
    /// `Option<T>` of any type T, which are set to `Option::Some<T>` value MUST serialize as a
    /// `Vec<T>` structure containing a single item equal to the `Option::unwrap()` value.
    #[test]
    fn test_option_serialize_some() {
        let o1: Option<u8> = Some(0);
        let o2: Option<u8> = Some(13);
        let o3: Option<u8> = Some(0xFF);
        let o4: Option<u64> = Some(13);
        let o5: Option<u64> = Some(0x1FF);
        let o6: Option<u64> = Some(0xFFFFFFFFFFFFFFFF);
        let o7: Option<usize> = Some(13);
        let o8: Option<usize> = Some(0xFFFFFFFFFFFFFFFF);

        let byte_0 = bytes![1u8, 0u8];
        let byte_13 = bytes![1u8, 13u8];
        let byte_255 = bytes![1u8, 0xFFu8];
        let word_13 = bytes![1u8, 13u8, 0u8];
        let qword_13 = bytes![1u8, 13u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        let qword_256 = bytes![1u8, 0xFFu8, 0x01u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        let qword_max = bytes![1u8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8];

        assert_eq!(strict_serialize(&o1).unwrap(), byte_0);
        assert_eq!(strict_serialize(&o2).unwrap(), byte_13);
        assert_eq!(strict_serialize(&o3).unwrap(), byte_255);
        assert_eq!(strict_serialize(&o4).unwrap(), qword_13);
        assert_eq!(strict_serialize(&o5).unwrap(), qword_256);
        assert_eq!(strict_serialize(&o6).unwrap(), qword_max);
        assert_eq!(strict_serialize(&o7).unwrap(), word_13);
        assert!(strict_serialize(&o8).err().is_some());

        assert_eq!(Option::<u8>::strict_deserialize(byte_0).unwrap(), Some(0));
        assert_eq!(Option::<u8>::strict_deserialize(byte_13).unwrap(), Some(13));
        assert_eq!(
            Option::<u8>::strict_deserialize(byte_255).unwrap(),
            Some(0xFF)
        );
        assert_eq!(
            Option::<u64>::strict_deserialize(qword_13).unwrap(),
            Some(13)
        );
        assert_eq!(
            Option::<u64>::strict_deserialize(qword_256).unwrap(),
            Some(0x1FF)
        );
        assert_eq!(
            Option::<u64>::strict_deserialize(qword_max).unwrap(),
            Some(0xFFFFFFFFFFFFFFFF)
        );
        assert_eq!(
            Option::<usize>::strict_deserialize(word_13).unwrap(),
            Some(13)
        );
        assert_eq!(
            Option::<usize>::strict_deserialize(qword_max).unwrap(),
            Some(0xFFFF)
        );
    }

    /// Test trying deserialization of non-zero and non-single item vector structures, which MUST
    /// fail with a specific error.
    #[test]
    fn test_option_deserialize_vec() {
        assert!(Option::<u8>::strict_deserialize(bytes![2u8, 0u8, 0u8, 0u8])
            .err()
            .is_some());
        assert!(Option::<u8>::strict_deserialize(bytes![3u8, 0u8, 0u8, 0u8])
            .err()
            .is_some());
        assert!(
            Option::<u8>::strict_deserialize(bytes![0xFFu8, 0u8, 0u8, 0u8])
                .err()
                .is_some()
        );
    }

    /// Test for checking the following rule from LNPBP-5:
    ///
    /// Array of any commitment-serializable type T MUST contain strictly less than `0x10000` items
    /// and must serialize as 16-bit little-endian value corresponding to the number of items
    /// followed by a direct serialization of each of the items.
    #[test]
    fn test_vec_serialize() {
        let v1: Vec<u8> = vec![0, 13, 0xFF];
        let v2: Vec<u8> = vec![13];
        let v3: Vec<u64> = vec![0, 13, 13, 0x1FF, 0xFFFFFFFFFFFFFFFF];
        let v4: Vec<u8> = (0..0x1FFFF).map(|item| (item % 0xFF) as u8).collect();

        let s1 = bytes![3u8, 0u8, 0u8, 13u8, 0xFFu8];
        let s2 = bytes![1u8, 0u8, 13u8];
        let s3 = bytes![
            5u8, 0u8, 0, 0, 0, 0, 0, 0, 0, 0, 13, 0, 0, 0, 0, 0, 0, 0, 13, 0, 0, 0, 0, 0, 0, 0,
            0xFF, 1, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        ];

        assert_eq!(strict_serialize(&v1).unwrap(), s1);
        assert_eq!(strict_serialize(&v2).unwrap(), s2);
        assert_eq!(strict_serialize(&v3).unwrap(), s3);
        assert!(strict_serialize(&v4).err().is_some());

        assert_eq!(Vec::<u8>::strict_deserialize(s1).unwrap(), v1);
        assert_eq!(Vec::<u8>::strict_deserialize(s2).unwrap(), v2);
        assert_eq!(Vec::<u64>::strict_deserialize(s3).unwrap(), v3);
    }
}

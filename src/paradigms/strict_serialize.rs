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
    type Error: std::error::Error;

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
    type Error: std::error::Error;

    /// Deserialize with the given [std::io::Reader] instance; must either
    /// construct an instance or return implementation-specific error type.
    fn strict_deserialize<D: io::Read>(d: D) -> Result<Self, Self::Error>;
}

impl Display for DataNotConsumedEntirelyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Data were not consumed entirely during strict deserialization procedure"
        )
    }
}

/// Convenience method for strict serialization of data structures implementing
/// [StrictSerialize] into a byte vector
pub fn strict_serialize<T>(data: &T) -> Result<Vec<u8>, T::Error>
where
    T: StrictSerialize,
    T::Error: From<DataNotConsumedEntirelyError>,
{
    let mut encoder = io::Cursor::new(vec![]);
    data.strict_serialize(&mut encoder)?;
    Ok(encoder.into_inner())
}

/// Convenience method for strict deserialization of data structures implementing
/// [StrictDeserialize] from any byt data source. To support this method a
/// type must implement `From<DataNotConsumedEntirelyError>` for an error type
/// provided as the associated type [StrictDeserialize::Error].
pub fn strict_deserialize<T>(data: &impl AsRef<[u8]>) -> Result<T, T::Error>
where
    T: StrictDeserialize,
    T::Error: From<DataNotConsumedEntirelyError>,
{
    let mut decoder = io::Cursor::new(data);
    let rv = T::strict_deserialize(&mut decoder)?;
    let consumed = decoder.position() as usize;

    // Fail if data are not consumed entirely.
    if consumed == data.as_ref().len() {
        Ok(rv)
    } else {
        Err(DataNotConsumedEntirelyError)?
    }
}

/// A singular error option that may be returned by the convenience method
/// [strict_deserialize]; any type that desire to have a support for this
/// convenience method must implement `From<DataNotConsumedEntirelyError>` for
/// the associated type [StrictDeserialize::Error].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Error)]
pub struct DataNotConsumedEntirelyError;

#[cfg(test)]
mod test {
    use super::*;

    use std::io::Error as IoError;
    use std::string::FromUtf8Error;
    #[derive(Error, From, Debug, Display)]
    #[display_from(Debug)]
    pub enum DumbError {
        #[derive_from(IoError)]
        IoError(IoError),
        #[derive_from(FromUtf8Error)]
        Utf8Error(FromUtf8Error),
        #[derive_from(DataNotConsumedEntirelyError)]
        DataNotConsumedEntirelyError,
    }

    impl StrictSerialize for &str {
        type Error = DumbError;
        fn strict_serialize<E: io::Write>(&self, mut e: E) -> Result<usize, Self::Error> {
            let len = self.len() as u64;
            let buf = len.to_be_bytes();
            e.write_all(&buf)?;
            e.write_all(self.as_ref())?;
            Ok(len as usize + buf.len())
        }
    }

    impl StrictDeserialize for String {
        type Error = DumbError;
        fn strict_deserialize<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
            let mut buf = [0u8; 8];
            d.read_exact(&mut buf)?;
            let len = u64::from_be_bytes(buf);
            let mut buf = vec![0u8; len as usize];
            d.read_exact(&mut buf);
            Ok(String::from_utf8(buf)?)
        }
    }

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
    fn test_consumation() {
        gen_strings().into_iter().for_each(|s| {
            let mut r = strict_serialize(&s).unwrap();
            r.extend_from_slice("data".as_ref());
            let p: Result<String, _> = strict_deserialize(&r);
            if let DumbError::DataNotConsumedEntirelyError = p.unwrap_err() {
            } else {
                assert!(false)
            }
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
}

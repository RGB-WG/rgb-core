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

use crate::lnp::transport;
use crate::strict_encoding;

#[cfg(feature = "lightning")]
use lightning::ln::msgs::DecodeError;

/// Presentation-level LNP error types. They do not include error source
/// for the simplicity of their encoding
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Display, Error, From)]
#[display(doc_comments)]
#[non_exhaustive]
#[repr(u16)]
pub enum Error {
    /// invalid connection endpoint data
    InvalidEndpoint,

    /// I/O error while decoding LNP message; probably socket error or out of
    /// memory
    #[from]
    Io(std::io::ErrorKind),

    /// message contains no data
    NoData,

    /// unknown encoder for encoding LNP message
    NoEncoder,

    /// unknown LNP protocol version
    UnknownProtocolVersion,

    /// error in strict encoded data in LMP message
    #[from(strict_encoding::Error)]
    EncodingError,

    /// unknown data type in LMP message
    #[from(UnknownTypeError)]
    UnknownDataType,

    /// invalid value in LMP message
    InvalidValue,

    /// LMP message with unknown even value
    MessageEvenType,

    /// bad length descriptor in LNP message
    BadLengthDescriptor,

    /// wrong order of TLV types inside LNP message
    TlvStreamWrongOrder,

    /// duplicated TLV type item inside LNP message
    TlvStreamDuplicateItem,

    /// found unknown even TLV record type inside LNP message
    TlvRecordEvenType,

    /// invalid length of TLV record inside LNP message
    TlvRecordInvalidLen,

    /// {0}
    #[from]
    Transport(transport::Error),
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err.kind())
    }
}

impl From<Error> for u8 {
    fn from(err: Error) -> Self {
        match err {
            Error::InvalidEndpoint => 0,
            Error::Io(_) => 1,
            Error::NoData => 2,
            Error::NoEncoder => 3,
            Error::UnknownProtocolVersion => 4,
            Error::EncodingError => 5,
            Error::UnknownDataType => 6,
            Error::InvalidValue => 7,
            Error::MessageEvenType => 8,
            Error::BadLengthDescriptor => 9,
            Error::TlvStreamWrongOrder => 10,
            Error::TlvStreamDuplicateItem => 11,
            Error::TlvRecordEvenType => 12,
            Error::TlvRecordInvalidLen => 13,
            Error::Transport(_) => 14,
        }
    }
}

#[cfg(feature = "lightning")]
impl From<DecodeError> for Error {
    fn from(err: DecodeError) -> Self {
        match err {
            DecodeError::UnknownVersion => Error::UnknownProtocolVersion,
            DecodeError::UnknownRequiredFeature => Error::MessageEvenType,
            DecodeError::InvalidValue => Error::InvalidValue,
            DecodeError::ShortRead => Error::NoData,
            DecodeError::BadLengthDescriptor => Error::BadLengthDescriptor,
            DecodeError::Io(_) => Error::Io,
        }
    }
}

/// Error representing unknown LNP message type
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, Error,
)]
#[display(Debug)]
pub struct UnknownTypeError;

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
    /// I/O error while decoding LNP message; probably socket error or out of
    /// memory
    #[from(std::io::Error)]
    Io = 1,

    /// LNP message contains no data
    NoData,

    /// Unknown encoder for encoding LNP message
    NoEncoder,

    /// Unknown LNP protocol version
    UnknownProtocolVersion,

    /// Error in strict encoded data in LNP message
    #[from(strict_encoding::Error)]
    EncodingError,

    /// Unknown data type in LNP message
    #[from(UnknownTypeError)]
    UnknownDataType,

    /// Invalid value in LNP message
    InvalidValue,

    /// LNP message with unknown even value
    MessageEvenType,

    /// Bad length descriptor in LNP message
    BadLengthDescriptor,

    /// Wrong order of TLV types inside LNP message
    TlvStreamWrongOrder,

    /// Duplicated TLV type item inside LNP message
    TlvStreamDuplicateItem,

    /// Found unknown even TLV record type inside LNP message
    TlvRecordEvenType,

    /// Invalid length of TLV record inside LNP message
    TlvRecordInvalidLen,
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

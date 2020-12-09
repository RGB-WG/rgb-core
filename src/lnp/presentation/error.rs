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

use super::encoding;
use crate::lnp::transport;
use crate::strict_encoding;

/// Presentation-level LNP error types
#[derive(Clone, PartialEq, Eq, Hash, Debug, Display, Error, From)]
#[display(doc_comments)]
#[non_exhaustive]
pub enum Error {
    /// invalid connection endpoint data
    InvalidEndpoint,

    /// message contains no data
    NoData,

    /// unknown encoder for encoding LNP message
    NoEncoder,

    /// unknown LNP protocol version
    UnknownProtocolVersion,

    /// Error in strict encoded data in LNP message
    #[display(inner)]
    #[from]
    StrictEncoding(strict_encoding::Error),

    /// Error in lightning-encoded data in LNP message
    #[display(inner)]
    #[from]
    LightningEncoding(encoding::Error),

    /// unknown data type in LNP message
    #[from(UnknownTypeError)]
    UnknownDataType,

    /// invalid value in LNP message
    InvalidValue,

    /// LNP message with unknown even value
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

    /// Transport-level LNP error
    #[display(inner)]
    #[from]
    Transport(transport::Error),
}

impl From<Error> for u8 {
    fn from(err: Error) -> Self {
        match err {
            Error::InvalidEndpoint => 0,
            Error::NoData => 2,
            Error::NoEncoder => 3,
            Error::UnknownProtocolVersion => 4,
            Error::StrictEncoding(_) => 5,
            Error::LightningEncoding(_) => 6,
            Error::UnknownDataType => 7,
            Error::InvalidValue => 8,
            Error::MessageEvenType => 9,
            Error::BadLengthDescriptor => 10,
            Error::TlvStreamWrongOrder => 11,
            Error::TlvStreamDuplicateItem => 12,
            Error::TlvRecordEvenType => 13,
            Error::TlvRecordInvalidLen => 14,
            Error::Transport(_) => 15,
        }
    }
}

/// Error representing unknown LNP message type
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, Error,
)]
#[display(Debug)]
pub struct UnknownTypeError;

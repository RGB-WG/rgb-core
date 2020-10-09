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

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(Debug)]
#[non_exhaustive]
pub enum Error {
    #[from(std::io::Error)]
    Io,
    NoData,
    NoEncoder,
    UnknownProtocolVersion,
    #[from]
    EncodingError(strict_encoding::Error),
    #[from(UnknownTypeError)]
    UnknownDataType,
    InvalidValue,
    MessageEvenType,
    BadLengthDescriptor,
    TlvStreamWrongOrder,
    TlvStreamDuplicateItem,
    TlvRecordEvenType,
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

#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, Error,
)]
#[display(Debug)]
pub struct UnknownTypeError;

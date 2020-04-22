// LNP/BP Rust Library
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


use zmq;

use bitcoin;
use bitcoin::secp256k1;

#[cfg(feature="rgb")]
use crate::csv;


#[derive(Debug, Display, From)]
#[display_from(Debug)]
pub enum Error {
    /// Transport-level error
    #[derive_from]
    SocketError(zmq::Error),

    // Request-specific errors
    MalformedRequest,
    MalformedCommand,
    UnknownCommand,

    // Reply-specific errors
    MalformedReply,
    MalformedStatus,
    UnknownStatus,

    // General API errors that may happen with both requests and replies
    MalformedArgument,
    WrongNumberOfArguments
}

impl std::error::Error for Error {}

impl From<Error> for String {
    fn from(err: Error) -> Self { format!("{}", err) }
}

impl From<bitcoin::consensus::encode::Error> for Error {
    fn from(_: bitcoin::consensus::encode::Error) -> Self {
        Error::MalformedArgument
    }
}

#[cfg(feature="rgb")]
impl From<csv::serialize::Error> for Error {
    fn from(_: csv::serialize::Error) -> Self {
        Error::MalformedArgument
    }
}

impl From<secp256k1::Error> for Error {
    fn from(_: secp256k1::Error) -> Self {
        Error::MalformedArgument
    }
}

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

#[cfg(feature = "node")]
use crate::error::RuntimeError;
use lnpbp::lnp;

/// Information about server-side failure returned through RPC API
#[derive(
    Clone, PartialEq, Eq, Hash, Debug, Display, StrictEncode, StrictDecode,
)]
#[display("Server returned failure #{code}: {info})")]
pub struct Failure {
    /// Failure #{}
    pub code: u16,

    /// Detailed information about the failure
    pub info: String,
}

/// Errors happening with RPC APIs
#[derive(Clone, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum Error {
    /// Unexpected server response
    UnexpectedServerResponse,

    #[from]
    /// {_0}
    ServerFailure(Failure),

    /// Error on LNP protocol transport level:
    /// {_0}
    #[from]
    PresentationError(lnp::presentation::Error),

    /// Error in LNP message serialization or structure:
    /// {_0}
    #[from]
    TransportError(lnp::transport::Error),
}

impl From<lnp::presentation::Error> for Failure {
    fn from(err: lnp::presentation::Error) -> Self {
        Failure {
            code: err as u16,
            info: err.to_string(),
        }
    }
}

#[cfg(feature = "node")]
impl<E> From<RuntimeError<E>> for Failure
where
    E: crate::error::Error,
{
    fn from(err: RuntimeError<E>) -> Self {
        Failure {
            code: 1000,
            info: err.to_string(),
        }
    }
}

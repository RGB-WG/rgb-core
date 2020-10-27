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

use std::fmt::{Debug, Display};
use std::hash::Hash;

use lnpbp::lnp;
use lnpbp::lnp::rpc_connection::Api;

#[cfg(feature = "node")]
use crate::error::RuntimeError;

/// Marker traits for endpoint identifiers lists
pub trait EndpointTypes: Copy + Eq + Hash + Display {}

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

    /// ZeroMQ socket error:
    /// {_0}
    #[from]
    Zmq(zmq::Error),

    /// Error on LNP protocol transport level:
    /// {_0}
    #[from]
    PresentationError(lnp::presentation::Error),

    /// Error in LNP message serialization or structure:
    /// {_0}
    #[from]
    TransportError(lnp::transport::Error),

    /// The provided RPC endpoint {_0} is unknown
    UnknownEndpoint(String),
}

impl From<lnp::presentation::Error> for Failure {
    fn from(err: lnp::presentation::Error) -> Self {
        Failure {
            code: u8::from(err) as u16,
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

/// Trait for types handling specific set of RPC API requests structured as a
/// single type implementing [`Request`]. They must return a corresponding reply
/// type implementing [`Reply`]. This request/replu pair is structured as an
/// [`Api`] trait provided in form of associated type parameter
pub trait Handler<Endpoints>
where
    Self: Sized,
    Endpoints: EndpointTypes,
{
    type Api: Api;
    type Error: crate::error::Error + Into<Failure>;

    /// Function that processes specific request and returns either response or
    /// a error that can be converted into a failure response
    fn handle(
        &mut self,
        endpoint: Endpoints,
        request: <Self::Api as Api>::Request,
    ) -> Result<<Self::Api as Api>::Reply, Self::Error>;
}

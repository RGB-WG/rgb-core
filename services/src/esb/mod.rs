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

mod controller;
pub use controller::{Controller, Handler, SenderList};

use std::fmt::{Debug, Display};
use std::hash::Hash;

use lnpbp::lnp::{presentation, transport, zmqsocket};

/// Marker traits for service bus identifiers
pub trait BusId: Copy + Eq + Hash + Display {}

pub struct BusConfig<A>
where
    A: ServiceAddress,
{
    pub carrier: zmqsocket::Carrier,
    pub router: Option<A>,
    /// Indicates whether the messages must be queued, or the send function
    /// must fail immediatelly if the remote point is not avaliable
    pub queued: bool,
}

impl<A> BusConfig<A>
where
    A: ServiceAddress,
{
    pub fn with_locator(
        locator: zmqsocket::SocketLocator,
        router: Option<A>,
    ) -> Self {
        Self {
            carrier: zmqsocket::Carrier::Locator(locator),
            router,
            queued: false,
        }
    }

    pub fn with_socket(socket: zmq::Socket, router: Option<A>) -> Self {
        Self {
            carrier: zmqsocket::Carrier::Socket(socket),
            router,
            queued: false,
        }
    }
}

/// Marker traits for service bus identifiers
pub trait ServiceAddress:
    Clone
    + Eq
    + Hash
    + Debug
    + Display
    + AsRef<[u8]>
    + Into<Vec<u8>>
    + From<Vec<u8>>
{
}

/// Errors happening with RPC APIs
#[derive(Clone, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum Error {
    /// unexpected server response
    UnexpectedServerResponse,

    /// message serialization or structure error: {_0}
    Presentation(presentation::Error),

    /// transport-level protocol error: {_0}
    #[from]
    Transport(transport::Error),

    /// provided service bus id {_0} is unknown
    UnknownBusId(String),

    /// {_0}
    ServiceError(String),
}

impl From<zmq::Error> for Error {
    fn from(err: zmq::Error) -> Self {
        Error::Transport(transport::Error::from(err))
    }
}

impl From<presentation::Error> for Error {
    fn from(err: presentation::Error) -> Self {
        match err {
            presentation::Error::Transport(err) => err.into(),
            err => Error::Presentation(err),
        }
    }
}

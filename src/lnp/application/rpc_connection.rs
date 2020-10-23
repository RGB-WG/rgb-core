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

use amplify::Bipolar;
use std::fmt::{Debug, Display};

use crate::lnp::presentation::{self, message};
use crate::lnp::session::{Decrypt, Encrypt, Session, ToNodeAddr, Transcode};
use crate::lnp::transport::{
    AsReceiver, AsSender, Connection, RecvFrame, SendFrame,
};

/// Marker trait for LNP RPC requests
pub trait Request:
    Debug + Display + message::TypedEnum + presentation::CreateUnmarshaller
{
}

/// Marker trait for LNP RPC replies
pub trait Reply:
    Debug + Display + message::TypedEnum + presentation::CreateUnmarshaller
{
}

/// RPC API pair, connecting [`Request`] type with [`Reply`]
pub trait Api {
    /// Requests supported by RPC API
    type Request: Request;

    /// Replies supported by RPC API
    type Reply: Reply;
}

pub struct RpcConnection<A, T, C>
where
    A: Api,
    T: Transcode,
    T::Left: Decrypt,
    T::Right: Encrypt,
    C: Connection + AsReceiver + AsSender + Bipolar,
    C::Left: RecvFrame,
    C::Right: SendFrame,
{
    api: A,
    session: Session<T, C>,
}

impl<A, T, C> RpcConnection<A, T, C>
where
    A: Api,
    T: Transcode,
    T::Left: Decrypt,
    T::Right: Encrypt,
    C: Connection + AsReceiver + AsSender + Bipolar,
    C::Left: RecvFrame,
    C::Right: SendFrame,
{
    pub fn new(remote: impl ToNodeAddr) -> Result<Self, presentation::Error> {
        unimplemented!()
    }
}

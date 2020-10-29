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

use std::collections::HashMap;

use lnpbp::lnp::presentation::Encode;
use lnpbp::lnp::rpc_connection::Api;
use lnpbp::lnp::transport::zmqsocket;
use lnpbp::lnp::{
    session, transport, CreateUnmarshaller, NoEncryption, Session, Unmarshall,
    Unmarshaller,
};

use super::{EndpointId, Error, Failure};
use crate::node::TryService;

/// Trait for types handling specific set of RPC API requests structured as a
/// single type implementing [`Request`]. They must return a corresponding reply
/// type implementing [`Reply`]. This request/replu pair is structured as an
/// [`Api`] trait provided in form of associated type parameter
pub trait Handler<E>
where
    Self: Sized,
    E: EndpointId,
{
    type Api: Api;
    type Error: crate::error::Error + Into<Failure>;

    /// Function that processes specific request and returns either response or
    /// a error that can be converted into a failure response
    fn handle(
        &mut self,
        endpoint: E,
        request: <Self::Api as Api>::Request,
    ) -> Result<<Self::Api as Api>::Reply, Self::Error>;

    fn handle_err(&mut self, error: Error) -> Result<(), Error>;
}

pub struct RpcServer<E, A, H>
where
    A: Api,
    H::Error: Into<Failure>,
    A::Reply: From<Failure>,
    E: EndpointId,
    H: Handler<E, Api = A>,
{
    sessions: HashMap<
        E,
        session::Raw<NoEncryption, transport::zmqsocket::Connection>,
    >,
    unmarshaller: Unmarshaller<A::Request>,
    handler: H,
}

impl<E, A, H> RpcServer<E, A, H>
where
    A: Api,
    H::Error: Into<Failure>,
    A::Reply: From<Failure>,
    E: EndpointId,
    H: Handler<E, Api = A>,
{
    pub fn with(
        endpoints: HashMap<E, zmqsocket::Carrier>,
        handler: H,
    ) -> Result<Self, transport::Error> {
        let mut sessions: HashMap<E, session::Raw<_, _>> = none!();
        for (endpoint, carrier) in endpoints {
            sessions.insert(
                endpoint,
                match carrier {
                    zmqsocket::Carrier::Locator(locator) => {
                        debug!(
                            "Creating RPC session for endpoint {} located at {}",
                            &endpoint,
                            &locator
                        );
                        session::Raw::with_zmq_unencrypted(
                            zmqsocket::ApiType::Server,
                            &locator,
                            None,
                            None,
                        )?
                    }
                    zmqsocket::Carrier::Socket(socket) => {
                        debug!(
                            "Creating RPC session for endpoint {}",
                            &endpoint
                        );
                        session::Raw::from_zmq_socket_unencrypted(
                            zmqsocket::ApiType::Server,
                            socket,
                        )
                    }
                },
            );
        }
        let unmarshaller = A::Request::create_unmarshaller();
        Ok(Self {
            sessions,
            unmarshaller,
            handler,
        })
    }
}

impl<E, A, H> TryService for RpcServer<E, A, H>
where
    A: Api,
    H::Error: Into<Failure>,
    A::Reply: From<Failure>,
    E: EndpointId,
    H: Handler<E, Api = A>,
{
    type ErrorType = Error;

    fn try_run_loop(mut self) -> Result<(), Self::ErrorType> {
        loop {
            match self.run() {
                Ok(_) => debug!("RPC request processing complete"),
                Err(err) => {
                    error!("RPC request processing error: {}", err);
                    self.handler.handle_err(err)?;
                }
            }
        }
    }
}

impl<E, A, H> RpcServer<E, A, H>
where
    A: Api,
    H::Error: Into<Failure>,
    A::Reply: From<Failure>,
    E: EndpointId,
    H: Handler<E, Api = A>,
{
    fn run(&mut self) -> Result<(), Error> {
        let mut index = vec![];
        let mut items = self
            .sessions
            .iter()
            .map(|(endpoint, session)| {
                index.push(endpoint);
                session.as_socket().as_poll_item(zmq::POLLIN | zmq::POLLERR)
            })
            .collect::<Vec<_>>();

        trace!("Awaiting for RPC request from {} endpoints...", items.len());
        let _ = zmq::poll(&mut items, -1)?;

        let endpoints = items
            .iter()
            .enumerate()
            .filter_map(|(i, item)| {
                if item.get_revents().is_empty() {
                    None
                } else {
                    Some(*index[i])
                }
            })
            .collect::<Vec<_>>();
        trace!("Received RPC request from {} endpoints...", endpoints.len());

        for endpoint in endpoints {
            let session = &mut self
                .sessions
                .get_mut(&endpoint)
                .expect("must exist, just indexed");

            let raw = session.recv_raw_message()?;
            let request = &*self.unmarshaller.unmarshall(&raw)?;

            debug!("RPC: got request {}", request);
            let reply = self
                .handler
                .handle(endpoint, request.clone())
                .unwrap_or_else(|err| A::Reply::from(err.into()));
            debug!("RPC: replying with {:?}", reply);
            let data = reply.encode()?;
            session.send_raw_message(&data)?;
        }

        Ok(())
    }
}

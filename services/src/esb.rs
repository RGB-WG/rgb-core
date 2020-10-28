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
use std::fmt::{Debug, Display};

use lnpbp::lnp::presentation::Encode;
use lnpbp::lnp::rpc_connection::Request;
use lnpbp::lnp::transport::zmqsocket;
use lnpbp::lnp::{session, transport, NoEncryption, Unmarshall, Unmarshaller};

#[cfg(feature = "node")]
use crate::node::TryService;
use crate::rpc;

/// Trait for types handling specific set of ESB RPC API requests structured as
/// a single type implementing [`Request`].
pub trait Handler<Endpoints>
where
    Self: Sized,
    Endpoints: rpc::EndpointTypes,
    rpc::Error: From<Self::Error>,
{
    type Request: Request;
    type Address: AsRef<[u8]> + From<Vec<u8>> + Display + Debug;
    type Error: std::error::Error;

    fn handle(
        &mut self,
        sessions: &mut Senders<Endpoints>,
        endpoint: Endpoints,
        addr: Self::Address,
        request: Self::Request,
    ) -> Result<(), Self::Error>;
}

pub struct Senders<E>(
    pub(self)  HashMap<
        E,
        session::Raw<NoEncryption, transport::zmqsocket::Connection>,
    >,
)
where
    E: rpc::EndpointTypes;

impl<E> Senders<E>
where
    E: rpc::EndpointTypes,
{
    pub fn send_to<A, R>(
        &mut self,
        endpoint: E,
        addr: A,
        request: R,
    ) -> Result<(), rpc::Error>
    where
        A: AsRef<[u8]> + From<Vec<u8>>,
        R: Request,
    {
        let data = request.encode()?;
        let session = self
            .0
            .get_mut(&endpoint)
            .ok_or(rpc::Error::UnknownEndpoint(endpoint.to_string()))?;
        Ok(session.send_addr_message(addr, data)?)
    }
}

pub struct Controller<E, R, H>
where
    R: Request,
    E: rpc::EndpointTypes,
    H: Handler<E, Request = R>,
    rpc::Error: From<H::Error>,
{
    sessions: Senders<E>,
    unmarshaller: Unmarshaller<R>,
    handler: H,
}

impl<E, R, H> Controller<E, R, H>
where
    R: Request,
    E: rpc::EndpointTypes,
    H: Handler<E, Request = R>,
    rpc::Error: From<H::Error>,
{
    pub fn init(
        identity: H::Address,
        endpoints: HashMap<E, rpc::EndpointCarrier>,
        handler: H,
        api_type: zmqsocket::ApiType,
    ) -> Result<Self, transport::Error> {
        let mut sessions: HashMap<E, session::Raw<_, _>> = none!();
        for (service, endpoint) in endpoints {
            let session = match endpoint {
                rpc::EndpointCarrier::Address(addr) => {
                    trace!(
                        "Creating session for {} endpoint at {} with identity '{}'",
                        &service,
                        &addr,
                        &identity
                    );
                    let session = session::Raw::with_zmq_unencrypted(
                        api_type,
                        &addr,
                        None,
                        Some(identity.as_ref()),
                    )?;
                    session.as_socket().set_router_mandatory(true)?;
                    trace!(
                        "ZMQ socket identity set to '{}'",
                        String::from_utf8_lossy(
                            &session.as_socket().get_identity()?
                        )
                    );
                    session
                }
                rpc::EndpointCarrier::Socket(socket) => {
                    trace!("Creating session for {} endpoint", &service,);
                    session::Raw::from_pair_socket(api_type, socket)
                }
            };
            sessions.insert(service, session);
        }
        let unmarshaller = R::create_unmarshaller();
        Ok(Self {
            sessions: Senders(sessions),
            unmarshaller,
            handler,
        })
    }

    pub fn send_to(
        &mut self,
        endpoint: E,
        addr: H::Address,
        request: R,
    ) -> Result<(), rpc::Error> {
        trace!(
            "Sending request {} to endpoint {}, target service identity '{}'",
            request,
            endpoint,
            addr
        );
        self.sessions.send_to(endpoint, addr, request)
    }
}

#[cfg(feature = "node")]
impl<E, R, H> TryService for Controller<E, R, H>
where
    R: Request,
    E: rpc::EndpointTypes,
    H: Handler<E, Request = R>,
    rpc::Error: From<H::Error>,
{
    type ErrorType = rpc::Error;

    fn try_run_loop(mut self) -> Result<(), Self::ErrorType> {
        loop {
            match self.run() {
                Ok(_) => debug!("ESB request processing complete"),
                Err(err) => {
                    error!("Error processing ESB request: {}", err);
                    Err(err)?;
                }
            }
        }
    }
}

impl<E, R, H> Controller<E, R, H>
where
    R: Request,
    E: rpc::EndpointTypes,
    H: Handler<E, Request = R>,
    rpc::Error: From<H::Error>,
{
    fn run(&mut self) -> Result<(), rpc::Error> {
        let mut index = vec![];
        let mut items = self
            .sessions
            .0
            .iter()
            .map(|(endpoint, session)| {
                index.push(endpoint);
                session.as_socket().as_poll_item(zmq::POLLIN | zmq::POLLERR)
            })
            .collect::<Vec<_>>();

        trace!("Awaiting for ESB RPC request in {} sockets...", items.len());
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
        trace!("Received request from {} sockets...", endpoints.len());

        for endpoint in endpoints {
            let session = self
                .sessions
                .0
                .get_mut(&endpoint)
                .expect("must exist, just indexed");

            let (addr, raw) = session.recv_addr_message()?;
            trace!("Got {} bytes over ESB RPC from {}", raw.len(), endpoint);

            let request = &*self.unmarshaller.unmarshall(&raw)?;
            debug!(
                "Unmarshalled ESB RPC request {:?}, processing ...",
                request.get_type()
            );

            self.handler.handle(
                &mut self.sessions,
                endpoint,
                H::Address::from(addr),
                request.clone(),
            )?;
        }

        Ok(())
    }
}

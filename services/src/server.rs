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
use lnpbp::lnp::transport::zmqsocket::{ApiType, SocketLocator};
use lnpbp::lnp::{
    session, transport, CreateUnmarshaller, NoEncryption, Session, TypedEnum,
    Unmarshall, Unmarshaller,
};

use crate::node::TryService;
use crate::rpc;

pub enum EndpointCarrier {
    Address(SocketLocator),
    Socket(zmq::Socket),
}

pub struct RpcZmqServer<E, A, H>
where
    A: Api,
    H::Error: Into<rpc::Failure>,
    A::Reply: From<rpc::Failure>,
    E: rpc::EndpointTypes,
    H: rpc::Handler<E, Api = A>,
{
    sessions: HashMap<
        E,
        session::Raw<NoEncryption, transport::zmqsocket::Connection>,
    >,
    unmarshaller: Unmarshaller<A::Request>,
    handler: H,
}

impl<E, A, H> RpcZmqServer<E, A, H>
where
    A: Api,
    H::Error: Into<rpc::Failure>,
    A::Reply: From<rpc::Failure>,
    E: rpc::EndpointTypes,
    H: rpc::Handler<E, Api = A>,
{
    pub fn init(
        endpoints: HashMap<E, EndpointCarrier>,
        handler: H,
    ) -> Result<Self, transport::Error> {
        let mut sessions: HashMap<E, session::Raw<_, _>> = none!();
        for (service, endpoint) in endpoints {
            sessions.insert(
                service,
                match endpoint {
                    EndpointCarrier::Address(addr) => {
                        session::Raw::with_zmq_unencrypted(
                            ApiType::Server,
                            &addr,
                            None,
                        )?
                    }
                    EndpointCarrier::Socket(socket) => {
                        session::Raw::from_pair_socket(socket)
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

impl<E, A, H> TryService for RpcZmqServer<E, A, H>
where
    A: Api,
    H::Error: Into<rpc::Failure>,
    A::Reply: From<rpc::Failure>,
    E: rpc::EndpointTypes,
    H: rpc::Handler<E, Api = A>,
{
    type ErrorType = rpc::Error;

    fn try_run_loop(mut self) -> Result<(), Self::ErrorType> {
        loop {
            match self.run() {
                Ok(_) => debug!("API request processing complete"),
                Err(err) => {
                    error!("Error processing API request: {}", err);
                    Err(err)?;
                }
            }
        }
    }
}

impl<E, A, H> RpcZmqServer<E, A, H>
where
    A: Api,
    H::Error: Into<rpc::Failure>,
    A::Reply: From<rpc::Failure>,
    E: rpc::EndpointTypes,
    H: rpc::Handler<E, Api = A>,
{
    fn run(&mut self) -> Result<(), rpc::Error> {
        let mut index = vec![];
        let mut items = self
            .sessions
            .iter()
            .map(|(endpoint, session)| {
                index.push(endpoint);
                session.as_socket().as_poll_item(zmq::POLLIN | zmq::POLLERR)
            })
            .collect::<Vec<_>>();

        trace!("Awaiting for ZMQ RPC request in {} sockets...", items.len());
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
            let session = &mut self
                .sessions
                .get_mut(&endpoint)
                .expect("must exist, just indexed");

            let raw = session.recv_raw_message()?;
            trace!("Got {} bytes over ZMQ RPC from {}", raw.len(), endpoint);

            let request = &*self.unmarshaller.unmarshall(&raw)?;
            debug!(
                "Unmarshalled ZMQ RPC request {:?}, processing ...",
                request.get_type()
            );

            let reply = self
                .handler
                .handle(endpoint, request.clone())
                .unwrap_or_else(|err| A::Reply::from(err.into()));
            trace!("Preparing ZMQ RPC reply: {:?}", reply);
            let data = reply.encode()?;
            session.send_raw_message(&data)?;
        }

        Ok(())
    }
}

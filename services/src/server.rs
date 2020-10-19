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
use lnpbp::lnp::transport::zmqsocket::{ApiType, SocketLocator};
use lnpbp::lnp::{
    transport, CreateUnmarshaller, NoEncryption, Session, TypedEnum,
    Unmarshall, Unmarshaller,
};

use crate::node::TryService;
use crate::rpc;

pub struct RpcServer<Endpoints, Api, Handler>
where
    Api: rpc::Api,
    <Api as rpc::Api>::Reply: From<Handler::Error>,
    Endpoints: rpc::EndpointTypes,
    Handler: rpc::Handler<Endpoints, Api = Api>,
{
    sessions: HashMap<
        Endpoints,
        Session<NoEncryption, transport::zmqsocket::Connection>,
    >,
    unmarshaller: Unmarshaller<Api::Request>,
    handler: Handler,
}

impl<Endpoints, Api, Handler> RpcServer<Endpoints, Api, Handler>
where
    Api: rpc::Api,
    <Api as rpc::Api>::Reply: From<Handler::Error>,
    Endpoints: rpc::EndpointTypes,
    Handler: rpc::Handler<Endpoints, Api = Api>,
{
    pub fn init(
        endpoints: HashMap<Endpoints, SocketLocator>,
        context: &zmq::Context,
        handler: Handler,
    ) -> Result<Self, transport::Error> {
        let mut sessions: HashMap<Endpoints, Session<_, _>> = none!();
        for (service, endpoint) in endpoints {
            sessions.insert(
                service,
                Session::new_zmq_unencrypted(
                    ApiType::Server,
                    &context,
                    endpoint,
                    None,
                )?,
            );
        }
        let unmarshaller = Api::Request::create_unmarshaller();
        Ok(Self {
            sessions,
            unmarshaller,
            handler,
        })
    }
}

impl<Endpoints, Api, Handler> TryService for RpcServer<Endpoints, Api, Handler>
where
    Api: rpc::Api,
    <Api as rpc::Api>::Reply: From<Handler::Error>,
    Endpoints: rpc::EndpointTypes,
    Handler: rpc::Handler<Endpoints, Api = Api>,
{
    type ErrorType = rpc::Error;

    fn try_run_loop(mut self) -> Result<!, Self::ErrorType> {
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

impl<Endpoints, Api, Handler> RpcServer<Endpoints, Api, Handler>
where
    Api: rpc::Api,
    <Api as rpc::Api>::Reply: From<Handler::Error>,
    Endpoints: rpc::EndpointTypes,
    Handler: rpc::Handler<Endpoints, Api = Api>,
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
                .unwrap_or_else(Into::into);
            trace!("Preparing ZMQ RPC reply: {:?}", reply);
            let data = reply.encode()?;
            session.send_raw_message(data)?;
        }

        Ok(())
    }
}

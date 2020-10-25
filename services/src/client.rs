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
    session, transport, CreateUnmarshaller, NoEncryption, Session, Unmarshall,
    Unmarshaller,
};

use crate::rpc;

pub struct RpcClient<E, A>
where
    A: Api,
    E: rpc::EndpointTypes,
{
    sessions: HashMap<
        E,
        session::Raw<NoEncryption, transport::zmqsocket::Connection>,
    >,
    unmarshaller: Unmarshaller<A::Reply>,
}

impl<E, A> RpcClient<E, A>
where
    A: Api,
    E: rpc::EndpointTypes,
{
    pub fn init(
        endpoints: HashMap<E, SocketLocator>,
    ) -> Result<Self, transport::Error> {
        let mut sessions: HashMap<E, session::Raw<_, _>> = none!();
        for (service, endpoint) in endpoints {
            sessions.insert(
                service,
                session::Raw::with_zmq_unencrypted(
                    ApiType::Client,
                    &endpoint,
                    None,
                )?,
            );
        }
        let unmarshaller = A::Reply::create_unmarshaller();
        Ok(Self {
            sessions,
            unmarshaller,
        })
    }

    pub fn request(
        &mut self,
        endpoint: E,
        request: A::Request,
    ) -> Result<A::Reply, rpc::Error> {
        let data = request.encode()?;
        let session = self
            .sessions
            .get_mut(&endpoint)
            .ok_or(rpc::Error::UnknownEndpoint(endpoint.to_string()))?;
        session.send_raw_message(&data)?;
        let raw = session.recv_raw_message()?;
        let reply = self.unmarshaller.unmarshall(&raw)?;
        Ok((&*reply).clone())
    }
}

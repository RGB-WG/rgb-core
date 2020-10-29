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
use lnpbp::lnp::rpc_connection::Request;
use lnpbp::lnp::transport::zmqsocket;
use lnpbp::lnp::{session, NoEncryption, Session, Unmarshall, Unmarshaller};

use super::{BusId, Error, ServiceAddress};
use crate::esb::BusConfig;
#[cfg(feature = "node")]
use crate::node::TryService;

/// Trait for types handling specific set of ESB RPC API requests structured as
/// a single type implementing [`Request`].
pub trait Handler<B>
where
    Self: Sized,
    B: BusId,
    Error: From<Self::Error>,
{
    type Request: Request;
    type Address: ServiceAddress;
    type Error: std::error::Error;

    fn identity(&self) -> Self::Address;

    fn handle(
        &mut self,
        senders: &mut SenderList<B, Self::Address>,
        bus_id: B,
        source: Self::Address,
        request: Self::Request,
    ) -> Result<(), Self::Error>;

    fn handle_err(&mut self, error: Error) -> Result<(), Error>;
}

struct Sender<A>
where
    A: ServiceAddress,
{
    pub(self) session: session::Raw<NoEncryption, zmqsocket::Connection>,
    pub(self) router: Option<A>,
}

impl<A> Sender<A>
where
    A: ServiceAddress,
{
    pub(self) fn send_to<R>(
        &mut self,
        source: A,
        dest: A,
        request: R,
    ) -> Result<(), Error>
    where
        R: Request,
    {
        let data = request.encode()?;
        let router = match self.router {
            None => {
                trace!(
                    "Routing: sending {} from {} to {} directly",
                    request,
                    source,
                    dest,
                );
                &dest
            }
            Some(ref router) if &source == router => {
                trace!(
                    "Routing: sending {} from {} to {}",
                    request,
                    source,
                    dest,
                );
                &dest
            }
            Some(ref router) => {
                trace!(
                    "Routing: sending {} from {} to {} via {}",
                    request,
                    source,
                    dest,
                    router,
                );
                router
            }
        };
        self.session.send_routed_message(
            source.as_ref(),
            router.as_ref(),
            dest.as_ref(),
            &data,
        )?;
        Ok(())
    }
}

pub struct SenderList<B, A>(pub(self) HashMap<B, Sender<A>>)
where
    B: BusId,
    A: ServiceAddress;

impl<B, A> SenderList<B, A>
where
    B: BusId,
    A: ServiceAddress,
{
    pub fn new() -> Self {
        Self(Default::default())
    }

    pub fn send_to<R>(
        &mut self,
        bus_id: B,
        source: A,
        dest: A,
        request: R,
    ) -> Result<(), Error>
    where
        R: Request,
    {
        let session = self
            .0
            .get_mut(&bus_id)
            .ok_or(Error::UnknownBusId(bus_id.to_string()))?;
        session.send_to(source, dest, request)
    }
}

#[derive(Getters)]
pub struct Controller<B, R, H>
where
    R: Request,
    B: BusId,
    H: Handler<B, Request = R>,
    Error: From<H::Error>,
{
    senders: SenderList<B, H::Address>,
    unmarshaller: Unmarshaller<R>,
    handler: H,
    api_type: zmqsocket::ApiType,
}

impl<B, R, H> Controller<B, R, H>
where
    R: Request,
    B: BusId,
    H: Handler<B, Request = R>,
    Error: From<H::Error>,
{
    pub fn with(
        service_bus: HashMap<B, BusConfig<H::Address>>,
        handler: H,
        api_type: zmqsocket::ApiType,
    ) -> Result<Self, Error> {
        let senders = SenderList::new();
        let unmarshaller = R::create_unmarshaller();
        let mut me = Self {
            senders,
            unmarshaller,
            handler,
            api_type,
        };
        for (id, config) in service_bus {
            me.add_service_bus(id, config)?;
        }
        Ok(me)
    }

    pub fn add_service_bus(
        &mut self,
        id: B,
        config: BusConfig<H::Address>,
    ) -> Result<(), Error> {
        let session = match config.carrier {
            zmqsocket::Carrier::Locator(locator) => {
                debug!(
                    "Creating ESB session for service {} located at {} with identity '{}'",
                    &id,
                    &locator,
                    self.handler.identity()
                );
                let session = session::Raw::with_zmq_unencrypted(
                    self.api_type,
                    &locator,
                    None,
                    Some(self.handler.identity().as_ref()),
                )?;
                session
            }
            zmqsocket::Carrier::Socket(socket) => {
                debug!("Creating ESB session for service {}", &id);
                session::Raw::from_zmq_socket_unencrypted(self.api_type, socket)
            }
        };
        if !config.queued {
            session.as_socket().set_router_mandatory(true)?;
        }
        let router = match config.router {
            Some(router) if router == self.handler.identity() => None,
            router => router,
        };
        self.senders.0.insert(id, Sender { session, router });
        Ok(())
    }

    pub fn send_to(
        &mut self,
        bus_id: B,
        dest: H::Address,
        request: R,
    ) -> Result<(), Error> {
        self.senders
            .send_to(bus_id, self.handler.identity(), dest, request)
    }
}

#[cfg(feature = "node")]
impl<B, R, H> TryService for Controller<B, R, H>
where
    R: Request,
    B: BusId,
    H: Handler<B, Request = R>,
    Error: From<H::Error>,
{
    type ErrorType = Error;

    fn try_run_loop(mut self) -> Result<(), Self::ErrorType> {
        loop {
            match self.run() {
                Ok(_) => debug!("ESB request processing complete"),
                Err(err) => {
                    error!("ESB request processing error: {}", err);
                    self.handler.handle_err(err)?;
                }
            }
        }
    }
}

impl<B, R, H> Controller<B, R, H>
where
    R: Request,
    B: BusId,
    H: Handler<B, Request = R>,
    Error: From<H::Error>,
{
    fn run(&mut self) -> Result<(), Error> {
        let mut index = vec![];
        let mut items = self
            .senders
            .0
            .iter()
            .map(|(service, sender)| {
                index.push(service);
                sender
                    .session
                    .as_socket()
                    .as_poll_item(zmq::POLLIN | zmq::POLLERR)
            })
            .collect::<Vec<_>>();

        trace!(
            "Awaiting for ESB request from {} service buses...",
            items.len()
        );
        let _ = zmq::poll(&mut items, -1)?;

        let service_buses = items
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
        trace!(
            "Received ESB request from {} service busses...",
            service_buses.len()
        );

        for bus_id in service_buses {
            let sender = self
                .senders
                .0
                .get_mut(&bus_id)
                .expect("must exist, just indexed");

            let routed_frame = sender.session.recv_routed_message()?;
            let request =
                (&*self.unmarshaller.unmarshall(&routed_frame.msg)?).clone();
            let source = H::Address::from(routed_frame.src);
            let dest = H::Address::from(routed_frame.dst);

            if dest == self.handler.identity() {
                // We are the destination
                debug!(
                    "ESB request {} from {} forwarded to processing",
                    request, source
                );

                self.handler.handle(
                    &mut self.senders,
                    bus_id,
                    source,
                    request,
                )?;
            } else {
                // Need to route
                debug!(
                    "ESB request {} will be routed from {} to {}",
                    request, source, dest
                );

                self.senders.send_to(bus_id, source, dest, request)?
            }
        }

        Ok(())
    }
}

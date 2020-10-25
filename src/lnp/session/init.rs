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

use crate::lnp::transport::Error;
use crate::lnp::{
    session, zmqsocket, LocalAddr, LocalNode, NodeAddr, NodeEndpoint,
    RemoteAddr, Session,
};

pub trait Connect {
    fn connect(&self, node: &LocalNode) -> Result<Box<dyn Session>, Error>;
}

pub trait Accept {
    fn accept(&self, node: &LocalNode) -> Result<Box<dyn Session>, Error>;
}

impl Connect for LocalAddr {
    fn connect(&self, local: &LocalNode) -> Result<Box<dyn Session>, Error> {
        Ok(Box::new(match self {
            LocalAddr::Zmq(locator) => session::Raw::with_zmq_unencrypted(
                zmqsocket::ApiType::Client,
                locator,
                None,
            )?,
            LocalAddr::Posix(_) => unimplemented!(),
        }))
    }
}

impl Accept for LocalAddr {
    fn accept(&self, local: &LocalNode) -> Result<Box<dyn Session>, Error> {
        Ok(Box::new(match self {
            LocalAddr::Zmq(locator) => session::Raw::with_zmq_unencrypted(
                zmqsocket::ApiType::Client,
                locator,
                None,
            )?,
            LocalAddr::Posix(_) => unimplemented!(),
        }))
    }
}

impl Connect for NodeAddr {
    fn connect(&self, local: &LocalNode) -> Result<Box<dyn Session>, Error> {
        Ok(match self.remote_addr {
            RemoteAddr::Ftcp(inet) => {
                Box::new(session::Raw::connect_ftcp_unencrypted(inet)?)
                    as Box<dyn Session>
            }
            RemoteAddr::Posix(_) => unimplemented!(),
            #[cfg(feature = "zmq")]
            // TODO: (v0.3) pass specific ZMQ API type using additional
            //       `RemoteAddr` field
            RemoteAddr::Zmq(socket) => {
                Box::new(session::Raw::with_zmq_unencrypted(
                    zmqsocket::ApiType::Client,
                    &zmqsocket::SocketLocator::Tcp(socket),
                    None,
                )?)
            }
            RemoteAddr::Http(_) => unimplemented!(),
            #[cfg(feature = "websocket")]
            RemoteAddr::Websocket(_) => unimplemented!(),
            RemoteAddr::Smtp(_) => unimplemented!(),
        })
    }
}

impl Accept for NodeAddr {
    fn accept(&self, local: &LocalNode) -> Result<Box<dyn Session>, Error> {
        Ok(match self.remote_addr {
            RemoteAddr::Ftcp(inet) => {
                Box::new(session::Raw::accept_ftcp_unencrypted(inet)?)
                    as Box<dyn Session>
            }
            RemoteAddr::Posix(_) => unimplemented!(),
            #[cfg(feature = "zmq")]
            // TODO: (v0.3) pass specific ZMQ API type using additional
            //       `RemoteAddr` field
            RemoteAddr::Zmq(socket) => {
                Box::new(session::Raw::with_zmq_unencrypted(
                    zmqsocket::ApiType::Client,
                    &zmqsocket::SocketLocator::Tcp(socket),
                    None,
                )?)
            }
            RemoteAddr::Http(_) => unimplemented!(),
            #[cfg(feature = "websocket")]
            RemoteAddr::Websocket(_) => unimplemented!(),
            RemoteAddr::Smtp(_) => unimplemented!(),
        })
    }
}

impl Connect for NodeEndpoint {
    fn connect(&self, local: &LocalNode) -> Result<Box<dyn Session>, Error> {
        match self {
            NodeEndpoint::Local(addr) => addr.connect(local),
            NodeEndpoint::Remote(addr) => addr.connect(local),
        }
    }
}

impl Accept for NodeEndpoint {
    fn accept(&self, local: &LocalNode) -> Result<Box<dyn Session>, Error> {
        match self {
            NodeEndpoint::Local(addr) => addr.accept(local),
            NodeEndpoint::Remote(addr) => addr.accept(local),
        }
    }
}

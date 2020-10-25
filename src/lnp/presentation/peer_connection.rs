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

//! BOLT-1. Manages state of the remote peer and handles direct communications
//! with it. Relies on transport layer (BOLT-8-based) protocol.

use amplify::Bipolar;
use std::sync::Arc;
#[cfg(not(feature = "tokio"))]
use std::sync::Mutex;
#[cfg(feature = "tokio")]
use tokio::sync::Mutex;

use super::{Error, Payload};
use crate::lnp::session::{
    self, Accept, Connect, LocalNode, NoEncryption, NodeEndpoint, Session,
    Split, ToNodeEndpoint,
};
use crate::lnp::transport::{ftcp, zmqsocket};
use crate::lnp::LIGHTNING_P2P_DEFAULT_PORT;

pub struct PeerConnection {
    remote_peer: NodeEndpoint,
    awaiting_pong: bool,
    session: Box<dyn Session>,
}

pub struct PeerReceiver {
    remote_peer: NodeEndpoint,
    awaiting_pong: Arc<Mutex<bool>>,
    //#[cfg(not(feature = "async"))]
    receiver: Box<dyn session::Input>,
    /* #[cfg(feature = "async")]
     * receiver: Box<dyn AsyncRecvFrame>, */
}

pub struct PeerSender {
    remote_peer: NodeEndpoint,
    awaiting_pong: Arc<Mutex<bool>>,
    //#[cfg(not(feature = "async"))]
    sender: Box<dyn session::Output>,
    /* #[cfg(feature = "async")]
     * sender: Box<dyn AsyncSendFrame>, */
}

impl PeerConnection {
    pub fn with(
        session: impl Session + 'static,
        remote_peer: NodeEndpoint,
    ) -> Self {
        Self {
            remote_peer,
            awaiting_pong: false,
            session: Box::new(session),
        }
    }

    pub fn connect(
        remote: impl ToNodeEndpoint,
        local: &LocalNode,
    ) -> Result<Self, Error> {
        let endpoint = remote
            .to_node_endpoint(LIGHTNING_P2P_DEFAULT_PORT)
            .ok_or(Error::InvalidEndpoint)?;
        let session = endpoint.connect(local)?;
        Ok(Self {
            remote_peer: endpoint,
            session,
            awaiting_pong: false,
        })
    }

    pub fn accept(
        remote: impl ToNodeEndpoint,
        local: &LocalNode,
    ) -> Result<Self, Error> {
        let endpoint = remote
            .to_node_endpoint(LIGHTNING_P2P_DEFAULT_PORT)
            .ok_or(Error::InvalidEndpoint)?;
        let session = endpoint.accept(local)?;
        Ok(Self {
            remote_peer: endpoint,
            session,
            awaiting_pong: false,
        })
    }

    pub fn send(&self, msg: Payload) -> Result<(), Error> {
        unimplemented!()
    }
}

impl Bipolar for PeerConnection {
    type Left = PeerReceiver;
    type Right = PeerSender;

    fn join(left: Self::Left, right: Self::Right) -> Self {
        unimplemented!()
    }

    fn split(self) -> (Self::Left, Self::Right) {
        let session = self.session.into_any();
        let (input, output) = if let Some(_) = session
            .downcast_ref::<session::Raw<NoEncryption, ftcp::Connection>>()
        {
            let session = session
                .downcast::<session::Raw<NoEncryption, ftcp::Connection>>()
                .expect(
                    "Must not fail; we just ensured that with downcast_ref",
                );
            (*session).split()
        } else if let Some(_) = session
            .downcast_ref::<session::Raw<NoEncryption, zmqsocket::Connection>>()
        {
            let session = session
                .downcast::<session::Raw<NoEncryption, ftcp::Connection>>()
                .expect(
                    "Must not fail; we just ensured that with downcast_ref",
                );
            (*session).split()
        } else {
            panic!("Impossible to split this type of Session")
        };
        let awaiting_pong = Arc::new(Mutex::new(self.awaiting_pong));
        (
            PeerReceiver {
                remote_peer: self.remote_peer.clone(),
                receiver: input,
                awaiting_pong: awaiting_pong.clone(),
            },
            PeerSender {
                remote_peer: self.remote_peer.clone(),
                sender: output,
                awaiting_pong,
            },
        )
    }
}

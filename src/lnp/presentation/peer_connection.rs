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
use crate::lnp::session::{Connect, LocalNode, NodeEndpoint, ToNodeEndpoint};
use crate::lnp::transport::Duplex;
//#[cfg(feature = "async")]
//use crate::lnp::transport::{AsyncRecvFrame, AsyncSendFrame};
//#[cfg(not(feature = "async"))]
use crate::lnp::transport::{RecvFrame, SendFrame};
use crate::lnp::LIGHTNING_P2P_DEFAULT_PORT;

pub struct PeerConnection {
    remote_peer: NodeEndpoint,
    awaiting_pong: bool,
    session: Box<dyn Duplex>,
}

pub struct PeerReceiver {
    remote_peer: NodeEndpoint,
    awaiting_pong: Arc<Mutex<bool>>,
    //#[cfg(not(feature = "async"))]
    receiver: Box<dyn RecvFrame>,
    /* #[cfg(feature = "async")]
     * receiver: Box<dyn AsyncRecvFrame>, */
}

pub struct PeerSender {
    remote_peer: NodeEndpoint,
    awaiting_pong: Arc<Mutex<bool>>,
    //#[cfg(not(feature = "async"))]
    sender: Box<dyn SendFrame>,
    /* #[cfg(feature = "async")]
     * sender: Box<dyn AsyncSendFrame>, */
}

impl PeerConnection {
    pub async fn with(
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

    pub async fn send(&self, msg: Payload) -> Result<(), Error> {
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
        unimplemented!()
        /*
        let session = self.session.as_mut();
        let (input, output) = session.dyn_split();
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
         */
    }
}

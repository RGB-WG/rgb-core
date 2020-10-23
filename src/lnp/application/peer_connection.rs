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

use std::sync::Arc;
#[cfg(not(feature = "tokio"))]
use std::sync::Mutex;
#[cfg(feature = "tokio")]
use tokio::sync::Mutex;

use crate::lnp::presentation::Message;
use crate::lnp::session::{
    Connection, ConnectionError, ConnectionInput, ConnectionOutput, LocalNode,
    NodeAddr, ToNodeEndpoint,
};

pub struct PeerConnection {
    pub remote_peer: NodeAddr,
    connection: Connection,
    awaiting_pong: bool,
}

pub struct PeerConnectionInput {
    pub remote_peer: NodeAddr,
    pub connection: ConnectionInput,
    awaiting_pong: Arc<Mutex<bool>>,
}

pub struct PeerConnectionOutput {
    pub remote_peer: NodeAddr,
    pub connection: ConnectionOutput,
    awaiting_pong: Arc<Mutex<bool>>,
}

impl PeerConnection {
    pub async fn new_outbound(
        remote: impl ToNodeEndpoint,
        local: LocalNode,
    ) -> Result<Self, ConnectionError> {
        unimplemented!()
        /*let connection =
            node.connect(private_key, ephemeral_private_key).await?;
        Ok(Self {
            remote_peer: node,
            connection,
            awaiting_pong: false,
        })*/
    }

    pub async fn send(
        &self,
        _msg: &dyn Message,
    ) -> Result<(), ConnectionError> {
        // TODO: Implement
        Ok(())
    }

    pub fn split(self) -> (PeerConnectionInput, PeerConnectionOutput) {
        let (input, output) = self.connection.split();
        let awaiting_pong = Arc::new(Mutex::new(self.awaiting_pong));
        (
            PeerConnectionInput {
                remote_peer: self.remote_peer.clone(),
                connection: input,
                awaiting_pong: awaiting_pong.clone(),
            },
            PeerConnectionOutput {
                remote_peer: self.remote_peer,
                connection: output,
                awaiting_pong,
            },
        )
    }
}

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

use bitcoin::secp256k1;
#[cfg(feature = "tokio")]
use std::sync::Arc;
#[cfg(feature = "tokio")]
use tokio::sync::Mutex;

use crate::lnp::presentation::Message;
use crate::lnp::session::{Connection, ConnectionError, NodeAddr};
#[cfg(feature = "tokio")]
use crate::lnp::session::{ConnectionInput, ConnectionOutput};

pub struct Peer {
    pub node: NodeAddr,
    #[allow(dead_code)]
    connection: Connection,
    awaiting_pong: bool,
}

#[cfg(feature = "tokio")]
pub struct PeerInput {
    pub node: NodeAddr,
    pub connection: ConnectionInput,
    awaiting_pong: Arc<Mutex<bool>>,
}

#[cfg(feature = "tokio")]
pub struct PeerOutput {
    pub node: NodeAddr,
    pub connection: ConnectionOutput,
    awaiting_pong: Arc<Mutex<bool>>,
}

impl Peer {
    pub async fn new_outbound(
        node: NodeAddr,
        private_key: &secp256k1::SecretKey,
        ephemeral_private_key: &secp256k1::SecretKey,
    ) -> Result<Self, ConnectionError> {
        let connection = node.connect(private_key, ephemeral_private_key).await?;
        Ok(Self {
            node,
            connection,
            awaiting_pong: false,
        })
    }

    pub async fn send(&self, _msg: &dyn Message) -> Result<(), ConnectionError> {
        // TODO: Implement
        Ok(())
    }

    #[cfg(feature = "tokio")]
    pub fn split(self) -> (PeerInput, PeerOutput) {
        let (input, output) = self.connection.split();
        let awaiting_pong = Arc::new(Mutex::new(self.awaiting_pong));
        (
            PeerInput {
                node: self.node.clone(),
                connection: input,
                awaiting_pong: awaiting_pong.clone(),
            },
            PeerOutput {
                node: self.node,
                connection: output,
                awaiting_pong,
            },
        )
    }
}

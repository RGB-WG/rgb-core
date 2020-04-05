// LNP/BP Rust Library
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

use lightning::secp256k1;

use super::transport::*;


pub struct Peer {
    pub node: Node,
    connection: Connection,
    awaiting_pong: bool,
}

impl Peer {
    pub async fn new_outbound(node: Node,
                              private_key: &secp256k1::SecretKey,
                              ephemeral_private_key: &secp256k1::SecretKey
    ) -> Result<Self, ConnectionError> {
        let connection = node.connect(private_key, ephemeral_private_key).await?;
        Ok(Self {
            node,
            connection,
            awaiting_pong: false,
        })
    }

    pub async fn send(&self, msg: Message) -> Result<(), ConnectionError> {
        // TODO: Implement
        Ok(())
    }
}

pub struct TLV();

pub struct MessageType(pub u16);

/// Generic LNP message as defined in BOLT-1
pub struct Message {
    pub type_id: MessageType,
    pub payload: Vec<u8>,
    pub extension: TLV,
}

pub trait Messageable: From<Message> + Into<Message> {

}

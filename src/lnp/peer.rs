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

///! Abstracting LN peer concept

use lightning::secp256k1;

use super::transport::*;

/// The structure holds the state of communications with particular peer
pub struct Peer {
    pub node_id: Node,
    pub connections: Vec<Connection>,
}

impl Peer {
    /// Just registers new peer, without connecting to it. The peer will
    /// have an empty list of active connections. It is the necessary step
    /// before creating a connection to the peer.
    pub fn new(node_id: Node) -> Self {
        Self {
            node_id,
            connections: vec![]
        }
    }

    /// Creates a new outbound connection to the peer.
    pub fn connect(&mut self,
                   ephemeral_key: secp256k1::SecretKey
    ) -> Result<Connection, ConnectionError> {
        Connection::new(self, ephemeral_key)
    }
}

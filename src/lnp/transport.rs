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

///! BOLT-8 related structures and functions covering Lightning network
///! transport layer

use std::io;
use std::net::SocketAddr;
use std::convert::TryInto;
#[cfg(feature="use-tokio")]
use tokio::net::TcpStream;
#[cfg(not(feature="use-tokio"))]
use std::net::TcpStream;
use lightning::secp256k1;

// We re-export this under more proper name (it's not per-channel encryptor,
// it is per-connection transport-level encryptor)
use lightning::ln::peer_channel_encryptor::PeerChannelEncryptor as Encryptor;

use crate::common::internet;

/*
pub use lightning::ln::{
    peer_handler::SocketDescriptor,
    peer_handler::Peer,
}
*/

#[derive(Clone, Copy, Debug, Display)]
#[display_from(Debug)]
pub struct Node {
    pub id: secp256k1::PublicKey,
    pub socket_address: internet::SocketAddress,
}


#[derive(Debug, Display)]
#[display_from(Debug)]
pub enum ConnectionError {
    TorNotYetSupported,
    IoError(io::Error)
}

impl From<io::Error> for ConnectionError {
    fn from(err: io::Error) -> Self {
        ConnectionError::IoError(err)
    }
}


pub struct Connection {
    pub peer_node: Node,
    pub socket: TcpStream,
    pub outbound: bool,
    encryptor: Encryptor,
    awaiting_pong: bool,
}

impl Connection {
    pub async fn new(node: Node,
               ephemeral_key: secp256k1::SecretKey) -> Result<Self, ConnectionError> {

        // TODO: Add support for Tor connections
        if node.socket_address.address.is_tor() {
            Err(ConnectionError::TorNotYetSupported)?
        }

        #[cfg(feature="use-tor")]
        let saddr: SocketAddr = node.socket_address.try_into().unwrap();
        #[cfg(not(feature="use-tor"))]
        let saddr: SocketAddr = node.socket_address.into();

        let socket = TcpStream::connect(saddr).await?;

        Ok(Self {
            peer_node: node,
            socket,
            outbound: true,
            encryptor: Encryptor::new_outbound(node.id, ephemeral_key),
            awaiting_pong: false
        })
    }
}

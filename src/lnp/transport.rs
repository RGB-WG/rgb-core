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

//! BOLT-8 related structures and functions covering Lightning network
//! transport layer

use std::io;
use std::str::FromStr;
use std::net::SocketAddr;
use std::convert::TryInto;

#[cfg(feature="use-tokio")]
use tokio::net::TcpStream;
#[cfg(feature="use-tokio")]
use tokio::io::AsyncWriteExt;
#[cfg(feature="use-tokio")]
use tokio::io::AsyncReadExt;

#[cfg(not(feature="use-tokio"))]
use std::net::TcpStream;
#[cfg(not(feature="use-tokio"))]
use std::io::AsyncWriteExt;
#[cfg(not(feature="use-tokio"))]
use std::io::AsyncReadExt;

use lightning::secp256k1;

// We re-export this under more proper name (it's not per-channel encryptor,
// it is per-connection transport-level encryptor)
use lightning::ln::peers::conduit::Conduit as Encryptor;
use lightning::ln::peers::handshake::PeerHandshake;

use crate::common::internet;
use super::LIGHTNING_P2P_DEFAULT_PORT;
use crate::common::internet::InetSocketAddr;


pub const MAX_TRANSPORT_FRAME_SIZE: usize = 65569;

#[derive(Clone, Copy, Debug, Display)]
#[display_from(Debug)]
pub struct NodeAddr {
    pub node_id: secp256k1::PublicKey,
    pub inet_addr: internet::InetSocketAddr,
}

impl NodeAddr {
    pub async fn connect(&self,
                   private_key: &secp256k1::SecretKey,
                   ephemeral_private_key: &secp256k1::SecretKey
    ) -> Result<Connection, ConnectionError> {
        Connection::new(self, private_key, ephemeral_private_key).await
    }
}

impl FromStr for NodeAddr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err_msg = "Wrong LN peer id; it must be in format \
                            `<node_id>@<node_inet_addr>[:<port>]`, \
                            where <node_inet_addr> may be IPv4, IPv6 or TORv3 address\
                            ";

        let mut splitter = s.split('@');
        let (id, inet) = match (splitter.next(), splitter.next(), splitter.next()) {
            (Some(id), Some(inet), None) => (id, inet),
            _ => Err(String::from(err_msg))?
        };

        let mut splitter = inet.split(':');
        let (addr, port) = match (splitter.next(), splitter.next(), splitter.next()) {
            (Some(addr), Some(port), None) =>
                (addr, port.parse().map_err(|_| err_msg)?),
            (Some(addr), None, _) => (addr, LIGHTNING_P2P_DEFAULT_PORT),
            _ => Err(String::from(err_msg))?
        };

        Ok(Self {
            node_id: id.parse().map_err(|_| err_msg)?,
            inet_addr: InetSocketAddr::new(addr.parse().map_err(|_| err_msg)?, port)
        })
    }
}


#[derive(Debug, Display)]
#[display_from(Debug)]
pub enum ConnectionError {
    TorNotYetSupported,
    FailedHandshake(String),
    IoError(io::Error)
}

impl From<io::Error> for ConnectionError {
    fn from(err: io::Error) -> Self {
        ConnectionError::IoError(err)
    }
}


pub struct Connection {
    pub stream: TcpStream,
    pub outbound: bool,
    encryptor: Encryptor,
}

impl Connection {
    pub async fn new(node: &NodeAddr,
                     private_key: &secp256k1::SecretKey,
                     ephemeral_private_key: &secp256k1::SecretKey
    ) -> Result<Self, ConnectionError> {

        // TODO: Add support for Tor connections
        if node.inet_addr.address.is_tor() {
            Err(ConnectionError::TorNotYetSupported)?
        }

        // Opening network connection
        #[cfg(feature="use-tor")]
        let socker_addr: SocketAddr = node.inet_addr.try_into().unwrap();
        #[cfg(not(feature="use-tor"))]
        let socker_addr: SocketAddr = node.inet_addr.into();
        let mut stream = TcpStream::connect(socker_addr).await?;

        let mut handshake = PeerHandshake::new_outbound(
            private_key, &node.node_id, ephemeral_private_key
        );

        let mut buf = vec![];
        buf.reserve(MAX_TRANSPORT_FRAME_SIZE);
        let result: Result<Encryptor, ConnectionError> = loop {
            let read_len = stream.read_buf(&mut buf).await?;
            let input = &buf[0..read_len];
            let (act, enc) = handshake.process_act(input)
                .map_err(|msg| ConnectionError::FailedHandshake(msg))?;
            if let Some(encryptor) = enc {
                break Ok(encryptor)
            } else if let Some(next_act) = act {
                stream.write_all(&next_act.serialize()).await?;
            } else {
                Err(ConnectionError::FailedHandshake(
                    "PeerHandshake.process_act returned non-standard result"
                        .to_string()
                ))?
            }
        };
        let encryptor = result?;

        Ok(Self {
            stream,
            outbound: true,
            encryptor
        })
    }
}
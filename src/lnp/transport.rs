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

//! BOLT-8 related structures and functions covering Lightning network
//! transport layer

use std::convert::TryInto;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::str::FromStr;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "tokio")]
use tokio::io::AsyncReadExt;
#[cfg(feature = "tokio")]
use tokio::io::AsyncWriteExt;
#[cfg(feature = "tokio")]
use tokio::net::{tcp, TcpStream};

#[cfg(not(feature = "tokio"))]
use std::io::{Read, Write};
#[cfg(not(feature = "tokio"))]
use std::net::TcpStream;

use bitcoin::secp256k1;

use lightning::ln::peers::conduit::{Conduit as Transcoder, Decryptor, Encryptor};
use lightning::ln::peers::handshake::PeerHandshake;

use super::LIGHTNING_P2P_DEFAULT_PORT;
use crate::common::internet::InetSocketAddr;

pub const MAX_TRANSPORT_FRAME_SIZE: usize = 65569;

#[derive(Clone, Copy, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(
        try_from = "crate::common::serde::CowHelper",
        into = "String",
        crate = "serde_crate"
    )
)]
pub struct NodeAddr {
    pub node_id: secp256k1::PublicKey,
    pub inet_addr: InetSocketAddr,
}

impl NodeAddr {
    pub async fn connect(
        &self,
        private_key: &secp256k1::SecretKey,
        ephemeral_private_key: &secp256k1::SecretKey,
    ) -> Result<Connection, ConnectionError> {
        Connection::new(self, private_key, ephemeral_private_key).await
    }
}

impl fmt::Display for NodeAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.node_id, self.inet_addr)
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
            _ => Err(String::from(err_msg))?,
        };

        let mut splitter = inet.split(':');
        let (addr, port) = match (splitter.next(), splitter.next(), splitter.next()) {
            (Some(addr), Some(port), None) => (addr, port.parse().map_err(|_| err_msg)?),
            (Some(addr), None, _) => (addr, LIGHTNING_P2P_DEFAULT_PORT),
            _ => Err(String::from(err_msg))?,
        };

        Ok(Self {
            node_id: id.parse().map_err(|_| err_msg)?,
            inet_addr: InetSocketAddr::new(addr.parse().map_err(|_| err_msg)?, port),
        })
    }
}

impl_try_from_stringly_standard!(NodeAddr);
impl_into_stringly_standard!(NodeAddr);

#[derive(Debug, Display)]
#[display_from(Debug)]
pub enum ConnectionError {
    TorNotYetSupported,
    FailedHandshake(String),
    IoError(io::Error),
}

impl From<io::Error> for ConnectionError {
    fn from(err: io::Error) -> Self {
        ConnectionError::IoError(err)
    }
}

pub struct Connection {
    pub stream: TcpStream,
    pub outbound: bool,
    #[allow(dead_code)]
    transcoder: Transcoder,
}

#[cfg(feature = "tokio")]
pub struct ConnectionInput {
    pub istream: tcp::OwnedReadHalf,
    pub outbound: bool,
    pub decryptor: Decryptor,
}

#[cfg(feature = "tokio")]
pub struct ConnectionOutput {
    pub ostream: tcp::OwnedWriteHalf,
    pub outbound: bool,
    pub encryptor: Encryptor,
}

impl Connection {
    pub async fn new(
        node: &NodeAddr,
        private_key: &secp256k1::SecretKey,
        ephemeral_private_key: &secp256k1::SecretKey,
    ) -> Result<Self, ConnectionError> {
        // TODO: Add support for Tor connections
        if node.inet_addr.address.is_tor() {
            Err(ConnectionError::TorNotYetSupported)?
        }

        #[cfg(feature = "log")]
        debug!("Initiating connection protocol with {}", node);

        // Opening network connection
        #[cfg(feature = "tor")]
        let socket_addr: SocketAddr = node
            .inet_addr
            .try_into()
            .map_err(|_| ConnectionError::TorNotYetSupported)?;
        #[cfg(not(feature = "tor"))]
        let socket_addr: SocketAddr = node
            .inet_addr
            .try_into()
            .expect("We are not using tor so conversion of internet addresses must not fail");

        #[cfg(feature = "log")]
        trace!("Connecting to {}", socket_addr);
        #[cfg(feature = "tokio")]
        let mut stream = TcpStream::connect(socket_addr).await?;
        #[cfg(not(feature = "tokio"))]
        let mut stream = TcpStream::connect(socket_addr)?;

        #[cfg(feature = "log")]
        trace!("Starting handshake procedure with {}", node);
        let mut handshake =
            PeerHandshake::new_outbound(private_key, &node.node_id, ephemeral_private_key);

        let mut step: usize = 0;
        let mut input: &[u8] = &[];
        let mut buf = vec![];
        buf.reserve(MAX_TRANSPORT_FRAME_SIZE);
        let result: Result<Transcoder, ConnectionError> = loop {
            #[cfg(feature = "log")]
            trace!("Handshake step {}: processing data `{:x?}`", step, input);

            let (act, enc) = handshake
                .process_act(input)
                .map_err(|msg| ConnectionError::FailedHandshake(msg))?;

            if let Some(encryptor) = enc {
                break Ok(encryptor);
            } else if let Some(act) = act {
                #[cfg(feature = "log")]
                trace!("Handshake step {}: sending `{:x?}`", step, act.serialize());

                #[cfg(feature = "tokio")]
                stream.write_all(&act.serialize()).await?;
                #[cfg(not(feature = "tokio"))]
                stream.write_all(&act.serialize())?;
            } else {
                #[cfg(feature = "log")]
                error!("`PeerHandshake.process_act` returned non-standard result");

                Err(ConnectionError::FailedHandshake(
                    "PeerHandshake.process_act returned non-standard result".to_string(),
                ))?
            }

            #[cfg(feature = "log")]
            trace!("Handshake step {}: waiting for response`", step);

            #[cfg(feature = "tokio")]
            let read_len = stream.read_buf(&mut buf).await?;
            #[cfg(not(feature = "tokio"))]
            let read_len = stream.read_to_end(&mut buf)?;
            input = &buf[0..read_len];

            #[cfg(feature = "log")]
            trace!("Handshake step {}: received data `{:x?}`", step, input);

            step += 1;
        };
        let encryptor = result?;

        #[cfg(feature = "log")]
        trace!("Handshake successfully completed");

        Ok(Self {
            stream,
            outbound: true,
            transcoder: encryptor,
        })
    }

    #[cfg(feature = "tokio")]
    pub fn split(self) -> (ConnectionInput, ConnectionOutput) {
        let (istream, ostream) = self.stream.into_split();
        let (encryptor, decryptor) = self.transcoder.split();
        (
            ConnectionInput {
                istream,
                outbound: self.outbound,
                decryptor,
            },
            ConnectionOutput {
                ostream,
                outbound: self.outbound,
                encryptor,
            },
        )
    }
}

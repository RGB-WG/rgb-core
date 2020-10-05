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

use std::fmt;
use std::str::FromStr;

use amplify::internet::InetSocketAddr;
use bitcoin::secp256k1;

use super::{Connection, ConnectionError};
use crate::lnp::LIGHTNING_P2P_DEFAULT_PORT;

#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(
        try_from = "amplify::CowHelper",
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

#[derive(
    Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, Error, From,
)]
#[display(doc_comments)]
/// Error parsing [`NodeAddr`] from string representation, which must be in
/// `<node_id>@<node_inet_addr>[:<port>]` format, where <node_inet_addr> may be
/// IPv4, IPv6 or TOR v2, v3 address
pub enum ParseError {
    /// Node id can't be decoded from the given information. Node id must be a
    /// valid Secp256k1 public key in a compact form
    #[from(bitcoin::secp256k1::Error)]
    WrongNodeId,

    /// Node address must be given as in form of
    /// `<node_id>@<node_inet_addr>[:<port>]`, where <node_inet_addr> may be
    /// IPv4, IPv6 or TORv3 address
    NoNodeId,

    /// The provided node address is incorrect; it must be IPv4, IPv6 or TOR
    /// v2, v3 address
    #[from]
    WrongInetAddr(String),

    /// Port information can't be decoded; it must be a 16-bit unsigned integer
    /// literal
    #[from(std::num::ParseIntError)]
    WrongPort,

    /// No port information in the node address string.
    NoPort,
}

impl FromStr for NodeAddr {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut splitter = s.split('@');
        let (id, inet) =
            match (splitter.next(), splitter.next(), splitter.next()) {
                (Some(id), Some(inet), None) => (id, inet),
                _ => Err(ParseError::NoNodeId)?,
            };

        let mut splitter = inet.split(':');
        let (addr, port) =
            match (splitter.next(), splitter.next(), splitter.next()) {
                (Some(addr), Some(port), None) => (addr, port.parse()?),
                (Some(addr), None, _) => (addr, LIGHTNING_P2P_DEFAULT_PORT),
                _ => Err(ParseError::NoPort)?,
            };

        Ok(Self {
            node_id: id.parse()?,
            inet_addr: InetSocketAddr::new(addr.parse()?, port),
        })
    }
}

impl_try_from_stringly_standard!(NodeAddr);
impl_into_stringly_standard!(NodeAddr);

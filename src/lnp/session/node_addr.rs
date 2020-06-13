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

use bitcoin::secp256k1;

use super::{Connection, ConnectionError};
use crate::internet::InetSocketAddr;
use crate::lnp::LIGHTNING_P2P_DEFAULT_PORT;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
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

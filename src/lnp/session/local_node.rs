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

use bitcoin::secp256k1;

//use super::{NodeAddr, NodeLocator, Session, SessionTrait};

#[derive(Clone, PartialEq, Eq, Debug, Display)]
#[display_from(Debug)]
pub struct LocalNode {
    private_key: Option<secp256k1::SecretKey>,
    ephemeral_private_key: Option<secp256k1::SecretKey>,
}

/*
impl LocalNode {
    pub fn connect(&self, remote: NodeLocator) -> impl SessionTrait {}

    pub fn connect_native(&self, remote: &NodeAddr) -> Session<Transcoder, TcpConnection> {}
    pub fn connect_ipc(
        &self,
        socket_addr: PathBuf,
        connection_type: ZmqType,
    ) -> Session<NoEncryption, ZmqConnection> {
    }
    pub fn connect_inproc(
        &self,
        name: String,
        context: zmq::Context,
        connection_type: ZmqType,
    ) -> Session<NoEncryption, ZmqConnection> {
    }

    pub fn bind_native(&self, local: InetSocketAddr) -> Bind<TcpListener> {}
}

 */

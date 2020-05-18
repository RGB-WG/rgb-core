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

mod connection;
mod node_addr;
mod node_locator;

pub use connection::{Connection, ConnectionError, ConnectionInput, ConnectionOutput};
pub use node_addr::NodeAddr;
pub use node_locator::NodeLocator;

pub const MAX_TRANSPORT_FRAME_SIZE: usize = 65569;

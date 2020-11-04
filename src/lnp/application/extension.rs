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

use std::convert::TryFrom;
use std::fmt::{Debug, Display};
use std::hash::Hash;

use super::channel;
use crate::lnp::application::Messages;
use crate::strict_encoding;

/// Marker trait for creating extension nomenclatures, defining order in which
/// extensions are applied to the channel transaction structure.
///
/// Extension nomenclature is an enum with members convertible into `u16`
/// representation
pub trait Nomenclature
where
    Self: Clone
        + Copy
        + PartialEq
        + Eq
        + PartialOrd
        + Ord
        + Hash
        + Debug
        + Display
        + Default
        + TryFrom<u16, Error = strict_encoding::Error>
        + Into<u16>,
{
}

pub trait Extension {
    type Identity: Nomenclature;

    fn identity(&self) -> Self::Identity;

    /// Updates extension state from the data takend from the message received
    /// from the remote peer
    fn update_from_peer(
        &mut self,
        data: &Messages,
    ) -> Result<(), channel::Error>;

    /// Returns extension state for persistence & backups
    ///
    /// These are extension configuration data, like the data that are the part
    /// of the channel parameters negotiatied between peeers or preconfigured
    /// parameters from the configuration file
    fn extension_state(&self) -> Box<dyn channel::State>;
}

pub trait RoutingExtension: Extension {}

pub trait GossipExtension: Extension {}

pub trait ChannelExtension: Extension {
    /// Returns channel state for persistence & backups.
    ///
    /// These are channel-specific data generated from channel operations,
    /// including client-validated data
    fn channel_state(&self) -> Box<dyn channel::State>;

    /// Applies state to the channel transaction graph
    fn apply(
        &mut self,
        tx_graph: &mut channel::TxGraph,
    ) -> Result<(), channel::Error>;
}

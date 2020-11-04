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

use crate::bp::LexOrder;
use crate::lnp::application::payment::ExtensionId;
use crate::lnp::application::{channel, ChannelExtension, Extension, Messages};

pub struct Bip96;

impl Extension for Bip96 {
    type Identity = ExtensionId;

    #[inline]
    fn identity(&self) -> Self::Identity {
        ExtensionId::Bip96
    }

    #[inline]
    fn update_from_peer(&mut self, _: &Messages) -> Result<(), channel::Error> {
        // Nothing to do here: peers can't tell us anything that will be related
        // to the stateless lexicographic output ordering. So ignoring their
        // messages all together
        Ok(())
    }

    #[inline]
    fn extension_state(&self) -> Box<dyn channel::State> {
        Box::new(())
    }
}

impl ChannelExtension for Bip96 {
    #[inline]
    fn channel_state(&self) -> Box<dyn channel::State> {
        Box::new(())
    }

    #[inline]
    fn apply(
        &mut self,
        tx_graph: &mut channel::TxGraph,
    ) -> Result<(), channel::Error> {
        tx_graph.cmt_outs.lex_order();
        tx_graph
            .vec_mut()
            .into_iter()
            .for_each(|(_, _, tx)| tx.lex_order());
        Ok(())
    }
}

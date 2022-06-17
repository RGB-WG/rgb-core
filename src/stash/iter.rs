// RGB Core Library: a reference implementation of RGB smart contract standards.
// Written in 2019-2022 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the MIT License along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

//! Iterators for stash-related data structures ([`Stash`] implementations,
//! [`Consignment`]s, [`Disclosure`]s)

use std::collections::{btree_map, BTreeSet};
use std::slice;

use bitcoin::Txid;
use bp::dbc::Anchor;
use commit_verify::lnpbp4;

use crate::schema::TransitionType;
use crate::{Transition, TransitionBundle};

#[derive(Debug)]
pub struct MeshIter<'iter> {
    bundles: slice::Iter<'iter, (Anchor<lnpbp4::MerkleProof>, TransitionBundle)>,
    transitions: Option<(Txid, btree_map::Keys<'iter, Transition, BTreeSet<u16>>)>,
    transition_types: &'iter [TransitionType],
}

impl<'iter> Iterator for MeshIter<'iter> {
    type Item = (&'iter Transition, Txid);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            while let Some((txid, transition)) = self
                .transitions
                .as_mut()
                .and_then(|(txid, iter)| iter.next().map(|transition| (txid, transition)))
            {
                if self
                    .transition_types
                    .contains(&transition.transition_type())
                {
                    return Some((transition, *txid));
                }
            }
            let next = self.bundles.next();
            self.transitions =
                next.map(|(anchor, bundle)| (anchor.txid, bundle.known_transitions()));
            self.transitions.as_ref()?;
        }
    }
}

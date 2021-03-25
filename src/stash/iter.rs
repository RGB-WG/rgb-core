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

//! Iterators for stash-related data structures ([`Stash`] implementations,
//! [`Consignment`]s, [`Disclosure`]s)

use std::slice;

use bitcoin::Txid;

use crate::{Anchor, Consignment, Transition};

pub trait TransitionIterator<'iter> {
    type Iterator: Iterator<Item = (Txid, &'iter Transition)>;
}

impl<'iter> TransitionIterator<'iter> for Consignment {
    type Iterator = ConsTsIter<'iter>;
}

/// Iterator over transitions and corresponding witness transaction ids which
/// can be created out of consignment data
#[derive(Debug)]
pub struct ConsTsIter<'iter> {
    consignment: &'iter Consignment,
    iter: slice::Iter<'iter, (Anchor, Transition)>,
}

impl Consignment {
    /// Creates iterator over all state transitions present in the consignment
    /// and corresponding witness transaction ids
    pub fn transition_iter(&self) -> ConsTsIter {
        ConsTsIter {
            consignment: self,
            iter: self.state_transitions.iter(),
        }
    }
}

impl<'iter> Iterator for ConsTsIter<'iter> {
    type Item = (Txid, &'iter Transition);

    fn next(&mut self) -> Option<Self::Item> {
        if let Some((anchor, transition)) = self.iter.next() {
            Some((anchor.txid, transition))
        } else {
            return None;
        }
    }
}

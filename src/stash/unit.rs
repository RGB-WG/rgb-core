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

//! Definition of and operations with state transition units ([`Unit`])

use bitcoin::{OutPoint, Txid};

use crate::schema::OwnedRightType;
use crate::stash::iter::{ConsTsIter, TransitionIterator};
use crate::{Assignments, Consignment, NodeOutput, StateTypes, Transition};
use std::iter::Filter;

/// State transition units (or simply "state units", or even just "units") are
/// extracts from the RGB contract data (as they are stored in a stash)
/// representing particular step in contract state evolution.
///
/// State units can be extracted from stash, consignment (which can be
/// represented by a set of individual state units), and, sometimes, from
/// disclosures (which may not contain even a single complete state unit) and
/// in most cases can't be represented by a set of state units.
///
/// State units are used for data extraction only (unlike consignments and
/// disclosures) and can't be used for mutating or update the contract state or
/// stash. They also do not participate in contract validation and serve pure
/// API usability needs for creating more user-friendly schema-specific APIs.
///
/// State units always contain fully-revealed data and can't be extracted from
/// the contract if at least some of the data are concealed (i.e. seal, state
/// or anchoring mechanism).
///
/// State unit contract-scoped id can be defined as combination of
/// [`Unit::state_type`] and [`Unit::output`]. Global unique state unit ID may
/// be composed by adding RGB contract id to those data.
#[derive(Getters, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct Unit<'container, State>
where
    State: StateTypes,
{
    /// The type of the owned rights which is being modified by the operation
    state_type: OwnedRightType,

    /// State origin in the contract node graph
    input: NodeOutput,

    /// State destination in the contract node graph
    output: NodeOutput,

    /// The seal closed by the operation
    closed_seal: OutPoint,

    /// The new seal defined by the operation
    defined_seal: OutPoint,

    /// Previous state (invalidated by the operation)
    prev_state: &'container State::Revealed,

    /// New state defined as a result of the operation
    next_state: &'container State::Revealed,

    /// Transaction output operating as a single-use-seal closing witness
    witness: OutPoint,
}

#[derive(Eq, PartialEq, Debug)]
pub struct UnitIter<'iter, TsIter, State, Resolver>
where
    State: StateTypes,
    TsIter: TransitionIterator<'iter>,
    Resolver: Fn(Txid) -> u16,
{
    iter: Filter<TsIter<'iter>, fn((Txid, &'iter Transition)) -> bool>,
    item: Option<(Txid, &'iter Assignments)>,
    index: usize,
    resolver: Resolver,
    state_type: OwnedRightType,
}

impl<'iter, TsIter, State, Resolver> Iterator
    for UnitIter<'iter, TsIter, State, Resolver>
where
    State: StateTypes,
    TsIter: TransitionIterator<'iter>,
    Resolver: Fn(Txid) -> u16,
{
    type Item = Unit<'iter, State>;

    fn next(&mut self) -> Option<Self::Item> {
        let (txid, assignments) = if let Some((txid, assignments)) =
            while self.item.is_none() {
                let (txid, transition) =
                    if let Some((txid, transition)) = self.iter.next() {
                        (txid, transition)
                    } else {
                        return None;
                    };
                self.item = transition
                    .owned_rights_by_type(self.state_type)
                    .map(|assignments| (txid, assignments));
                self.index = 0;
                self.item
            } {
            (txid, assignments)
        } else {
            return None;
        };

        assignments
    }
}

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

use std::collections::VecDeque;

use crate::bp;
use crate::rgb::{Anchor, Genesis, Node, Transition};

#[derive(Clone, Debug, Display)]
#[display_from(Debug)]
pub struct Consignment {
    pub genesis: Genesis,
    pub transitions: Vec<Transition>,
    pub endpoints: Vec<Transition>,
    pub data: Vec<(Anchor, Transition)>,
}

#[derive(Clone, Debug, Display, Default)]
#[display_from(Debug)]
pub struct ValidationResult {
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<ValidationWarning>,
}

impl ValidationResult {
    pub fn is_valid(&self) -> bool {
        return self.errors.is_empty();
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, From)]
#[display_from(Debug)]
pub enum ValidationError {}

#[derive(Clone, PartialEq, Eq, Debug, Display, From)]
#[display_from(Debug)]
pub enum ValidationWarning {}

#[derive(Clone, PartialEq, Eq, Debug, Display, From, Error)]
#[display_from(Debug)]
pub enum TxResolverError {}

pub trait TxResolver {
    fn tx_by_id(&mut self, txid: &bitcoin::Txid) -> Result<Option<Transition>, TxResolverError>;
    fn tx_by_ubid(&mut self, ubid: &bp::ShortId) -> Result<Option<Transition>, TxResolverError>;
    fn spending_tx(
        &mut self,
        outpoint: &bitcoin::OutPoint,
    ) -> Result<Option<Transition>, TxResolverError>;
    fn tx_fee(&mut self, txid: &bitcoin::Txid) -> Result<Option<bitcoin::Amount>, TxResolverError>;
}

impl Consignment {
    pub fn validate(&self, _resolver: &mut impl TxResolver) -> ValidationResult {
        let result = ValidationResult::default();
        let mut nodes_queue: VecDeque<&dyn Node> = VecDeque::new();

        nodes_queue.push_back(&self.genesis);

        // Take the next node from the buffer of nodes containing all inputs
        while let Some(node) = nodes_queue.pop_front() {
            // Verify node against the schema

            node.assignment_types().iter().for_each(|at| {
                node.assignments_by_type(*at).into_iter().for_each(|a| {
                    a.known_seals().into_iter().for_each(|_seal| {
                        // Get the seal-spending tx

                        // Get the anchor

                        // Get the child transition

                        // Extract new state and cache it for the verification

                        // Verify the fact of anchor/tx commitment (if not;
                        // save the verification fact for later)

                        // Add this node as an input for the next transition

                        // If the transition has its all inputs covered
                        // add it to the buffer. Completeness can be determined
                        // using index of all seals
                    });
                });
                // Verify state evolution consistency with the script
            });
        }

        // Check that all nodes and anchors are verified

        result
    }
}

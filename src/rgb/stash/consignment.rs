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
use std::io;

use crate::bp;
use crate::rgb::{validation, Anchor, Genesis, Node, Transition};
use crate::strict_encoding::{self, StrictDecode, StrictEncode};

#[derive(Clone, Debug, Display)]
#[display_from(Debug)]
pub struct Consignment {
    pub genesis: Genesis,
    pub endpoints: Vec<bp::blind::OutpointHash>,
    pub data: Vec<(Anchor, Transition)>,
}

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
    pub fn validate(&self, _resolver: &mut impl TxResolver) -> validation::Status {
        let status = validation::Status::default();
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

        status
    }
}

impl StrictEncode for Consignment {
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, strict_encoding::Error> {
        Ok(strict_encode_list!(e; self.genesis, self.endpoints, self.data))
    }
}

impl StrictDecode for Consignment {
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, strict_encoding::Error> {
        Ok(Self {
            genesis: Genesis::strict_decode(&mut d)?,
            endpoints: Vec::<bp::blind::OutpointHash>::strict_decode(&mut d)?,
            data: Vec::<(Anchor, Transition)>::strict_decode(&mut d)?,
        })
    }
}

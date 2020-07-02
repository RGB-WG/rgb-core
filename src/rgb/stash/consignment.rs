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

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io;

use crate::bp;
use crate::rgb::{validation, Anchor, Genesis, Node, NodeId, Schema, Transition};
use crate::strict_encoding::{self, StrictDecode, StrictEncode};

#[derive(Clone, Debug, Display)]
#[display_from(Debug)]
pub struct Consignment {
    pub genesis: Genesis,
    pub endpoints: Vec<(NodeId, bp::blind::OutpointHash)>,
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
    pub fn validate(&self, schema: &Schema, _resolver: &mut impl TxResolver) -> validation::Status {
        let mut status = validation::Status::default();

        let schema_id = self.genesis.schema_id();
        if schema.schema_id() != schema_id {
            status.add_failure(validation::Failure::SchemaUnknown(schema_id));
            return status;
        }

        // Create indexes
        let mut node_index = BTreeMap::<NodeId, &dyn Node>::new();
        for (_, transition) in &self.data {
            node_index.insert(transition.node_id(), transition);
        }

        // Collect all endpoint transitions
        let mut end_transitions = Vec::<&dyn Node>::new();
        for (node_id, outpoint_hash) in &self.endpoints {
            match node_index.get(node_id) {
                Some(node) => {
                    if node.all_seal_definitions().contains(&outpoint_hash) {
                        if end_transitions
                            .iter()
                            .filter(|n| n.node_id() == *node_id)
                            .collect::<Vec<_>>()
                            .len()
                            > 0
                        {
                            status.add_warning(validation::Warning::EndpointDuplication(
                                *node_id,
                                *outpoint_hash,
                            ));
                        } else {
                            end_transitions.push(*node);
                        }
                    } else {
                        // We generate just a warning here because it's up to a user
                        // to decide whether to accept consignment with wrong
                        // endpoint list
                        status.add_warning(validation::Warning::EndpointTransitionSealNotFound(
                            *node_id,
                            *outpoint_hash,
                        ));
                    }
                }
                None => {
                    // We generate just a warning here because it's up to a user
                    // to decide whether to accept consignment with wrong
                    // endpoint list
                    status.add_warning(validation::Warning::EndpointTransitionNotFound(*node_id));
                }
            }
        }

        let mut validation_index = BTreeSet::<NodeId>::new();
        // Validate genesis
        status += schema.validate(&self.genesis, &vec![]);
        for node in end_transitions {
            let mut nodes_queue: VecDeque<&dyn Node> = VecDeque::new();

            nodes_queue.push_back(node);

            while let Some(transition) = nodes_queue.pop_front() {
                let node_id = node.node_id();

                let ancestors: Vec<&dyn Node> = node
                    .ancestors()
                    .into_iter()
                    .filter_map(|id| {
                        node_index.get(id).cloned().or_else(|| {
                            status.add_failure(validation::Failure::TransitionAbsent(*id));
                            None
                        })
                    })
                    .collect();

                // Verify node against the schema
                status += schema.validate(transition, &ancestors);
                validation_index.insert(node_id);

                // Check that transition is committed into the anchor
                // Check that the anchor is committed into a transaction spending
                //   all of the transition inputs

                nodes_queue.extend(ancestors);
            }
        }

        // Generate warning if some of the transitions within the consignment
        // were excessive (i.e. not part of validation_index)

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
            endpoints: Vec::<(NodeId, bp::blind::OutpointHash)>::strict_decode(&mut d)?,
            data: Vec::<(Anchor, Transition)>::strict_decode(&mut d)?,
        })
    }
}

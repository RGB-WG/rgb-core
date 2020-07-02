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

use bitcoin::Txid;

use crate::bp;
use crate::rgb::{validation, Anchor, Genesis, Node, NodeId, Schema, Transition};
use crate::strict_encoding::{self, StrictDecode, StrictEncode};

pub type ConsignmentEndpoints = Vec<(NodeId, bp::blind::OutpointHash)>;
pub type ConsignmentData = Vec<(Anchor, Transition)>;

pub const RGB_CONSIGNMENT_VERSION: u16 = 0;

#[derive(Clone, Debug, Display)]
#[display_from(Debug)]
pub struct Consignment {
    version: u16,
    pub genesis: Genesis,
    pub endpoints: ConsignmentEndpoints,
    pub data: ConsignmentData,
}

impl Consignment {
    pub fn with(
        genesis: Genesis,
        endpoints: ConsignmentEndpoints,
        data: ConsignmentData,
    ) -> Consignment {
        Self {
            version: RGB_CONSIGNMENT_VERSION,
            genesis,
            endpoints,
            data,
        }
    }

    #[inline]
    pub fn txids(&self) -> BTreeSet<Txid> {
        self.data.iter().map(|(anchor, _)| anchor.txid).collect()
    }

    #[inline]
    pub fn node_ids(&self) -> BTreeSet<NodeId> {
        let mut set: BTreeSet<NodeId> = self.data.iter().map(|(_, node)| node.node_id()).collect();
        set.insert(self.genesis.node_id());
        set
    }

    pub fn validate(
        &self,
        schema: &Schema,
        resolver: validation::TxResolver,
    ) -> validation::Status {
        let mut status = validation::Status::default();

        let genesis_id = self.genesis.node_id();
        let contract_id = self.genesis.contract_id();
        let schema_id = self.genesis.schema_id();
        if schema.schema_id() != schema_id {
            status.add_failure(validation::Failure::SchemaUnknown(schema_id));
            return status;
        }

        // Create indexes
        let mut node_index = BTreeMap::<NodeId, &dyn Node>::new();
        let mut anchor_index = BTreeMap::<NodeId, &Anchor>::new();
        for (anchor, transition) in &self.data {
            let node_id = transition.node_id();
            node_index.insert(node_id, transition);
            anchor_index.insert(node_id, anchor);
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
        status += schema.validate(&node_index, &self.genesis, &bmap![]);
        for node in end_transitions {
            let mut queue: VecDeque<&dyn Node> = VecDeque::new();

            queue.push_back(node);

            while let Some(transition) = queue.pop_front() {
                let node_id = node.node_id();

                // Verify node against the schema
                status += schema.validate(&node_index, transition, &node.ancestors());
                validation_index.insert(node_id);

                if let Some(anchor) = anchor_index.get(&node_id).cloned() {
                    // Check that transition is committed into the anchor
                    if !anchor.validate(&contract_id, &node_id) {
                        status.add_failure(validation::Failure::TransitionNotInAnchor(
                            node_id,
                            anchor.anchor_id(),
                        ));
                    }

                    // Check that the anchor is committed into a transaction spending
                    //   all of the transition inputs
                    match resolver(&anchor.txid) {
                        Err(_) => {
                            status.unresolved_txids.push(anchor.txid);
                        }
                        Ok(None) => {
                            status.add_failure(validation::Failure::WitnessTransactionMissed(
                                anchor.txid,
                            ));
                        }
                        Ok(Some((tx, fee))) => {
                            if !anchor.verify(&contract_id, tx, fee) {
                                status.add_failure(validation::Failure::WitnessNoCommitment(
                                    node_id,
                                    anchor.anchor_id(),
                                    anchor.txid,
                                ));
                            }
                        }
                    }
                } else if node_id != genesis_id {
                    status.add_failure(validation::Failure::TransitionNotAnchored(node_id));
                }

                let ancestors: Vec<&dyn Node> = node
                    .ancestors()
                    .into_iter()
                    .filter_map(|(id, _)| {
                        node_index.get(id).cloned().or_else(|| {
                            status.add_failure(validation::Failure::TransitionAbsent(*id));
                            None
                        })
                    })
                    .collect();
                queue.extend(ancestors);
            }
        }

        // Generate warning if some of the transitions within the consignment
        // were excessive (i.e. not part of validation_index)
        for node_id in validation_index.difference(&self.node_ids()) {
            status.add_warning(validation::Warning::ExcessiveTransition(*node_id));
        }

        status
    }
}

impl StrictEncode for Consignment {
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, strict_encoding::Error> {
        Ok(strict_encode_list!(e; self.version, self.genesis, self.endpoints, self.data))
    }
}

impl StrictDecode for Consignment {
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, strict_encoding::Error> {
        Ok(Self {
            version: u16::strict_decode(&mut d)?,
            genesis: Genesis::strict_decode(&mut d)?,
            endpoints: ConsignmentEndpoints::strict_decode(&mut d)?,
            data: ConsignmentData::strict_decode(&mut d)?,
        })
    }
}

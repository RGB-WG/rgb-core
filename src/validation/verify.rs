// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2023 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2019-2023 Dr Maxim Orlovsky. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use bp::dbc::Anchor;
use bp::seals::txout::TxoSeal;
use bp::{Tx, Txid};
use commit_verify::mpc;

use super::graph::Consignment;
use super::schema::NodeType;
use super::{Failure, Status, Validity, Warning};
use crate::validation::subschema::SchemaVerify;
use crate::{
    schema, seal, BundleId, ContractId, Extension, Node, NodeId, Schema, SchemaId,
    TransitionBundle, TypedState,
};

#[derive(Debug, Display, Error)]
#[display(doc_comments)]
/// transaction {0} is not mined
pub struct TxResolverError(Txid);

pub trait ResolveTx {
    fn resolve_tx(&self, txid: Txid) -> Result<Tx, TxResolverError>;
}

pub struct Validator<'consignment, 'resolver, C: Consignment<'consignment>, R: ResolveTx> {
    consignment: &'consignment C,

    status: Status,

    schema_id: SchemaId,
    genesis_id: NodeId,
    contract_id: ContractId,
    node_index: BTreeMap<NodeId, &'consignment dyn Node>,
    anchor_index: BTreeMap<NodeId, &'consignment Anchor<mpc::MerkleProof>>,
    end_transitions: Vec<(&'consignment dyn Node, BundleId)>,
    validation_index: BTreeSet<NodeId>,
    anchor_validation_index: BTreeSet<NodeId>,

    resolver: &'resolver R,
}

impl<'consignment, 'resolver, C: Consignment<'consignment>, R: ResolveTx>
    Validator<'consignment, 'resolver, C, R>
{
    fn init(consignment: &'consignment C, resolver: &'resolver R) -> Self {
        // We use validation status object to store all detected failures and
        // warnings
        let mut status = Status::default();

        // Frequently used computation-heavy data
        let genesis_id = consignment.genesis().node_id();
        let contract_id = consignment.genesis().contract_id();
        let schema_id = consignment.genesis().schema_id();

        // Create indexes
        let mut node_index = BTreeMap::<NodeId, &dyn Node>::new();
        let mut anchor_index = BTreeMap::<NodeId, &Anchor<mpc::MerkleProof>>::new();
        for (anchor, bundle) in consignment.anchored_bundles() {
            if !TransitionBundle::validate(bundle) {
                status.add_failure(Failure::BundleInvalid(bundle.bundle_id()));
            }
            for transition in bundle.revealed.keys() {
                let node_id = transition.node_id();
                node_index.insert(node_id, transition);
                anchor_index.insert(node_id, anchor);
            }
        }
        node_index.insert(genesis_id, consignment.genesis());
        for extension in consignment.state_extensions() {
            let node_id = Extension::node_id(extension);
            node_index.insert(node_id, extension);
        }

        // Collect all endpoint transitions
        // This is pretty simple operation; it takes a lot of code because
        // we would like to detect any potential issues with the consignment
        // structure and notify user about them (in form of generated warnings)
        let mut end_transitions = Vec::<(&dyn Node, BundleId)>::new();
        for (bundle_id, seal_endpoint) in consignment.endpoints() {
            let transitions = match consignment.known_transitions_by_bundle_id(*bundle_id) {
                Ok(transitions) => transitions,
                Err(_) => {
                    status.add_failure(Failure::BundleInvalid(*bundle_id));
                    continue;
                }
            };
            for transition in transitions {
                let node_id = transition.node_id();
                // Checking for endpoint definition duplicates
                if !transition.to_confiential_seals().contains(&seal_endpoint) {
                    // We generate just a warning here because it's up to a user
                    // to decide whether to accept consignment with wrong
                    // endpoint list
                    status.add_warning(Warning::EndpointTransitionSealNotFound(
                        node_id,
                        *seal_endpoint,
                    ));
                }
                if end_transitions
                    .iter()
                    .filter(|(n, _)| n.node_id() == node_id)
                    .count() >
                    0
                {
                    status.add_warning(Warning::EndpointDuplication(node_id, *seal_endpoint));
                } else {
                    end_transitions.push((transition, *bundle_id));
                }
            }
        }

        // Validation index is used to check that all transitions presented
        // in the consignment were validated. Also, we use it to avoid double
        // schema validations for transitions.
        let validation_index = BTreeSet::<NodeId>::new();

        // Index used to avoid repeated validations of the same
        // anchor+transition pairs
        let anchor_validation_index = BTreeSet::<NodeId>::new();

        Self {
            consignment,
            status,
            schema_id,
            genesis_id,
            contract_id,
            node_index,
            anchor_index,
            end_transitions,
            validation_index,
            anchor_validation_index,
            resolver,
        }
    }

    /// Validation procedure takes a schema object, root schema (if any),
    /// resolver function returning transaction and its fee for a given
    /// transaction id, and returns a validation object listing all detected
    /// failures, warnings and additional information.
    ///
    /// When a failure detected, it not stopped; the failure is is logged into
    /// the status object, but the validation continues for the rest of the
    /// consignment data. This can help it debugging and detecting all problems
    /// with the consignment.
    pub fn validate(consignment: &'consignment C, resolver: &'resolver R) -> Status {
        let mut validator = Validator::init(consignment, resolver);

        validator.validate_schema(consignment.schema(), consignment.root_schema());
        // We must return here, since if the schema is not valid there is no
        // reason to validate contract nodes against it: it will produce a
        // plenty of errors
        if validator.status.validity() == Validity::Invalid {
            return validator.status;
        }

        validator.validate_contract(consignment.schema());

        // Done. Returning status report with all possible failures, issues,
        // warnings and notifications about transactions we were unable to
        // obtain.
        validator.status
    }

    fn validate_schema(&mut self, schema: &Schema, root: Option<&Schema>) {
        // Validating schema against root schema
        if let Some(root) = root {
            self.status += schema.schema_verify(root);
        } else if let Some(root_id) = schema.subset_of {
            self.status
                .add_failure(Failure::SchemaRootRequired(root_id));
        }
    }

    fn validate_contract(&mut self, schema: &Schema) {
        // [VALIDATION]: Making sure that we were supplied with the schema
        //               that corresponds to the schema of the contract genesis
        if schema.schema_id() != self.schema_id {
            self.status
                .add_failure(Failure::SchemaUnknown(self.schema_id));
            // Unlike other failures, here we return immediatelly, since there
            // is no point to validate all consignment data against an invalid
            // schema: it will result in a plenty of meaningless errors
            return;
        }

        // [VALIDATION]: Validate genesis
        self.status +=
            schema.validate(&self.node_index, self.consignment.genesis(), &schema.script);
        self.validation_index.insert(self.genesis_id);

        // [VALIDATION]: Iterating over each endpoint, reconstructing node graph
        //               up to genesis for each one of them. NB: We are not
        //               aiming to validate the consignment as a whole, but
        //               instead treat it as a superposition of subgraphs, one
        //               for each endpoint; and validate them independently.
        for (node, bundle_id) in self.end_transitions.clone() {
            self.validate_branch(schema, node, bundle_id);
        }
        // Replace missed (not yet mined) endpoint witness transaction failures
        // with a dedicated type
        for (node, _) in &self.end_transitions {
            if let Some(anchor) = self.anchor_index.get(&node.node_id()) {
                if let Some(pos) = self
                    .status
                    .failures
                    .iter()
                    .position(|f| f == &Failure::WitnessTransactionMissed(anchor.txid))
                {
                    self.status.failures.remove(pos);
                    self.status
                        .unresolved_txids
                        .retain(|txid| *txid != anchor.txid);
                    self.status.unmined_endpoint_txids.push(anchor.txid);
                    self.status
                        .warnings
                        .push(Warning::EndpointTransactionMissed(anchor.txid));
                }
            }
        }

        // Generate warning if some of the transitions within the consignment
        // were excessive (i.e. not part of validation_index). Nothing critical,
        // but still good to report the user that the consignment is not perfect
        for node_id in self
            .validation_index
            .difference(&self.consignment.node_ids())
        {
            self.status.add_warning(Warning::ExcessiveNode(*node_id));
        }
    }

    fn validate_branch(
        &mut self,
        schema: &Schema,
        node: &'consignment dyn Node,
        bundle_id: BundleId,
    ) {
        let mut queue: VecDeque<&dyn Node> = VecDeque::new();

        // Instead of constructing complex graph structures or using a
        // recursions we utilize queue to keep the track of the upstream
        // (ancestor) nodes and make sure that ve have validated each one
        // of them up to genesis. The graph is valid when each of its nodes
        // and each of its edges is valid, i.e. when all individual nodes
        // has passed validation against the schema (we track that fact with
        // `validation_index`) and each of the node ancestor state change to
        // a given node is valid against the schema + committed into bitcoin
        // transaction graph with proper anchor. That is what we are
        // checking in the code below:
        queue.push_back(node);
        while let Some(node) = queue.pop_front() {
            let node_id = node.node_id();
            let node_type = node.node_type();

            // [VALIDATION]: Verify node against the schema. Here we check
            //               only a single node, not state evolution (it
            //               will be checked lately)
            if !self.validation_index.contains(&node_id) {
                self.status += schema.validate(&self.node_index, node, &schema.script);
                self.validation_index.insert(node_id);
            }

            // Making sure we do have a corresponding anchor; otherwise
            // reporting failure (see below) - with the except of genesis and
            // extension nodes, which does not have a corresponding anchor
            if let Some(anchor) = self.anchor_index.get(&node_id).cloned() {
                if !self.anchor_validation_index.contains(&node_id) {
                    // Ok, now we have the `node` and the `anchor`, let's do all
                    // required checks

                    // [VALIDATION]: Check that transition is committed into the
                    //               anchor. This must be done with
                    //               deterministic bitcoin commitments & LNPBP-4
                    if anchor.convolve(self.contract_id, bundle_id.into()).is_err() {
                        self.status
                            .add_failure(Failure::TransitionNotInAnchor(node_id, anchor.txid));
                    }

                    self.validate_graph_node(node, bundle_id, anchor);
                    self.anchor_validation_index.insert(node_id);
                }
                // Ouch, we are out of that multi-level nested cycles :)
            } else if node_type != NodeType::Genesis && node_type != NodeType::StateExtension {
                // This point is actually unreachable: b/c of the
                // consignment structure, each state transition
                // has a corresponding anchor. So if we've got here there
                // is something broken with LNP/BP core library.
                self.status
                    .add_failure(Failure::TransitionNotAnchored(node_id));
            }

            // Now, we must collect all parent nodes and add them to the
            // verification queue
            let parent_nodes_1: Vec<&dyn Node> = node
                .parent_owned_rights()
                .iter()
                .filter_map(|(id, _)| {
                    self.node_index.get(id).cloned().or_else(|| {
                        // This will not actually happen since we already
                        // checked that each ancrstor reference has a
                        // corresponding node in the code above. But rust
                        // requires to double-check :)
                        self.status.add_failure(Failure::TransitionAbsent(*id));
                        None
                    })
                })
                .collect();

            let parent_nodes_2: Vec<&dyn Node> = node
                .parent_public_rights()
                .iter()
                .filter_map(|(id, _)| {
                    self.node_index.get(id).cloned().or_else(|| {
                        // This will not actually happen since we already
                        // checked that each ancestor reference has a
                        // corresponding node in the code above. But rust
                        // requires to double-check :)
                        self.status.add_failure(Failure::TransitionAbsent(*id));
                        None
                    })
                })
                .collect();

            queue.extend(parent_nodes_1);
            queue.extend(parent_nodes_2);
        }
    }

    fn validate_graph_node(
        &mut self,
        node: &'consignment dyn Node,
        bundle_id: BundleId,
        anchor: &'consignment Anchor<mpc::MerkleProof>,
    ) {
        let txid = anchor.txid;
        let node_id = node.node_id();

        // Check that the anchor is committed into a transaction spending all of
        // the transition inputs.
        match self.resolver.resolve_tx(txid) {
            Err(_) => {
                // We wre unable to retrieve corresponding transaction, so can't
                // check. Reporting this incident and continuing further.
                // Why this happens? No connection to Bitcoin Core, Electrum or
                // other backend etc. So this is not a failure in a strict
                // sense, however we can't be sure that the
                // consignment is valid. That's why we keep the
                // track of such information in a separate place
                // (`unresolved_txids` field of the validation
                // status object).
                self.status.unresolved_txids.push(txid);
                // This also can mean that there is no known transaction with the
                // id provided by the anchor, i.e. consignment is invalid. We
                // are proceeding with further validation in order to detect the
                // rest of problems (and reporting the failure!)
                self.status
                    .add_failure(Failure::WitnessTransactionMissed(txid));
            }
            Ok(witness_tx) => {
                // Ok, now we have the transaction and fee information for a
                // single state change from some ancestors array to the
                // currently validated transition node: that's everything
                // required to do the complete validation

                // [VALIDATION]: Checking anchor deterministic bitcoin
                //               commitment
                if anchor
                    .verify(self.contract_id, bundle_id.into(), &witness_tx)
                    .is_err()
                {
                    // TODO: Save error details
                    // The node is not committed to bitcoin transaction graph!
                    // Ultimate failure. But continuing to detect the rest
                    // (after reporting it).
                    self.status
                        .add_failure(Failure::WitnessNoCommitment(node_id, txid));
                }

                // Checking that bitcoin transaction closes seals defined by
                // transition ancestors.
                for (ancestor_id, assignments) in node.parent_owned_rights().iter() {
                    let ancestor_id = *ancestor_id;
                    let ancestor_node =
                        if let Some(ancestor_node) = self.node_index.get(&ancestor_id) {
                            *ancestor_node
                        } else {
                            // Node, referenced as the ancestor, was not found
                            // in the consignment. Usually this means that the
                            // consignment data are broken
                            self.status
                                .add_failure(Failure::TransitionAbsent(ancestor_id));
                            continue;
                        };

                    for (assignment_type, assignment_indexes) in assignments {
                        let assignment_type = *assignment_type;

                        let variant = if let Some(variant) =
                            ancestor_node.owned_rights_by_type(assignment_type)
                        {
                            variant
                        } else {
                            self.status
                                .add_failure(Failure::TransitionParentWrongSealType {
                                    node_id,
                                    ancestor_id,
                                    assignment_type,
                                });
                            continue;
                        };

                        for seal_index in assignment_indexes {
                            self.validate_witness_input(
                                &witness_tx,
                                node_id,
                                ancestor_id,
                                assignment_type,
                                variant,
                                *seal_index,
                            );
                        }
                    }
                }
            }
        }
    }

    // TODO #45: Move part of logic into single-use-seals and bitcoin seals
    fn validate_witness_input(
        &mut self,
        witness_tx: &Tx,
        node_id: NodeId,
        ancestor_id: NodeId,
        assignment_type: schema::OwnedRightType,
        variant: &'consignment TypedState,
        seal_index: u16,
    ) {
        // Getting bitcoin transaction outpoint for the current ancestor ... ->
        if let Some(outpoint) =
            match (variant.revealed_seal_at(seal_index), self.anchor_index.get(&ancestor_id)) {
                (Err(_), _) => {
                    self.status.add_failure(Failure::TransitionParentWrongSeal {
                        node_id,
                        ancestor_id,
                        assignment_type,
                        seal_index,
                    });
                    None
                }
                (Ok(None), _) => {
                    // Everything is ok, but we have incomplete data (confidential),
                    // thus can't do a full verification and have to report the
                    // failure
                    eprintln!("{:#?}", variant);
                    self.status
                        .add_failure(Failure::TransitionParentConfidentialSeal {
                            node_id,
                            ancestor_id,
                            assignment_type,
                            seal_index,
                        });
                    None
                }
                (
                    Ok(Some(seal::Revealed {
                        txid: Some(txid),
                        vout,
                        ..
                    })),
                    None,
                ) => {
                    // We are at genesis, so the outpoint must contain tx
                    Some(bp::Outpoint::new(txid, vout))
                }
                (Ok(Some(_)), None) => {
                    // This can't happen, since if we have a node in the index
                    // and the node is not genesis, we always have an anchor
                    unreachable!()
                }
                /* -> ... so we can check that the bitcoin transaction
                 * references it as one of its inputs */
                (Ok(Some(seal)), Some(anchor)) => Some(seal.outpoint_or(anchor.txid)),
            }
        {
            if !witness_tx
                .inputs
                .iter()
                .any(|txin| txin.prev_output == outpoint)
            {
                // Another failure: we do not spend one of the transition
                // ancestors in the witness transaction. The consignment is
                // clearly invalid; reporting this and processing to other
                // potential issues.
                self.status
                    .add_failure(Failure::TransitionParentIsNotWitnessInput {
                        node_id,
                        ancestor_id,
                        assignment_type,
                        seal_index,
                        outpoint,
                    });
            }
        }
    }
}

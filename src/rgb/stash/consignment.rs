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
use crate::rgb::{seal, validation, Anchor, Genesis, Node, NodeId, Schema, Transition};
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

    // TODO: Refactor into multiple subroutines
    // TODO: Move part of logic into single-use-seals and bitcoin seals
    /// Validation procedure takes a schema object, resolver function
    /// returning transaction and its fee for a given transaction id, and
    /// returns a validation object listing all detected falires, warnings and
    /// additional information.
    ///
    /// When a failure detected, it not stopped; the failure is is logged into
    /// the status object, but the validation continues for the rest of the
    /// consignment data. This can help it debugging and detecting all problems
    /// with the consignment.
    pub fn validate(
        &self,
        schema: &Schema,
        resolver: validation::TxResolver,
    ) -> validation::Status {
        // We use validation status object to store all detected failures and
        // warnings
        let mut status = validation::Status::default();

        // Frequently used computation-heavy data
        let genesis_id = self.genesis.node_id();
        let contract_id = self.genesis.contract_id();
        let schema_id = self.genesis.schema_id();

        // [VALIDATION]: Making sure that we were supplied with the schema
        //               that corresponds to the schema of the contract genesis
        if schema.schema_id() != schema_id {
            status.add_failure(validation::Failure::SchemaUnknown(schema_id));
            // Unlike other failures, here we return immediatelly, since there
            // is no point to validate all consignment data against an invalid
            // schema: it will result in a plenty of meaningless errors
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
        node_index.insert(genesis_id, &self.genesis);

        // Collect all endpoint transitions
        // This is pretty simple operation; it takes a lot of code because
        // we would like to detect any potential issues with the consignment
        // structure and notify use about them (in form of generated warnings)
        let mut end_transitions = Vec::<&dyn Node>::new();
        for (node_id, outpoint_hash) in &self.endpoints {
            if let Some(node) = node_index.get(node_id) {
                // Checking for endpoint definition duplicates
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
            } else {
                // We generate just a warning here because it's up to a user
                // to decide whether to accept consignment with wrong
                // endpoint list
                status.add_warning(validation::Warning::EndpointTransitionNotFound(*node_id));
            }
        }

        // Validation index is used to check that all transitions presented
        // in the consignment were validated. Also, we use it to avoid double
        // schema validations for transitions.
        let mut validation_index = BTreeSet::<NodeId>::new();

        // [VALIDATION]: Validate genesis
        status += schema.validate(&node_index, &self.genesis);
        validation_index.insert(genesis_id);

        // [VALIDATION]: Iterating over each endpoint, reconstructing node graph
        //               up to genesis for each one of them. NB: We are not
        //               aiming to validate the consignment as a whole, but
        //               instead treat it as a superposition of subgraphs, one
        //               for each endpoint; and validate them independently.
        for node in end_transitions {
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

                // [VALIDATION]: Verify node against the schema. Here we check
                //               only a single node, not state evolution (it
                //               will be checked lately)
                if !validation_index.contains(&node_id) {
                    status += schema.validate(&node_index, node);
                    validation_index.insert(node_id);
                }

                // Making sure we do have a corresponding anchor; otherwise
                // reporting failure (see below) - with the except of genesis
                // node, which does not have a corresponding anchor
                if let Some(anchor) = anchor_index.get(&node_id).cloned() {
                    // Ok, now we have the `node` and the `anchor`, let's do all
                    // required checks

                    // [VALIDATION]: Check that transition is committed into the
                    //               anchor. This must be done with
                    //               deterministic bitcoin commitments & LNPBP-4
                    if !anchor.validate(&contract_id, &node_id) {
                        status.add_failure(validation::Failure::TransitionNotInAnchor(
                            node_id,
                            anchor.anchor_id(),
                        ));
                    }

                    // Check that the anchor is committed into a transaction
                    // spending all of the transition inputs. Yep, this has
                    // many nested code levels b/c of the rust language style;
                    // we have too much of the temporary state that prevents
                    // from re-organizing this into separate procedures.
                    match resolver(&anchor.txid) {
                        Err(_) => {
                            // We wre unable to retrieve corresponding
                            // transaction, so can't check. Reporting this
                            // incident and continuing further.
                            // Why this happens? no connection to Bitcoin Core,
                            // Electrum or other backend etc. So this is not a
                            // failure in a strict sense, however we can't be
                            // sure that the consignment is valid. That's why
                            // we keep the track of such information in a
                            // separate place (`unresolved_txids` field of
                            // the validation status object).
                            status.unresolved_txids.push(anchor.txid);
                        }
                        Ok(None) => {
                            // There is no mined transaction with the id
                            // provided by the anchor. Literally, the whole
                            // consignment is fucked up, but we are proceeding
                            // with further validation in order to detect the
                            // rest of fuck ups (and reporting the failure!)
                            status.add_failure(validation::Failure::WitnessTransactionMissed(
                                anchor.txid,
                            ));
                        }
                        Ok(Some((witness_tx, fee))) => {
                            // Ok, now we have the transaction and fee
                            // information for a single state change from some
                            // ancestors array to the currently validated
                            // transition node: that's everything required to do
                            // the complete validation

                            // [VALIDATION]: Checking anchor deterministic
                            //               bitcoin commitment
                            if !anchor.verify(&contract_id, &witness_tx, fee) {
                                // The node is not committed to bitcoin
                                // transaction graph! Ultimate failure. But
                                // continuing to detect the rest (after
                                // reporting it).
                                status.add_failure(validation::Failure::WitnessNoCommitment(
                                    node_id,
                                    anchor.anchor_id(),
                                    anchor.txid,
                                ));
                            }

                            // Checking that bitcoin transaction closes seals
                            // defined by transition ancestors. It's hard to
                            // figure that out, so you will be probably ashamed
                            // with the nested code levels... Still finding a
                            // way to do it better; feel free to open a PR.
                            for (id, assignments) in node.ancestors() {
                                match node_index.get(id).cloned() {
                                    None => {
                                        // Node, referenced as the ancestor, was
                                        // not found in the consignment. Usually
                                        // this means that the consignment data
                                        // are broken. So reporting this failure
                                        status.add_failure(validation::Failure::TransitionAbsent(
                                            *id,
                                        ));
                                    }
                                    Some(ancestor_node) => {
                                        for (assignment_type, indexes) in assignments {
                                            match ancestor_node
                                                .assignments_by_type(*assignment_type)
                                            {
                                                None => {
                                                    status.add_failure(
                                                        validation::Failure::TransitionAncestorWrongSealType {
                                                            node_id,
                                                            ancestor_id: *id,
                                                            assignment_type: *assignment_type,
                                                        }
                                                    );
                                                }
                                                Some(variant) => {
                                                    for index in indexes {
                                                        // Getting bitcoin transaction outpoint for the current ancestor ... ->
                                                        match (variant.seal(*index), anchor_index.get(id).cloned()) {
                                                            (Err(_), _) => {
                                                                status.add_failure(
                                                                    validation::Failure::TransitionAncestorWrongSeal {
                                                                        node_id,
                                                                        ancestor_id: *id,
                                                                        assignment_type: *assignment_type,
                                                                        seal_index: *index
                                                                    }
                                                                );
                                                                None
                                                            }
                                                            (Ok(None), _) => {
                                                                // Everything is ok, but we have incomplete confidential data, 
                                                                // thus can't do a full verification and have to report the failure
                                                                status.add_failure(
                                                                    validation::Failure::TransitionAncestorConfidentialSeal {
                                                                        node_id,
                                                                        ancestor_id: *id,
                                                                        assignment_type: *assignment_type,
                                                                        seal_index: *index
                                                                    }
                                                                );
                                                                None
                                                            }
                                                            (Ok(Some(seal::Revealed::TxOutpoint(outpoint))), None) => {
                                                                // We are at genesis, so the outpoint must contain tx
                                                                Some(bitcoin::OutPoint::from(outpoint.clone()))
                                                            }
                                                            (Ok(Some(_)), None) => {
                                                                // This can't happen, since if we have a node in the index
                                                                // and the node is not genesis, we always have an anchor
                                                                unreachable!()
                                                            }
                                                            (Ok(Some(seal)), Some(anchor)) => {
                                                                Some(bitcoin::OutPoint::from(seal.outpoint_reveal(anchor.txid)))
                                                            }
                                                        // -> ... so we can check that the bitcoin transaction references it as one of its inputs
                                                        }.map(|outpoint| {
                                                            if witness_tx.input.iter().find(|txin| txin.previous_output == outpoint).is_none() {
                                                                // Another failure: we do not spend one of the transition ancestors in the witness
                                                                // transaction. The consignment is clearly invalid; reporting this and processing
                                                                // to other potential issues.
                                                                status.add_failure(
                                                                    validation::Failure::TransitionAncestorIsNotWitnessInput {
                                                                        node_id,
                                                                        ancestor_id: *id,
                                                                        assignment_type: *assignment_type,
                                                                        seal_index: *index,
                                                                        outpoint
                                                                    }
                                                                );
                                                            }
                                                        });
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                // Ouch, we are out of that multi-level nested cycles :)
                } else if node_id != genesis_id {
                    // This point is actually unreachable: b/c of the
                    // consignment structure, each node (other then genesis)
                    // has a corresponding anchor. So if we've got here there
                    // is something broken with LNP/BP core library.
                    // TODO: Consider to remove this failure and replace it
                    //       with panic using `unreachable!()` macro.
                    status.add_failure(validation::Failure::TransitionNotAnchored(node_id));
                }

                // Now, we must collect all ancestor nodes and add them to the
                // verification queue
                let ancestors: Vec<&dyn Node> = node
                    .ancestors()
                    .into_iter()
                    .filter_map(|(id, _)| {
                        node_index.get(id).cloned().or_else(|| {
                            // This will not actually happen since we already
                            // checked that each ancrstor reference has a
                            // corresponding node in the code above. But rust
                            // requires to double-check :)
                            status.add_failure(validation::Failure::TransitionAbsent(*id));
                            None
                        })
                    })
                    .collect();
                queue.extend(ancestors);
            }
        }

        // Generate warning if some of the transitions within the consignment
        // were excessive (i.e. not part of validation_index). Nothing critical,
        // but still good to report the used that the consignment is not perfect
        for node_id in validation_index.difference(&self.node_ids()) {
            status.add_warning(validation::Warning::ExcessiveTransition(*node_id));
        }

        // Done. Returing status report with all possible failures, issues,
        // warnings and notifications about transactions we were unable to
        // obtain.
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

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::rgb::schema::test::schema;

    pub(crate) fn consignment() -> Consignment {
        let data: Vec<u8> = vec![
            0, 0, 32, 0, 175, 68, 251, 129, 83, 146, 46, 224, 148, 121, 32, 207, 66, 190, 97, 28,
            158, 179, 119, 79, 148, 59, 221, 61, 93, 232, 235, 15, 159, 58, 147, 188, 11, 17, 9, 7,
            7, 0, 0, 0, 1, 0, 33, 5, 0, 67, 79, 86, 73, 68, 1, 0, 1, 0, 33, 11, 0, 67, 111, 118,
            105, 100, 32, 116, 111, 107, 101, 110, 3, 0, 1, 0, 3, 100, 0, 0, 0, 0, 0, 0, 0, 4, 0,
            1, 0, 3, 100, 0, 0, 0, 0, 0, 0, 0, 5, 0, 1, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 1, 0,
            0, 0, 8, 0, 1, 0, 2, 57, 105, 255, 94, 2, 0, 1, 0, 1, 3, 1, 0, 1, 0, 34, 165, 223, 89,
            157, 212, 161, 60, 169, 160, 45, 95, 60, 60, 68, 97, 224, 93, 246, 23, 246, 171, 184,
            6, 93, 50, 60, 5, 35, 58, 96, 198, 241, 6, 30, 226, 0, 0, 3, 100, 0, 0, 0, 0, 0, 0, 0,
            32, 0, 156, 221, 61, 60, 184, 6, 7, 109, 36, 84, 174, 189, 113, 99, 171, 166, 182, 228,
            131, 107, 42, 200, 35, 93, 1, 228, 182, 203, 46, 175, 183, 56, 2, 0, 0, 0, 0, 0, 0, 1,
            0, 83, 131, 189, 122, 77, 36, 240, 65, 255, 85, 56, 74, 138, 140, 96, 130, 24, 252,
            212, 163, 226, 175, 124, 104, 208, 155, 197, 147, 42, 30, 108, 147, 14, 210, 180, 166,
            126, 169, 208, 75, 25, 232, 25, 3, 234, 26, 9, 49, 37, 73, 61, 65, 164, 111, 223, 38,
            234, 11, 233, 112, 180, 119, 128, 227, 1, 0, 97, 164, 66, 156, 189, 79, 2, 211, 4, 166,
            134, 47, 17, 48, 48, 201, 24, 174, 152, 214, 1, 12, 240, 50, 17, 226, 182, 59, 77, 57,
            24, 211, 1, 0, 0, 209, 14, 87, 70, 119, 82, 48, 77, 43, 181, 31, 113, 154, 17, 233, 63,
            110, 55, 185, 129, 42, 110, 97, 198, 154, 9, 114, 100, 213, 55, 186, 167, 1, 107, 165,
            166, 43, 121, 222, 245, 39, 3, 158, 255, 31, 84, 122, 29, 95, 146, 223, 162, 186, 122,
            246, 172, 151, 26, 75, 208, 59, 164, 167, 52, 176, 49, 86, 162, 86, 184, 173, 58, 30,
            249, 0, 1, 0, 0, 0, 1, 0, 120, 175, 150, 24, 51, 142, 132, 88, 48, 225, 228, 68, 149,
            108, 209, 219, 142, 99, 150, 68, 220, 167, 203, 146, 245, 204, 45, 172, 226, 43, 133,
            124, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 3, 1, 0, 2, 14, 210, 180, 166, 126, 169,
            208, 75, 25, 232, 25, 3, 234, 26, 9, 49, 37, 73, 61, 65, 164, 111, 223, 38, 234, 11,
            233, 112, 180, 119, 128, 227, 3, 100, 0, 0, 0, 0, 0, 0, 0, 32, 0, 219, 99, 194, 167,
            245, 137, 224, 79, 24, 146, 231, 158, 84, 190, 247, 219, 211, 11, 89, 112, 106, 222,
            186, 44, 141, 77, 67, 98, 189, 4, 120, 0, 0, 0,
        ];

        Consignment::strict_decode(&data[..]).unwrap()
    }

    fn tx_resolver(
        txid: &Txid,
    ) -> Result<Option<(bitcoin::Transaction, u64)>, validation::TxResolverError> {
        eprintln!("Validating txid {}", txid);
        Err(validation::TxResolverError)
    }

    #[test]
    fn test_consignment_validation() {
        let consignment = consignment();
        let schema = schema();
        let status = consignment.validate(&schema, tx_resolver);
        println!("{}", status);
    }
}

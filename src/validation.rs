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

use core::iter::FromIterator;
use core::ops::AddAssign;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use bitcoin::{Transaction, Txid};
use bp::dbc::Anchor;
use bp::seals::txout::TxoSeal;
use commit_verify::{lnpbp4, CommitConceal};
use stens::TypeRef;
use wallet::onchain::ResolveTx;

use super::schema::{NodeType, OccurrencesError};
use super::{schema, seal, ContractId, Node, NodeId, Schema, SchemaId, TypedAssignments};
use crate::schema::SchemaVerify;
use crate::stash::Consignment;
use crate::{data, BundleId, Extension, SealEndpoint, TransitionBundle};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Display)]
#[display(Debug)]
#[repr(u8)]
pub enum Validity {
    Valid,
    UnresolvedTransactions,
    Invalid,
}

#[derive(Clone, Debug, Display, Default, StrictEncode, StrictDecode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
// TODO #42: Display via YAML
#[display(Debug)]
pub struct Status {
    pub unresolved_txids: Vec<Txid>,
    pub failures: Vec<Failure>,
    pub warnings: Vec<Warning>,
    pub info: Vec<Info>,
}

impl AddAssign for Status {
    fn add_assign(&mut self, rhs: Self) {
        self.unresolved_txids.extend(rhs.unresolved_txids);
        self.failures.extend(rhs.failures);
        self.warnings.extend(rhs.warnings);
        self.info.extend(rhs.info);
    }
}

impl Status {
    pub fn from_error(v: Failure) -> Self {
        Status {
            unresolved_txids: vec![],
            failures: vec![v],
            warnings: vec![],
            info: vec![],
        }
    }
}

impl FromIterator<Failure> for Status {
    fn from_iter<T: IntoIterator<Item = Failure>>(iter: T) -> Self {
        Self {
            failures: iter.into_iter().collect(),
            ..Self::default()
        }
    }
}

impl Status {
    pub fn new() -> Self { Self::default() }

    pub fn with_failure(failure: Failure) -> Self {
        Self {
            failures: vec![failure],
            ..Self::default()
        }
    }

    pub fn add_failure(&mut self, failure: Failure) -> &Self {
        self.failures.push(failure);
        self
    }

    pub fn add_warning(&mut self, warning: Warning) -> &Self {
        self.warnings.push(warning);
        self
    }

    pub fn add_info(&mut self, info: Info) -> &Self {
        self.info.push(info);
        self
    }

    pub fn validity(&self) -> Validity {
        if !self.failures.is_empty() {
            Validity::Invalid
        } else if !self.unresolved_txids.is_empty() {
            Validity::UnresolvedTransactions
        } else {
            Validity::Valid
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, From, StrictEncode, StrictDecode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
// TODO #44: (v0.3) convert to detailed error description using doc_comments
#[display(Debug)]
pub enum Failure {
    SchemaUnknown(SchemaId),
    /// schema is a subschema, so root schema {0} must be provided for the
    /// validation
    SchemaRootRequired(SchemaId),
    /// Root schema for this schema has another root, which is prohibited
    SchemaRootHierarchy(SchemaId),
    SchemaRootNoFieldTypeMatch(schema::FieldType),
    SchemaRootNoOwnedRightTypeMatch(schema::OwnedRightType),
    SchemaRootNoPublicRightTypeMatch(schema::PublicRightType),
    SchemaRootNoTransitionTypeMatch(schema::TransitionType),
    SchemaRootNoExtensionTypeMatch(schema::ExtensionType),

    SchemaRootNoMetadataMatch(NodeType, schema::FieldType),
    SchemaRootNoParentOwnedRightsMatch(NodeType, schema::OwnedRightType),
    SchemaRootNoParentPublicRightsMatch(NodeType, schema::PublicRightType),
    SchemaRootNoOwnedRightsMatch(NodeType, schema::OwnedRightType),
    SchemaRootNoPublicRightsMatch(NodeType, schema::PublicRightType),

    SchemaUnknownExtensionType(NodeId, schema::ExtensionType),
    SchemaUnknownTransitionType(NodeId, schema::TransitionType),
    SchemaUnknownFieldType(NodeId, schema::FieldType),
    SchemaUnknownOwnedRightType(NodeId, schema::OwnedRightType),
    SchemaUnknownPublicRightType(NodeId, schema::PublicRightType),

    SchemaDeniedScriptExtension(NodeId),

    SchemaMetaValueTooSmall(schema::FieldType),
    SchemaMetaValueTooLarge(schema::FieldType),
    SchemaStateValueTooSmall(schema::OwnedRightType),
    SchemaStateValueTooLarge(schema::OwnedRightType),

    SchemaWrongEnumValue {
        field_or_state_type: u16,
        unexpected: u8,
    },
    SchemaWrongDataLength {
        field_or_state_type: u16,
        max_expected: u16,
        found: usize,
    },
    SchemaMismatchedDataType(u16),
    SchemaMismatchedStateType(schema::OwnedRightType),

    SchemaMetaOccurrencesError(NodeId, schema::FieldType, OccurrencesError),
    SchemaParentOwnedRightOccurrencesError(NodeId, schema::OwnedRightType, OccurrencesError),
    SchemaOwnedRightOccurrencesError(NodeId, schema::OwnedRightType, OccurrencesError),

    SchemaScriptOverrideDenied,
    SchemaScriptVmChangeDenied,

    BundleInvalid(BundleId),

    TransitionAbsent(NodeId),
    TransitionNotAnchored(NodeId),
    TransitionNotInAnchor(NodeId, Txid),
    TransitionParentWrongSealType {
        node_id: NodeId,
        ancestor_id: NodeId,
        assignment_type: schema::OwnedRightType,
    },
    TransitionParentWrongSeal {
        node_id: NodeId,
        ancestor_id: NodeId,
        assignment_type: schema::OwnedRightType,
        seal_index: u16,
    },
    TransitionParentConfidentialSeal {
        node_id: NodeId,
        ancestor_id: NodeId,
        assignment_type: schema::OwnedRightType,
        seal_index: u16,
    },
    TransitionParentIsNotWitnessInput {
        node_id: NodeId,
        ancestor_id: NodeId,
        assignment_type: schema::OwnedRightType,
        seal_index: u16,
        outpoint: bitcoin::OutPoint,
    },

    ExtensionAbsent(NodeId),
    ExtensionParentWrongValenciesType {
        node_id: NodeId,
        ancestor_id: NodeId,
        valencies_type: schema::PublicRightType,
    },

    WitnessTransactionMissed(Txid),
    WitnessNoCommitment(NodeId, Txid),

    EndpointTransitionNotFound(NodeId),

    InvalidStateDataType(NodeId, u16, TypeRef, data::Revealed),
    InvalidStateDataValue(NodeId, u16, TypeRef, Vec<u8>),

    /// invalid bulletproofs in {0}:{1}: {2}
    InvalidBulletproofs(NodeId, u16, secp256k1zkp::Error),

    ScriptFailure(NodeId),
}

#[derive(Clone, PartialEq, Eq, Debug, Display, From, StrictEncode, StrictDecode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
// TODO #44: (v0.3) convert to detailed descriptions using doc_comments
#[display(Debug)]
pub enum Warning {
    EndpointDuplication(NodeId, SealEndpoint),
    EndpointTransitionSealNotFound(NodeId, SealEndpoint),
    ExcessiveNode(NodeId),
}

#[derive(Clone, PartialEq, Eq, Debug, Display, From, StrictEncode, StrictDecode)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
// TODO #44: (v0.3) convert to detailed descriptions using doc_comments
#[display(Debug)]
pub enum Info {
    UncheckableConfidentialStateData(NodeId, u16),
}

pub struct Validator<'consignment, 'resolver, C: Consignment<'consignment>, R: ResolveTx> {
    consignment: &'consignment C,

    status: Status,

    schema_id: SchemaId,
    genesis_id: NodeId,
    contract_id: ContractId,
    node_index: BTreeMap<NodeId, &'consignment dyn Node>,
    anchor_index: BTreeMap<NodeId, &'consignment Anchor<lnpbp4::MerkleProof>>,
    end_transitions: Vec<(&'consignment dyn Node, BundleId)>,
    validation_index: BTreeSet<NodeId>,

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
        let mut anchor_index = BTreeMap::<NodeId, &Anchor<lnpbp4::MerkleProof>>::new();
        for (anchor, bundle) in consignment.anchored_bundles() {
            if !TransitionBundle::validate(&bundle) {
                status.add_failure(Failure::BundleInvalid(bundle.bundle_id()));
            }
            for transition in bundle.known_transitions() {
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
                if !transition
                    .to_confiential_seals()
                    .contains(&seal_endpoint.commit_conceal())
                {
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
                    .count()
                    > 0
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
        } else if schema.root_id != default!() {
            self.status
                .add_failure(Failure::SchemaRootRequired(schema.root_id));
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
        anchor: &'consignment Anchor<lnpbp4::MerkleProof>,
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
                    .verify(self.contract_id, bundle_id.into(), witness_tx.clone())
                    .is_ok()
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
        witness_tx: &Transaction,
        node_id: NodeId,
        ancestor_id: NodeId,
        assignment_type: schema::OwnedRightType,
        variant: &'consignment TypedAssignments,
        seal_index: u16,
    ) {
        // Getting bitcoin transaction outpoint for the current ancestor ... ->
        if let Some(outpoint) = match (
            variant.revealed_seal_at(seal_index),
            self.anchor_index.get(&ancestor_id),
        ) {
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
                Some(bitcoin::OutPoint::new(txid, vout))
            }
            (Ok(Some(_)), None) => {
                // This can't happen, since if we have a node in the index
                // and the node is not genesis, we always have an anchor
                unreachable!()
            }
            (Ok(Some(seal)), Some(anchor)) => Some(seal.outpoint_or(anchor.txid)), /* -> ... so we can check that the bitcoin transaction
                                                                                    * references it as one of its inputs */
        } {
            if !witness_tx
                .input
                .iter()
                .any(|txin| txin.previous_output == outpoint)
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

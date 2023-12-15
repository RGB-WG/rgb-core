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

use bp::seals::txout::{CloseMethod, ExplicitSeal, TxoSeal, Witness};
use bp::{dbc, Outpoint, Tx, Txid};
use commit_verify::mpc;
use single_use_seals::SealWitness;

use super::status::{Failure, Warning};
use super::{CheckedConsignment, ConsignmentApi, Status, Validity, VirtualMachine};
use crate::vm::AluRuntime;
use crate::{
    AltLayer1, Anchor, AnchorSet, BundleId, ContractId, Layer1, OpId, OpRef, Operation, Opout,
    Schema, SchemaId, SchemaRoot, Script, SubSchema, Transition, TransitionBundle, TypedAssigns,
    WitnessId,
};

#[derive(Clone, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum TxResolverError {
    /// transaction {0} is not mined
    Unknown(Txid),
    /// unable to retriev transaction {0}, {1}
    Other(Txid, String),
}

pub trait ResolveTx {
    fn resolve_bp_tx(&self, layer1: Layer1, txid: Txid) -> Result<Tx, TxResolverError>;
}

pub struct Validator<'consignment, 'resolver, C: ConsignmentApi, R: ResolveTx> {
    consignment: CheckedConsignment<'consignment, C>,

    status: Status,

    schema_id: SchemaId,
    genesis_id: OpId,
    contract_id: ContractId,
    layers1: BTreeSet<Layer1>,

    validated_op_seals: BTreeSet<OpId>,
    validated_op_state: BTreeSet<OpId>,

    vm: Box<dyn VirtualMachine + 'consignment>,
    resolver: &'resolver R,
}

impl<'consignment, 'resolver, C: ConsignmentApi, R: ResolveTx>
    Validator<'consignment, 'resolver, C, R>
{
    fn init(consignment: &'consignment C, resolver: &'resolver R) -> Self {
        // We use validation status object to store all detected failures and
        // warnings
        let mut status = Status::default();
        let vm = match consignment.schema().script {
            Script::AluVM(ref lib) => {
                Box::new(AluRuntime::new(lib)) as Box<dyn VirtualMachine + 'consignment>
            }
        };
        let consignment = CheckedConsignment::new(consignment);

        // Frequently used computation-heavy data
        let genesis = consignment.genesis();
        let genesis_id = genesis.id();
        let contract_id = genesis.contract_id();
        let schema_id = genesis.schema_id;

        // Collect all endpoint transitions.
        // This is pretty simple operation; it takes a lot of code because we would like
        // to detect any potential issues with the consignment structure and notify user
        // about them (in form of generated warnings)
        for (bundle_id, seal_endpoint) in consignment.terminals() {
            let Some(anchored_bundle) = consignment.anchored_bundle(bundle_id) else {
                status.add_failure(Failure::TerminalBundleAbsent(bundle_id));
                continue;
            };
            for (opid, transition) in &anchored_bundle.bundle.known_transitions {
                // Checking for endpoint definition duplicates
                if !transition
                    .assignments
                    .values()
                    .flat_map(TypedAssigns::to_confidential_seals)
                    .any(|seal| seal == seal_endpoint)
                {
                    // We generate just a warning here because it's up to a user to decide whether
                    // to accept consignment with wrong endpoint list
                    status.add_warning(Warning::TerminalSealAbsent(*opid, seal_endpoint));
                }
            }
        }

        // Validation index is used to check that all transitions presented in the
        // consignment were validated. Also, we use it to avoid double schema
        // validations for transitions.
        let validated_op_state = BTreeSet::<OpId>::new();
        let validated_op_seals = BTreeSet::<OpId>::new();

        let mut layers1 = bset! { Layer1::Bitcoin };
        layers1.extend(genesis.alt_layers1.iter().map(AltLayer1::layer1));

        Self {
            consignment,
            status,
            schema_id,
            genesis_id,
            contract_id,
            layers1,
            validated_op_state,
            validated_op_seals,
            vm,
            resolver,
        }
    }

    /// Validation procedure takes a schema object, root schema (if any),
    /// resolver function returning transaction and its fee for a given
    /// transaction id, and returns a validation object listing all detected
    /// failures, warnings and additional information.
    ///
    /// When a failure detected, validation is not stopped; the failure is
    /// logged into the status object, but the validation continues for the
    /// rest of the consignment data. This can help it debugging and
    /// detecting all problems with the consignment.
    pub fn validate(consignment: &'consignment C, resolver: &'resolver R, testnet: bool) -> Status {
        let mut validator = Validator::init(consignment, resolver);
        // If the network mismatches there is no point in validating the contract since
        // all witness transactions will be missed.
        if testnet != validator.consignment.genesis().testnet {
            validator
                .status
                .add_failure(Failure::NetworkMismatch(testnet));
            return validator.status;
        }

        validator.validate_schema(consignment.schema());
        // We must return here, since if the schema is not valid there is no reason to
        // validate contract nodes against it: it will produce a plenty of errors.
        if validator.status.validity() == Validity::Invalid {
            return validator.status;
        }

        validator.validate_commitments();
        // We must return here, since if there were no proper commitments, it is
        // pointless to validate the contract state.
        if validator.status.validity() == Validity::Invalid {
            return validator.status;
        }

        validator.validate_logic(consignment.schema());
        // Done. Returning status report with all possible failures, issues, warnings
        // and notifications about transactions we were unable to obtain.
        validator.status
    }

    // *** PART I: Schema validation
    fn validate_schema(&mut self, schema: &SubSchema) { self.status += schema.verify(); }

    // *** PART II: Validating business logic
    fn validate_logic<Root: SchemaRoot>(&mut self, schema: &'consignment Schema<Root>) {
        // [VALIDATION]: Making sure that we were supplied with the schema
        //               that corresponds to the schema of the contract genesis
        if schema.schema_id() != self.schema_id {
            self.status.add_failure(Failure::SchemaMismatch {
                expected: self.schema_id,
                actual: schema.schema_id(),
            });
            // Unlike other failures, here we return immediately, since there is no point
            // to validate all consignment data against an invalid schema: it will result in
            // a plenty of meaningless errors
            return;
        }

        // [VALIDATION]: Validate genesis
        self.status += schema.validate_state(
            &self.consignment,
            OpRef::Genesis(self.consignment.genesis()),
            self.vm.as_ref(),
        );
        self.validated_op_state.insert(self.genesis_id);

        // [VALIDATION]: Iterating over each endpoint, reconstructing operation
        //               graph up to genesis for each one of them.
        // NB: We are not aiming to validate the consignment as a whole, but instead
        // treat it as a superposition of subgraphs, one for each endpoint; and validate
        // them independently.
        for (bundle_id, _) in self.consignment.terminals() {
            let Some(anchored_bundle) = self.consignment.anchored_bundle(bundle_id) else {
                // We already checked and errored here during the terminal validation, so just
                // skipping.
                continue;
            };
            for transition in anchored_bundle.bundle.known_transitions.values() {
                self.validate_logic_on_route(schema, transition);
            }
        }
    }

    fn validate_logic_on_route<Root: SchemaRoot>(
        &mut self,
        schema: &Schema<Root>,
        transition: &Transition,
    ) {
        let mut queue: VecDeque<OpRef> = VecDeque::new();

        // Instead of constructing complex graph structures or using a recursions we
        // utilize queue to keep the track of the upstream (ancestor) nodes and make
        // sure that ve have validated each one of them up to genesis. The graph is
        // valid when each of its nodes and each of its edges is valid, i.e. when all
        // individual nodes has passed validation against the schema (we track
        // that fact with `validation_index`) and each of the operation ancestor state
        // change to a given operation is valid against the schema + committed
        // into bitcoin transaction graph with proper anchor. That is what we are
        // checking in the code below:
        queue.push_back(OpRef::Transition(transition));
        while let Some(operation) = queue.pop_front() {
            let opid = operation.id();

            if operation.contract_id() != self.contract_id {
                self.status
                    .add_failure(Failure::ContractMismatch(opid, operation.contract_id()));
                continue;
            }

            if !self.validated_op_seals.contains(&opid) {
                self.status.add_failure(Failure::SealsUnvalidated(opid));
            }
            // [VALIDATION]: Verify operation against the schema and scripts
            self.status += schema.validate_state(&self.consignment, operation, self.vm.as_ref());
            if !self.validated_op_state.insert(opid) {
                self.status.add_failure(Failure::CyclicGraph(opid));
            }

            match operation {
                OpRef::Genesis(_) => {
                    // nothing to add to the queue here
                }
                OpRef::Transition(transition) => {
                    // Now, we must collect all parent nodes and add them to the verification queue
                    let parent_nodes = transition.inputs.iter().filter_map(|input| {
                        self.consignment.operation(input.prev_out.op).or_else(|| {
                            self.status
                                .add_failure(Failure::OperationAbsent(input.prev_out.op));
                            None
                        })
                    });

                    queue.extend(parent_nodes);
                }
                OpRef::Extension(extension) => {
                    for (valency, prev_id) in &extension.redeemed {
                        let Some(prev_op) = self.consignment.operation(*prev_id) else {
                            self.status.add_failure(Failure::ValencyNoParent {
                                opid,
                                prev_id: *prev_id,
                                valency: *valency,
                            });
                            continue;
                        };

                        if !prev_op.valencies().contains(valency) {
                            self.status.add_failure(Failure::NoPrevValency {
                                opid,
                                prev_id: *prev_id,
                                valency: *valency,
                            });
                            continue;
                        }

                        queue.push_back(prev_op);
                    }
                }
            }
        }
    }

    // *** PART III: Validating single-use-seals
    fn validate_commitments(&mut self) {
        for bundle_id in self.consignment.bundle_ids() {
            let Some(anchored_bundle) = self.consignment.anchored_bundle(bundle_id) else {
                self.status.add_failure(Failure::BundleAbsent(bundle_id));
                continue;
            };

            let layer1 = anchored_bundle.anchor.layer1();

            // For now we use just Bitcoin and Liquid as layer1, but in the
            // future we may have more validation routes for other types of
            // layer1 structure.
            let witness_id = anchored_bundle.anchor.witness_id();
            let anchors = match &anchored_bundle.anchor {
                Anchor::Bitcoin(anchor) | Anchor::Liquid(anchor) => anchor,
            };
            let bundle = &anchored_bundle.bundle;

            // [VALIDATION]: We validate that the seals were properly defined on BP-type layers
            let (seals, input_map) = self.validate_seal_definitions(layer1, witness_id, bundle);

            // [VALIDATION]: We validate that the seals were properly closed on BP-type layers
            let Some(witness_tx) = self.validate_commitments_bp(layer1, &seals, bundle_id, anchors)
            else {
                continue;
            };

            // [VALIDATION]: We validate bundle commitments to the input map
            self.validate_bundle_commitments(bundle_id, bundle, witness_tx, input_map);
        }
    }

    /// Validates that the transition bundle is internally consistent: inputs of
    /// its state transitions correspond to the way how they are committed
    /// in the input map of the bundle; and these inputs are real inputs of
    /// the transaction.
    fn validate_bundle_commitments(
        &mut self,
        bundle_id: BundleId,
        bundle: &TransitionBundle,
        witness_tx: Tx,
        input_map: BTreeMap<OpId, BTreeSet<Outpoint>>,
    ) {
        for (vin, opid) in &bundle.input_map {
            let Some(outpoints) = input_map.get(opid) else {
                self.status
                    .add_failure(Failure::BundleExtraTransition(bundle_id, *opid));
                continue;
            };
            let Some(input) = witness_tx.inputs.get(vin.to_usize()) else {
                self.status.add_failure(Failure::BundleInvalidInput(
                    bundle_id,
                    *opid,
                    witness_tx.txid(),
                ));
                continue;
            };
            if !outpoints.contains(&input.prev_output) {
                self.status.add_failure(Failure::BundleInvalidCommitment(
                    bundle_id,
                    *vin,
                    witness_tx.txid(),
                    *opid,
                ));
            }
        }
    }

    /// Bitcoin- and liquid-specific commitment validation using deterministic
    /// bitcoin commitments with opret and tapret schema.
    fn validate_commitments_bp(
        &mut self,
        layer1: Layer1,
        seals: impl AsRef<[ExplicitSeal<Txid>]>,
        bundle_id: BundleId,
        anchors: &AnchorSet,
    ) -> Option<Tx> {
        let Some(txid) = anchors.txid() else {
            self.status
                .add_failure(Failure::AnchorSetInvalid(bundle_id));
            return None;
        };

        // Check that the anchor is committed into a transaction spending all of the
        // transition inputs.
        match self.resolver.resolve_bp_tx(layer1, txid) {
            Err(_) => {
                // We wre unable to retrieve corresponding transaction, so can't check.
                // Reporting this incident and continuing further. Why this happens? No
                // connection to Bitcoin Core, Electrum or other backend etc. So this is not a
                // failure in a strict sense, however we can't be sure that the consignment is
                // valid. That's why we keep the track of such information in a separate place
                // (`unresolved_txids` field of the validation status object).
                self.status.unresolved_txids.push(txid);
                // This also can mean that there is no known transaction with the id provided by
                // the anchor, i.e. consignment is invalid. We are proceeding with further
                // validation in order to detect the rest of problems (and reporting the
                // failure!)
                self.status.add_failure(Failure::SealNoWitnessTx(txid));
                None
            }
            Ok(witness_tx) => {
                let (tapret, opret) = anchors.as_split();

                let tapret_seals = seals
                    .as_ref()
                    .iter()
                    .filter(|seal| seal.method() == CloseMethod::TapretFirst);
                if let Some(tapret) = tapret {
                    let witness = Witness::with(witness_tx.clone(), tapret.clone());
                    self.validate_seal_closing_bp(tapret_seals, witness, bundle_id, tapret)
                } else if tapret_seals.count() > 0 {
                    self.status.add_warning(Warning::UnclosedSeals(bundle_id));
                }

                let opret_seals = seals
                    .as_ref()
                    .iter()
                    .filter(|seal| seal.method() == CloseMethod::OpretFirst);
                if let Some(opret) = opret {
                    let witness = Witness::with(witness_tx.clone(), opret.clone());
                    self.validate_seal_closing_bp(opret_seals, witness, bundle_id, opret)
                } else if opret_seals.count() > 0 {
                    self.status.add_warning(Warning::UnclosedSeals(bundle_id));
                }
                Some(witness_tx)
            }
        }
    }

    /// Single-use-seal definition validation.
    ///
    /// Takes state transition, extracts all seals from its inputs and makes
    /// sure they are defined or a correct layer1.
    fn validate_seal_definitions(
        &mut self,
        layer1: Layer1,
        witness_id: WitnessId,
        bundle: &TransitionBundle,
    ) -> (Vec<ExplicitSeal<Txid>>, BTreeMap<OpId, BTreeSet<Outpoint>>) {
        let mut input_map: BTreeMap<OpId, BTreeSet<Outpoint>> = bmap!();
        let mut seals = vec![];
        for (opid, transition) in &bundle.known_transitions {
            let opid = *opid;

            if !self.validated_op_seals.insert(opid) {
                self.status.add_failure(Failure::CyclicGraph(opid));
            }

            // Checking that witness transaction closes seals defined by transition previous
            // outputs.
            for input in &transition.inputs {
                let Opout { op, ty, no } = input.prev_out;

                let Some(prev_op) = self.consignment.operation(op) else {
                    // Node, referenced as the ancestor, was not found in the consignment.
                    // Usually this means that the consignment data are broken
                    self.status.add_failure(Failure::OperationAbsent(op));
                    continue;
                };

                let Some(variant) = prev_op.assignments_by_type(ty) else {
                    self.status.add_failure(Failure::NoPrevState {
                        opid,
                        prev_id: op,
                        state_type: ty,
                    });
                    continue;
                };

                let Ok(seal) = variant.revealed_seal_at(no) else {
                    self.status
                        .add_failure(Failure::NoPrevOut(opid, input.prev_out));
                    continue;
                };
                let Some(seal) = seal else {
                    // Everything is ok, but we have incomplete data (confidential), thus can't do a
                    // full verification and have to report the failure
                    self.status
                        .add_failure(Failure::ConfidentialSeal(input.prev_out));
                    continue;
                };

                if seal.layer1() != layer1 {
                    self.status.add_failure(Failure::SealWitnessLayer1Mismatch {
                        seal: seal.layer1(),
                        anchor: layer1,
                    });
                    continue;
                }
                if !self.layers1.contains(&seal.layer1()) {
                    self.status
                        .add_failure(Failure::SealLayerMismatch(seal.layer1(), seal));
                    continue;
                }

                let seal = seal
                    .try_to_output_seal(witness_id)
                    .expect("method must be called only on BP-compatible layer 1")
                    .reduce_to_bp()
                    .expect("method must be called only on BP-compatible layer 1");
                seals.push(seal);
                input_map
                    .entry(opid)
                    .or_default()
                    .insert(Outpoint::new(seal.txid, seal.vout));
            }
        }
        (seals, input_map)
    }

    /// Single-use-seal closing validation.
    ///
    /// Checks that the set of seals is closed over the message, which is
    /// multi-protocol commitment, by utilizing witness, consisting of
    /// transaction with deterministic bitcoin commitments (defined by
    /// generic type `Dbc`) and extra-transaction data, which are taken from
    /// anchors DBC proof.
    ///
    /// Additionally checks that the provided message contains commitment to the
    /// bundle under the current contract.
    fn validate_seal_closing_bp<'seal, 'temp, Seal: TxoSeal + 'seal, Dbc: dbc::Proof>(
        &mut self,
        seals: impl IntoIterator<Item = &'seal Seal>,
        witness: Witness<Dbc>,
        bundle_id: BundleId,
        anchor: &'temp dbc::Anchor<mpc::MerkleProof, Dbc>,
    ) {
        let message = mpc::Message::from(bundle_id);
        // [VALIDATION]: Checking anchor MPC commitment
        match anchor.convolve(self.contract_id, message) {
            Err(err) => {
                // The operation is not committed to bitcoin transaction graph!
                // Ultimate failure. But continuing to detect the rest (after reporting it).
                self.status
                    .add_failure(Failure::MpcInvalid(bundle_id, witness.txid, err));
            }
            Ok(commitment) => {
                // [VALIDATION]: CHECKING SINGLE-USE-SEALS
                witness
                    .verify_many_seals(seals, &commitment)
                    .map_err(|err| {
                        self.status.add_failure(Failure::SealsInvalid(
                            bundle_id,
                            witness.txid,
                            err.to_string(),
                        ));
                    })
                    .ok();
            }
        }
    }
}

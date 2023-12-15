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

use std::collections::{BTreeSet, VecDeque};

use bp::seals::txout::{CloseMethod, TxoSeal, Witness};
use bp::{dbc, Tx, Txid};
use commit_verify::mpc;
use single_use_seals::SealWitness;

use super::status::{Failure, Warning};
use super::{CheckedConsignment, ConsignmentApi, Status, Validity, VirtualMachine};
use crate::vm::AluRuntime;
use crate::{
    AltLayer1, Anchor, AnchorSet, BundleId, ContractId, GenesisSeal, Layer1, OpId, OpRef,
    Operation, Opout, Schema, SchemaId, SchemaRoot, Script, SubSchema, Transition,
    TransitionBundle, TypedAssigns,
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

pub struct Validator<'consignment, 'vm, 'resolver, C: ConsignmentApi, R: ResolveTx> {
    consignment: CheckedConsignment<'consignment, C>,

    status: Status,

    schema_id: SchemaId,
    genesis_id: OpId,
    contract_id: ContractId,
    layers1: BTreeSet<Layer1>,
    end_transitions: Vec<(&'consignment Transition, BundleId)>,
    validated_op_state: BTreeSet<OpId>,

    vm: Box<dyn VirtualMachine + 'vm>,
    resolver: &'resolver R,
}

impl<'consignment, 'vm, 'resolver, C: ConsignmentApi, R: ResolveTx>
    Validator<'consignment, 'vm, 'resolver, C, R>
{
    fn init(consignment: &'consignment C, resolver: &'resolver R) -> Self {
        // We use validation status object to store all detected failures and
        // warnings
        let mut status = Status::default();
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
        let mut end_transitions = Vec::<(&Transition, BundleId)>::new();
        for (bundle_id, seal_endpoint) in consignment.terminals() {
            for transition in consignment.known_transitions_in_bundle(bundle_id) {
                let opid = transition.id();
                // Checking for endpoint definition duplicates
                if !transition
                    .assignments
                    .values()
                    .flat_map(TypedAssigns::to_confidential_seals)
                    .any(|seal| seal == seal_endpoint)
                {
                    // We generate just a warning here because it's up to a user to decide whether
                    // to accept consignment with wrong endpoint list
                    status.add_warning(Warning::TerminalSealAbsent(opid, seal_endpoint));
                }
                if end_transitions.iter().all(|(n, _)| n.id() != opid) {
                    end_transitions.push((transition, bundle_id));
                }
            }
        }

        // Validation index is used to check that all transitions presented in the
        // consignment were validated. Also, we use it to avoid double schema
        // validations for transitions.
        let validated_op_state = BTreeSet::<OpId>::new();

        let mut layers1 = bset! { Layer1::Bitcoin };
        layers1.extend(genesis.alt_layers1.iter().map(AltLayer1::layer1));

        let vm = match &consignment.schema().script {
            Script::AluVM(lib) => {
                Box::new(AluRuntime::new(lib)) as Box<dyn VirtualMachine + 'consignment>
            }
        };

        Self {
            consignment,
            status,
            schema_id,
            genesis_id,
            contract_id,
            layers1,
            end_transitions,
            validated_op_state,
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
    fn validate_logic<Root: SchemaRoot>(&mut self, schema: &Schema<Root>) {
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
        for (transition, _) in &self.end_transitions {
            self.validate_logic_on_route(schema, transition);
        }

        // Generate warning if some of the transitions within the consignment were
        // excessive (i.e. not part of validation_index). Nothing critical, but still
        // good to report the user that the consignment is not perfect
        for opid in self.consignment.op_ids_except(&self.validated_op_state) {
            self.status.add_warning(Warning::ExcessiveOperation(opid));
        }
    }

    fn validate_logic_on_route<Root: SchemaRoot>(
        &mut self,
        schema: &Schema<Root>,
        transition: &'consignment Transition,
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

            // [VALIDATION]: Verify operation against the schema and scripts
            if !self.validated_op_state.contains(&opid) {
                self.status +=
                    schema.validate_state(&self.consignment, operation, self.vm.as_ref());
                self.validated_op_state.insert(opid);
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
            let anchor = match &anchored_bundle.anchor {
                Anchor::Bitcoin(anchor) | Anchor::Liquid(anchor) => anchor,
            };

            self.validate_commitments_bp(layer1, bundle_id, &anchored_bundle.bundle, anchor);
        }
    }

    fn validate_commitments_bp(
        &mut self,
        layer1: Layer1,
        bundle_id: BundleId,
        bundle: &'consignment TransitionBundle,
        anchor: &'consignment AnchorSet,
    ) {
        let Some(txid) = anchor.txid() else {
            self.status
                .add_failure(Failure::AnchorSetInvalid(bundle_id));
            return;
        };

        let (tapret_seals, opret_seals) = self.validate_seal_definitions(layer1, txid, bundle);

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
            }
            Ok(witness_tx) => {
                let (tapret, opret) = match anchor {
                    AnchorSet::Taptet(tapret) => (Some(tapret), None),
                    AnchorSet::Opret(opret) => (None, Some(opret)),
                    AnchorSet::Dual { tapret, opret } => (Some(tapret), Some(opret)),
                };

                if let Some(tapret) = tapret {
                    let witness = Witness::with(witness_tx.clone(), tapret.clone());
                    self.validate_seal_closing(&tapret_seals, witness, bundle_id, tapret)
                } else if !tapret_seals.is_empty() {
                    self.status.add_warning(Warning::UnclosedSeals(bundle_id));
                }
                if let Some(opret) = opret {
                    let witness = Witness::with(witness_tx, opret.clone());
                    self.validate_seal_closing(&opret_seals, witness, bundle_id, opret)
                } else if !opret_seals.is_empty() {
                    self.status.add_warning(Warning::UnclosedSeals(bundle_id));
                }
            }
        }
    }

    fn validate_seal_definitions(
        &mut self,
        layer1: Layer1,
        witness_txid: Txid,
        bundle: &'consignment TransitionBundle,
    ) -> (Vec<GenesisSeal>, Vec<GenesisSeal>) {
        let (mut tapret_seals, mut opret_seals) = (vec![], vec![]);
        for (opid, transition) in &bundle.known_transitions {
            let opid = *opid;

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
                    .reduce_to_bp()
                    .expect("method must be called only on BP-compatible layer 1")
                    .resolve(witness_txid);
                match seal.method() {
                    CloseMethod::OpretFirst => opret_seals.push(seal),
                    CloseMethod::TapretFirst => tapret_seals.push(seal),
                }
            }
        }
        (tapret_seals, opret_seals)
    }

    /// Single-use-seal closing validation.
    ///
    /// Takes state transition, extracts all seals from its inputs. Checks that
    /// the set of seals is closed over the message, which is multi-protocol
    /// commitment, by utilizing witness, consisting of transaction with
    /// deterministic bitcoin commitments (defined by generic type `Dbc`) and
    /// extra-transaction data, which are taken from anchors DBC proof.
    ///
    /// Additionally checks that the provided message contains commitment to the
    /// bundle under the current contract.
    fn validate_seal_closing<'seal, Seal: TxoSeal + 'seal, Dbc: dbc::Proof>(
        &mut self,
        seals: impl IntoIterator<Item = &'seal Seal>,
        witness: Witness<Dbc>,
        bundle_id: BundleId,
        anchor: &'consignment dbc::Anchor<mpc::MerkleProof, Dbc>,
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

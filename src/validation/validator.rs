// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2019-2024 Dr Maxim Orlovsky. All rights reserved.
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

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::num::NonZeroU32;
use std::rc::Rc;

use bp::dbc::Anchor;
use bp::seals::txout::{CloseMethod, Witness};
use bp::{dbc, Outpoint, Tx, Txid};
use commit_verify::mpc;
use single_use_seals::SealWitness;

use super::status::{Failure, Warning};
use super::{CheckedConsignment, ConsignmentApi, DbcProof, EAnchor, OpRef, Status, Validity};
use crate::operation::seal::ExposedSeal;
use crate::vm::{ContractStateAccess, ContractStateEvolve, OrdOpRef, WitnessOrd};
use crate::{
    validation, BundleId, ChainNet, ContractId, OpId, OpType, Operation, Opout, OutputSeal, Schema,
    SchemaId, TransitionBundle,
};

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum WitnessResolverError {
    /// actual witness id {actual} doesn't match expected id {expected}.
    IdMismatch { actual: Txid, expected: Txid },
    /// witness {0} does not exist.
    Unknown(Txid),
    /// unable to retrieve witness {0}, {1}
    Other(Txid, String),
    /// resolver is for another chain-network pair
    WrongChainNet,
}

pub trait ResolveWitness {
    // TODO: Return with SPV proof data
    fn resolve_pub_witness(&self, witness_id: Txid) -> Result<Tx, WitnessResolverError>;

    fn resolve_pub_witness_ord(&self, witness_id: Txid)
        -> Result<WitnessOrd, WitnessResolverError>;

    fn check_chain_net(&self, chain_net: ChainNet) -> Result<(), WitnessResolverError>;
}

impl<T: ResolveWitness> ResolveWitness for &T {
    fn resolve_pub_witness(&self, witness_id: Txid) -> Result<Tx, WitnessResolverError> {
        ResolveWitness::resolve_pub_witness(*self, witness_id)
    }

    fn resolve_pub_witness_ord(
        &self,
        witness_id: Txid,
    ) -> Result<WitnessOrd, WitnessResolverError> {
        ResolveWitness::resolve_pub_witness_ord(*self, witness_id)
    }

    fn check_chain_net(&self, chain_net: ChainNet) -> Result<(), WitnessResolverError> {
        ResolveWitness::check_chain_net(*self, chain_net)
    }
}

struct CheckedWitnessResolver<R: ResolveWitness> {
    inner: R,
}

impl<R: ResolveWitness> From<R> for CheckedWitnessResolver<R> {
    fn from(inner: R) -> Self { Self { inner } }
}

impl<R: ResolveWitness> ResolveWitness for CheckedWitnessResolver<R> {
    fn resolve_pub_witness(&self, witness_id: Txid) -> Result<Tx, WitnessResolverError> {
        let witness = self.inner.resolve_pub_witness(witness_id)?;
        let actual_id = witness.txid();
        if actual_id != witness_id {
            return Err(WitnessResolverError::IdMismatch {
                actual: actual_id,
                expected: witness_id,
            });
        }
        Ok(witness)
    }

    #[inline]
    fn resolve_pub_witness_ord(
        &self,
        witness_id: Txid,
    ) -> Result<WitnessOrd, WitnessResolverError> {
        self.inner.resolve_pub_witness_ord(witness_id)
    }

    fn check_chain_net(&self, chain_net: ChainNet) -> Result<(), WitnessResolverError> {
        self.inner.check_chain_net(chain_net)
    }
}

pub struct Validator<
    'consignment,
    'resolver,
    S: ContractStateAccess + ContractStateEvolve,
    C: ConsignmentApi,
    R: ResolveWitness,
> {
    consignment: CheckedConsignment<'consignment, C>,

    status: RefCell<Status>,

    schema_id: SchemaId,
    contract_id: ContractId,
    chain_net: ChainNet,

    contract_state: Rc<RefCell<S>>,
    validated_op_seals: RefCell<BTreeSet<OpId>>,
    input_assignments: RefCell<BTreeSet<Opout>>,

    resolver: CheckedWitnessResolver<&'resolver R>,
    safe_height: Option<NonZeroU32>,
}

impl<
        'consignment,
        'resolver,
        S: ContractStateAccess + ContractStateEvolve,
        C: ConsignmentApi,
        R: ResolveWitness,
    > Validator<'consignment, 'resolver, S, C, R>
{
    fn init(
        consignment: &'consignment C,
        resolver: &'resolver R,
        context: S::Context<'_>,
        safe_height: Option<NonZeroU32>,
    ) -> Self {
        // We use validation status object to store all detected failures and
        // warnings
        let status = Status::default();
        let consignment = CheckedConsignment::new(consignment);

        // Frequently used computation-heavy data
        let genesis = consignment.genesis();
        let contract_id = genesis.contract_id();
        let schema_id = genesis.schema_id;
        let chain_net = genesis.chain_net;

        // Prevent repeated validation of single-use seals
        let validated_op_seals = RefCell::new(BTreeSet::<OpId>::new());
        let input_transitions = RefCell::new(BTreeSet::<Opout>::new());

        Self {
            consignment,
            status: RefCell::new(status),
            schema_id,
            contract_id,
            chain_net,
            validated_op_seals,
            input_assignments: input_transitions,
            resolver: CheckedWitnessResolver::from(resolver),
            contract_state: Rc::new(RefCell::new(S::init(context))),
            safe_height,
        }
    }

    /// Validation procedure takes a schema object, root schema (if any),
    /// resolver function returning transaction and its fee for a given
    /// transaction id, and returns a validation object listing all detected
    /// failures, warnings and additional information.
    ///
    /// When a failure detected, validation is not stopped; the failure is
    /// logged into the status object, but the validation continues for the
    /// rest of the consignment data. This can help to debug and detect all
    /// problems with the consignment.
    pub fn validate(
        consignment: &'consignment C,
        resolver: &'resolver R,
        chain_net: ChainNet,
        context: S::Context<'_>,
        safe_height: Option<NonZeroU32>,
    ) -> Status {
        let mut validator = Self::init(consignment, resolver, context, safe_height);
        // If the chain-network pair doesn't match there is no point in validating the contract
        // since all witness transactions will be missed.
        if validator.chain_net != chain_net {
            validator
                .status
                .borrow_mut()
                .add_failure(Failure::ContractChainNetMismatch(chain_net));
            return validator.status.into_inner();
        }
        if resolver.check_chain_net(chain_net).is_err() {
            validator
                .status
                .borrow_mut()
                .add_failure(Failure::ResolverChainNetMismatch(chain_net));
            return validator.status.into_inner();
        }

        validator.validate_schema(consignment.schema());
        // We must return here, since if the schema is not valid there is no reason to
        // validate contract nodes against it: it will produce a plenty of errors.
        if validator.status.borrow().validity() == Validity::Invalid {
            return validator.status.into_inner();
        }

        validator.validate_commitments();
        // We must return here, since if there were no proper commitments, it is
        // pointless to validate the contract state.
        if validator.status.borrow().validity() == Validity::Invalid {
            return validator.status.into_inner();
        }

        validator.validate_logic();
        // Done. Returning status report with all possible failures, issues, warnings
        // and notifications about transactions we were unable to obtain.
        validator.status.into_inner()
    }

    // *** PART I: Schema validation
    fn validate_schema(&mut self, schema: &Schema) {
        *self.status.borrow_mut() += schema.verify(self.consignment.types());
    }

    // *** PART II: Validating business logic
    fn validate_logic(&self) {
        let schema = self.consignment.schema();

        // [VALIDATION]: Making sure that we were supplied with the schema
        //               that corresponds to the schema of the contract genesis
        if schema.schema_id() != self.schema_id {
            self.status
                .borrow_mut()
                .add_failure(Failure::SchemaMismatch {
                    expected: self.schema_id,
                    actual: schema.schema_id(),
                });
            // Unlike other failures, here we return immediately, since there is no point
            // to validate all consignment data against an invalid schema: it will result in
            // a plenty of meaningless errors
            return;
        }

        // [VALIDATION]: Validate genesis
        *self.status.borrow_mut() += schema.validate_state(
            &self.consignment,
            OrdOpRef::Genesis(self.consignment.genesis()),
            self.contract_state.clone(),
        );

        // [VALIDATION]: Iterating over all consignment operations, ordering them according to the
        //               consensus ordering rules.
        let mut ops = BTreeSet::<OrdOpRef>::new();
        let mut unsafe_history_map: HashMap<u32, HashSet<Txid>> = HashMap::new();
        for bundle_id in self.consignment.bundle_ids() {
            let bundle = self
                .consignment
                .bundle(bundle_id)
                .expect("invalid checked consignment");
            let (witness_id, _) = self
                .consignment
                .anchor(bundle_id)
                .expect("invalid checked consignment");
            let witness_ord =
                match self.resolver.resolve_pub_witness_ord(witness_id) {
                    Ok(ord) => ord,
                    Err(err) => {
                        self.status.borrow_mut().add_failure(
                            validation::Failure::WitnessUnresolved(bundle_id, witness_id, err),
                        );
                        // We need to stop validation there since we can't order operations
                        return;
                    }
                };
            if let Some(safe_height) = self.safe_height {
                match witness_ord {
                    WitnessOrd::Mined(witness_pos) => {
                        let witness_height = witness_pos.height();
                        if witness_height > safe_height {
                            unsafe_history_map
                                .entry(witness_height.into())
                                .or_default()
                                .insert(witness_id);
                        }
                    }
                    WitnessOrd::Tentative | WitnessOrd::Ignored | WitnessOrd::Archived => {
                        unsafe_history_map.entry(0).or_default().insert(witness_id);
                    }
                }
            }
            for op in bundle.known_transitions.values() {
                ops.insert(OrdOpRef::Transition(op, witness_id, witness_ord, bundle_id));
                for input in &op.inputs {
                    // We will error in `validate_operations` below on the absent extension from the
                    // consignment.
                    if let Some(OpRef::Extension(extension)) =
                        self.consignment.operation(input.prev_out.op)
                    {
                        let ext = OrdOpRef::Extension(extension, witness_id, witness_ord);
                        // Account only for the first time when extension seal was closed
                        let prev = ops.iter().find(|r| matches!(r, OrdOpRef::Extension(ext, ..) if ext.id() == extension.id())).copied();
                        match prev {
                            Some(old) if old > ext => {
                                ops.remove(&old);
                                ops.insert(ext)
                            }
                            None => ops.insert(ext),
                            _ => {
                                /* the extension is already present in the queue and properly
                                 * ordered, so we have nothing to add or change */
                                true
                            }
                        };
                    }
                }
            }
        }
        if self.safe_height.is_some() {
            self.status
                .borrow_mut()
                .add_warning(Warning::UnsafeHistory(unsafe_history_map));
        }
        for op in ops {
            // We do not skip validating archive operations since after a re-org they may
            // become valid and thus must be added to the contract state and validated
            // beforehand.
            self.validate_operation(op);
        }
    }

    fn validate_operation(&self, operation: OrdOpRef<'consignment>) {
        let schema = self.consignment.schema();
        let opid = operation.id();

        if operation.contract_id() != self.contract_id {
            self.status
                .borrow_mut()
                .add_failure(Failure::ContractMismatch(opid, operation.contract_id()));
        }

        if !self.validated_op_seals.borrow().contains(&opid)
            && operation.op_type() == OpType::StateTransition
        {
            self.status
                .borrow_mut()
                .add_failure(Failure::SealsUnvalidated(opid));
        }
        // [VALIDATION]: Verify operation against the schema and scripts
        *self.status.borrow_mut() +=
            schema.validate_state(&self.consignment, operation, self.contract_state.clone());

        match operation {
            OrdOpRef::Genesis(_) => {
                unreachable!("genesis is not a part of the operation history")
            }
            OrdOpRef::Transition(transition, ..) => {
                for input in &transition.inputs {
                    if self.consignment.operation(input.prev_out.op).is_none() {
                        self.status
                            .borrow_mut()
                            .add_failure(Failure::OperationAbsent(input.prev_out.op));
                    }
                }
            }
            OrdOpRef::Extension(extension, ..) => {
                for (valency, prev_id) in &extension.redeemed {
                    let Some(prev_op) = self.consignment.operation(*prev_id) else {
                        self.status
                            .borrow_mut()
                            .add_failure(Failure::ValencyNoParent {
                                opid,
                                prev_id: *prev_id,
                                valency: *valency,
                            });
                        continue;
                    };

                    if !prev_op.valencies().contains(valency) {
                        self.status
                            .borrow_mut()
                            .add_failure(Failure::NoPrevValency {
                                opid,
                                prev_id: *prev_id,
                                valency: *valency,
                            });
                        continue;
                    }
                }
            }
        }
    }

    // *** PART III: Validating single-use-seals
    fn validate_commitments(&mut self) {
        for bundle_id in self.consignment.bundle_ids() {
            let Some(bundle) = self.consignment.bundle(bundle_id) else {
                self.status
                    .borrow_mut()
                    .add_failure(Failure::BundleAbsent(bundle_id));
                continue;
            };
            let Some((witness_id, anchor)) = self.consignment.anchor(bundle_id) else {
                self.status
                    .borrow_mut()
                    .add_failure(Failure::AnchorAbsent(bundle_id));
                continue;
            };

            // [VALIDATION]: We validate that the seals were properly defined on BP-type layer
            let (seals, input_map) = self.validate_seal_definitions(bundle);

            // [VALIDATION]: We validate that the seals were properly closed on BP-type layer
            let Some(witness_tx) =
                self.validate_seal_commitments(&seals, bundle_id, witness_id, anchor)
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
        &self,
        bundle_id: BundleId,
        bundle: &TransitionBundle,
        pub_witness: Tx,
        input_map: BTreeMap<OpId, BTreeSet<Outpoint>>,
    ) {
        let witness_id = pub_witness.txid();
        for (vin, opids) in &bundle.input_map {
            for opid in opids {
                let Some(outpoints) = input_map.get(opid) else {
                    self.status
                        .borrow_mut()
                        .add_failure(Failure::BundleExtraTransition(bundle_id, *opid));
                    continue;
                };
                let Some(input) = pub_witness.inputs.get(vin.to_usize()) else {
                    self.status
                        .borrow_mut()
                        .add_failure(Failure::BundleInvalidInput(bundle_id, *opid, witness_id));
                    continue;
                };
                if !outpoints.contains(&input.prev_output) {
                    self.status
                        .borrow_mut()
                        .add_failure(Failure::BundleInvalidCommitment(
                            bundle_id, *vin, witness_id, *opid,
                        ));
                }
            }
        }
    }

    /// Bitcoin- and liquid-specific commitment validation using deterministic
    /// bitcoin commitments with opret and tapret schema.
    fn validate_seal_commitments(
        &self,
        seals: impl AsRef<[OutputSeal]>,
        bundle_id: BundleId,
        witness_id: Txid,
        anchor: &EAnchor,
    ) -> Option<Tx> {
        // Check that the anchor is committed into a transaction spending all the
        // transition inputs.
        // Here the method can do SPV proof instead of querying the indexer. The SPV
        // proofs can be part of the consignments, but do not require .
        match self.resolver.resolve_pub_witness(witness_id) {
            Err(err) => {
                // We wre unable to retrieve corresponding transaction, so can't check.
                // Reporting this incident and continuing further. Why this happens? No
                // connection to Bitcoin Core, Electrum or other backend etc. So this is not a
                // failure in a strict sense, however we can't be sure that the consignment is
                // valid.
                // This also can mean that there is no known transaction with the id provided by
                // the anchor, i.e. consignment is invalid. We are proceeding with further
                // validation in order to detect the rest of problems (and reporting the
                // failure!)
                self.status
                    .borrow_mut()
                    .add_failure(Failure::SealNoPubWitness(bundle_id, witness_id, err));
                None
            }
            Ok(pub_witness) => {
                let seals = seals.as_ref();
                match anchor.clone() {
                    EAnchor {
                        mpc_proof,
                        dbc_proof: DbcProof::Tapret(tapret),
                        ..
                    } => {
                        let witness = Witness::with(pub_witness.clone(), tapret);
                        self.validate_seal_closing(seals, bundle_id, witness, mpc_proof)
                    }
                    EAnchor {
                        mpc_proof,
                        dbc_proof: DbcProof::Opret(opret),
                        ..
                    } => {
                        let witness = Witness::with(pub_witness.clone(), opret);
                        self.validate_seal_closing(seals, bundle_id, witness, mpc_proof)
                    }
                }

                Some(pub_witness)
            }
        }
    }

    /// Single-use-seal definition validation.
    ///
    /// Takes state transition, extracts all seals from its inputs and validates them.
    fn validate_seal_definitions(
        &self,
        bundle: &TransitionBundle,
    ) -> (Vec<OutputSeal>, BTreeMap<OpId, BTreeSet<Outpoint>>) {
        let mut input_map: BTreeMap<OpId, BTreeSet<Outpoint>> = bmap!();
        let mut seals = vec![];
        for (opid, transition) in &bundle.known_transitions {
            let opid = *opid;

            if !self.validated_op_seals.borrow_mut().insert(opid) {
                self.status
                    .borrow_mut()
                    .add_failure(Failure::CyclicGraph(opid));
            }

            // Checking that witness transaction closes seals defined by transition previous
            // outputs.
            for input in &transition.inputs {
                let Opout { op, ty, no } = input.prev_out;
                if !self.input_assignments.borrow_mut().insert(input.prev_out) {
                    self.status
                        .borrow_mut()
                        .add_failure(Failure::DoubleSpend(input.prev_out));
                }

                let Some(prev_op) = self.consignment.operation(op) else {
                    // Node, referenced as the ancestor, was not found in the consignment.
                    // Usually this means that the consignment data are broken
                    self.status
                        .borrow_mut()
                        .add_failure(Failure::OperationAbsent(op));
                    continue;
                };

                let Some(variant) = prev_op.assignments_by_type(ty) else {
                    self.status.borrow_mut().add_failure(Failure::NoPrevState {
                        opid,
                        prev_id: op,
                        state_type: ty,
                    });
                    continue;
                };

                let Ok(seal) = variant.revealed_seal_at(no) else {
                    self.status
                        .borrow_mut()
                        .add_failure(Failure::NoPrevOut(opid, input.prev_out));
                    continue;
                };
                let Some(seal) = seal else {
                    // Everything is ok, but we have incomplete data (confidential), thus can't do a
                    // full verification and have to report the failure
                    self.status
                        .borrow_mut()
                        .add_failure(Failure::ConfidentialSeal(input.prev_out));
                    continue;
                };

                let seal = if prev_op.op_type() == OpType::StateTransition {
                    let Some(witness_id) = self.consignment.op_witness_id(op) else {
                        self.status
                            .borrow_mut()
                            .add_failure(Failure::OperationAbsent(op));
                        continue;
                    };
                    seal.to_output_seal_or_default(witness_id)
                } else {
                    seal.to_output_seal()
                        .expect("genesis and state extensions must have explicit seals")
                };

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
    /// anchor's DBC proof.
    ///
    /// Additionally, checks that the provided message contains commitment to
    /// the bundle under the current contract.
    fn validate_seal_closing<'seal, Seal: 'seal, Dbc: dbc::Proof>(
        &self,
        seals: impl IntoIterator<Item = &'seal Seal>,
        bundle_id: BundleId,
        witness: Witness<Dbc>,
        mpc_proof: mpc::MerkleProof,
    ) where
        Witness<Dbc>: SealWitness<Seal, Message = mpc::Commitment>,
    {
        let message = mpc::Message::from(bundle_id);
        let witness_id = witness.txid;
        let anchor = Anchor::new(mpc_proof, witness.proof.clone());
        // [VALIDATION]: Checking anchor MPC commitment
        match anchor.convolve(self.contract_id, message) {
            Err(err) => {
                // The operation is not committed to bitcoin transaction graph!
                // Ultimate failure. But continuing to detect the rest (after reporting it).
                self.status
                    .borrow_mut()
                    .add_failure(Failure::MpcInvalid(bundle_id, witness_id, err));
            }
            Ok(commitment) => {
                // [VALIDATION]: Verify commitment
                let Some(output) = witness
                    .tx
                    .outputs()
                    .find(|out| out.script_pubkey.is_op_return() || out.script_pubkey.is_p2tr())
                else {
                    self.status
                        .borrow_mut()
                        .add_failure(Failure::NoDbcOutput(witness_id));
                    return;
                };
                let output_method = if output.script_pubkey.is_op_return() {
                    CloseMethod::OpretFirst
                } else {
                    CloseMethod::TapretFirst
                };
                let proof_method = witness.proof.method();
                if proof_method != output_method {
                    self.status
                        .borrow_mut()
                        .add_failure(Failure::InvalidProofType(witness_id, proof_method));
                }
                // [VALIDATION]: CHECKING SINGLE-USE-SEALS
                witness
                    .verify_many_seals(seals, &commitment)
                    .map_err(|err| {
                        self.status.borrow_mut().add_failure(Failure::SealsInvalid(
                            bundle_id,
                            witness_id,
                            err.to_string(),
                        ));
                    })
                    .ok();
            }
        }
    }
}

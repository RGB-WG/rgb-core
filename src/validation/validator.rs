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
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use bp::dbc::Anchor;
use bp::seals::txout::{CloseMethod, TxoSeal, Witness};
use bp::{dbc, Outpoint};
use commit_verify::mpc;
use single_use_seals::SealWitness;

use super::status::Failure;
use super::{CheckedConsignment, ConsignmentApi, DbcProof, EAnchor, Status, Validity};
use crate::vm::{
    ContractStateAccess, ContractStateEvolve, OpOrd, OpRef, OpTypeOrd, TxOrd, WitnessOrd,
    XWitnessId, XWitnessTx,
};
use crate::{
    validation, AltLayer1, BundleId, ContractId, Layer1, OpId, OpType, Operation, Opout, Schema,
    SchemaId, TransitionBundle, XChain, XOutpoint, XOutputSeal,
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
    IdMismatch {
        actual: XWitnessId,
        expected: XWitnessId,
    },
    /// witness {0} does not exist.
    Unknown(XWitnessId),
    /// unable to retrieve witness {0}, {1}
    Other(XWitnessId, String),
}

pub trait ResolveWitness {
    // TODO: Return with SPV proof data
    fn resolve_pub_witness(
        &self,
        witness_id: XWitnessId,
    ) -> Result<XWitnessTx, WitnessResolverError>;

    fn resolve_pub_witness_ord(
        &self,
        witness_id: XWitnessId,
    ) -> Result<TxOrd, WitnessResolverError>;
}

impl<T: ResolveWitness> ResolveWitness for &T {
    fn resolve_pub_witness(
        &self,
        witness_id: XWitnessId,
    ) -> Result<XWitnessTx, WitnessResolverError> {
        ResolveWitness::resolve_pub_witness(*self, witness_id)
    }

    fn resolve_pub_witness_ord(
        &self,
        witness_id: XWitnessId,
    ) -> Result<TxOrd, WitnessResolverError> {
        ResolveWitness::resolve_pub_witness_ord(*self, witness_id)
    }
}

struct CheckedWitnessResolver<R: ResolveWitness> {
    inner: R,
}

impl<R: ResolveWitness> From<R> for CheckedWitnessResolver<R> {
    fn from(inner: R) -> Self { Self { inner } }
}

impl<R: ResolveWitness> ResolveWitness for CheckedWitnessResolver<R> {
    fn resolve_pub_witness(
        &self,
        witness_id: XWitnessId,
    ) -> Result<XWitnessTx, WitnessResolverError> {
        let witness = self.inner.resolve_pub_witness(witness_id)?;
        let actual_id = witness.witness_id();
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
        witness_id: XWitnessId,
    ) -> Result<TxOrd, WitnessResolverError> {
        self.inner.resolve_pub_witness_ord(witness_id)
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
    genesis_id: OpId,
    contract_id: ContractId,
    layers1: BTreeSet<Layer1>,

    contract_state: Rc<RefCell<S>>,
    validated_op_seals: RefCell<BTreeSet<OpId>>,
    validated_op_state: RefCell<BTreeSet<OpId>>,

    resolver: CheckedWitnessResolver<&'resolver R>,
}

impl<
    'consignment,
    'resolver,
    S: ContractStateAccess + ContractStateEvolve,
    C: ConsignmentApi,
    R: ResolveWitness,
> Validator<'consignment, 'resolver, S, C, R>
{
    fn init(consignment: &'consignment C, resolver: &'resolver R, context: S::Context<'_>) -> Self {
        // We use validation status object to store all detected failures and
        // warnings
        let status = Status::default();
        let consignment = CheckedConsignment::new(consignment);

        // Frequently used computation-heavy data
        let genesis = consignment.genesis();
        let genesis_id = genesis.id();
        let contract_id = genesis.contract_id();
        let schema_id = genesis.schema_id;

        // Validation index is used to check that all transitions presented in the
        // consignment were validated. Also, we use it to avoid double schema
        // validations for transitions.
        let validated_op_state = RefCell::new(BTreeSet::<OpId>::new());
        let validated_op_seals = RefCell::new(BTreeSet::<OpId>::new());

        let mut layers1 = bset! { Layer1::Bitcoin };
        layers1.extend(genesis.alt_layers1.iter().map(AltLayer1::layer1));

        Self {
            consignment,
            status: RefCell::new(status),
            schema_id,
            genesis_id,
            contract_id,
            layers1,
            validated_op_state,
            validated_op_seals,
            resolver: CheckedWitnessResolver::from(resolver),
            contract_state: Rc::new(RefCell::new(S::init(context))),
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
        testnet: bool,
        context: S::Context<'_>,
    ) -> Status {
        let mut validator = Self::init(consignment, resolver, context);
        // If the network mismatches there is no point in validating the contract since
        // all witness transactions will be missed.
        if testnet != validator.consignment.genesis().testnet {
            validator
                .status
                .borrow_mut()
                .add_failure(Failure::NetworkMismatch(testnet));
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
            OpRef::Genesis(self.consignment.genesis()),
            self.contract_state.clone(),
        );
        self.validated_op_state.borrow_mut().insert(self.genesis_id);

        // [VALIDATION]: Iterating over all consignment operations, ordering them according to the
        //               consensus ordering rules.
        let mut ops = BTreeMap::<OpOrd, OpRef>::new();
        for bundle_id in self.consignment.bundle_ids() {
            let bundle = self
                .consignment
                .bundle(bundle_id)
                .expect("invalid checked consignment");
            let (witness_id, _) = self
                .consignment
                .anchor(bundle_id)
                .expect("invalid checked consignment");
            let pub_ord =
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
            for (opid, op) in &bundle.known_transitions {
                let witness_ord = WitnessOrd {
                    pub_ord,
                    witness_id,
                };
                let mut ord = OpOrd {
                    op_type: OpTypeOrd::Transition,
                    witness_ord,
                    opid: *opid,
                };
                ops.insert(ord, OpRef::Transition(op, witness_id));
                for input in &op.inputs {
                    // We will error in `validate_operations` below on the absent extension from the
                    // consignment.
                    if let Some(OpRef::Extension(extension, _)) =
                        self.consignment.operation(input.prev_out.op)
                    {
                        ord.op_type = OpTypeOrd::Extension(extension.extension_type);
                        ops.insert(ord, OpRef::Extension(extension, witness_id));
                    }
                }
            }
        }
        // TODO: Check that we include all terminal transitions
        for op in ops.into_values() {
            self.validate_operation(op);
        }
    }

    fn validate_operation(&self, operation: OpRef<'consignment>) {
        let schema = self.consignment.schema();
        let opid = operation.id();

        if operation.contract_id() != self.contract_id {
            self.status
                .borrow_mut()
                .add_failure(Failure::ContractMismatch(opid, operation.contract_id()));
        }

        if !self.validated_op_seals.borrow().contains(&opid) &&
            operation.op_type() == OpType::StateTransition
        {
            self.status
                .borrow_mut()
                .add_failure(Failure::SealsUnvalidated(opid));
        }
        // [VALIDATION]: Verify operation against the schema and scripts
        if self.validated_op_state.borrow_mut().insert(opid) {
            *self.status.borrow_mut() +=
                schema.validate_state(&self.consignment, operation, self.contract_state.clone());
        }

        match operation {
            OpRef::Genesis(_) => {
                unreachable!("genesis is not a part of the operation history")
            }
            OpRef::Transition(transition, _) => {
                for input in &transition.inputs {
                    if self.consignment.operation(input.prev_out.op).is_none() {
                        self.status
                            .borrow_mut()
                            .add_failure(Failure::OperationAbsent(input.prev_out.op));
                    }
                }
            }
            OpRef::Extension(extension, _) => {
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

            // [VALIDATION]: We validate that the seals were properly defined on BP-type layers
            let (seals, input_map) = self.validate_seal_definitions(witness_id.layer1(), bundle);

            // [VALIDATION]: We validate that the seals were properly closed on BP-type layers
            let Some(witness_tx) = self.validate_seal_commitments(
                &seals,
                bundle_id,
                witness_id,
                bundle.close_method,
                anchor,
            ) else {
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
        pub_witness: XWitnessTx,
        input_map: BTreeMap<OpId, BTreeSet<XOutpoint>>,
    ) {
        let witness_id = pub_witness.witness_id();
        for (vin, opid) in &bundle.input_map {
            let Some(outpoints) = input_map.get(opid) else {
                self.status
                    .borrow_mut()
                    .add_failure(Failure::BundleExtraTransition(bundle_id, *opid));
                continue;
            };
            let layer1 = pub_witness.layer1();
            let pub_witness = pub_witness.as_reduced_unsafe();
            let Some(input) = pub_witness.inputs.get(vin.to_usize()) else {
                self.status
                    .borrow_mut()
                    .add_failure(Failure::BundleInvalidInput(bundle_id, *opid, witness_id));
                continue;
            };
            if !outpoints.contains(&XChain::with(layer1, input.prev_output)) {
                self.status
                    .borrow_mut()
                    .add_failure(Failure::BundleInvalidCommitment(
                        bundle_id, *vin, witness_id, *opid,
                    ));
            }
        }
    }

    /// Bitcoin- and liquid-specific commitment validation using deterministic
    /// bitcoin commitments with opret and tapret schema.
    fn validate_seal_commitments(
        &self,
        seals: impl AsRef<[XOutputSeal]>,
        bundle_id: BundleId,
        witness_id: XWitnessId,
        close_method: CloseMethod,
        anchor: &EAnchor,
    ) -> Option<XWitnessTx> {
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
                for seal in seals.iter().filter(|seal| seal.method() != close_method) {
                    self.status
                        .borrow_mut()
                        .add_failure(Failure::SealInvalidMethod(bundle_id, *seal));
                }
                match (close_method, anchor.clone()) {
                    (
                        CloseMethod::TapretFirst,
                        EAnchor {
                            mpc_proof,
                            dbc_proof: DbcProof::Tapret(tapret),
                            ..
                        },
                    ) => {
                        let witness = pub_witness.clone().map(|tx| Witness::with(tx, tapret));
                        self.validate_seal_closing(seals, bundle_id, witness, mpc_proof)
                    }
                    (
                        CloseMethod::OpretFirst,
                        EAnchor {
                            mpc_proof,
                            dbc_proof: DbcProof::Opret(opret),
                            ..
                        },
                    ) => {
                        let witness = pub_witness.clone().map(|tx| Witness::with(tx, opret));
                        self.validate_seal_closing(seals, bundle_id, witness, mpc_proof)
                    }
                    (_, _) => {
                        self.status
                            .borrow_mut()
                            .add_failure(Failure::AnchorMethodMismatch(bundle_id));
                    }
                }

                Some(pub_witness)
            }
        }
    }

    /// Single-use-seal definition validation.
    ///
    /// Takes state transition, extracts all seals from its inputs and makes
    /// sure they are defined or a correct layer1.
    fn validate_seal_definitions(
        &self,
        layer1: Layer1,
        bundle: &TransitionBundle,
    ) -> (Vec<XOutputSeal>, BTreeMap<OpId, BTreeSet<XOutpoint>>) {
        let mut input_map: BTreeMap<OpId, BTreeSet<XOutpoint>> = bmap!();
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

                if seal.layer1() != layer1 {
                    self.status
                        .borrow_mut()
                        .add_failure(Failure::SealWitnessLayer1Mismatch {
                            seal: seal.layer1(),
                            anchor: layer1,
                        });
                    continue;
                }
                if !self.layers1.contains(&seal.layer1()) {
                    self.status
                        .borrow_mut()
                        .add_failure(Failure::SealLayerMismatch(seal.layer1(), seal));
                    continue;
                }

                let seal = if prev_op.op_type() == OpType::StateTransition {
                    let Some(witness_id) = self.consignment.op_witness_id(op) else {
                        self.status
                            .borrow_mut()
                            .add_failure(Failure::OperationAbsent(op));
                        continue;
                    };

                    match seal.try_to_output_seal(witness_id) {
                        Ok(seal) => seal,
                        Err(_) => {
                            self.status.borrow_mut().add_failure(
                                Failure::SealWitnessLayer1Mismatch {
                                    seal: seal.layer1(),
                                    anchor: witness_id.layer1(),
                                },
                            );
                            continue;
                        }
                    }
                } else {
                    seal.to_output_seal()
                        .expect("genesis and state extensions must have explicit seals")
                };

                seals.push(seal);
                input_map
                    .entry(opid)
                    .or_default()
                    .insert(seal.map(|seal| Outpoint::new(seal.txid, seal.vout)).into());
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
        witness: XChain<Witness<Dbc>>,
        mpc_proof: mpc::MerkleProof,
    ) where
        XChain<Witness<Dbc>>: SealWitness<Seal, Message = mpc::Commitment>,
    {
        let message = mpc::Message::from(bundle_id);
        let witness_id = witness.witness_id();
        let anchor = Anchor::new(mpc_proof, witness.as_reduced_unsafe().proof.clone());
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

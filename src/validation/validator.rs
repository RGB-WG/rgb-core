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

use std::collections::{BTreeSet, HashMap, HashSet};

use bc::{Tx, Txid};
use commit_verify::mpc;
use seals::txout::Witness;

use super::status::{Failure, Warning};
use super::{
    CheckedConsignment, ConsignmentApi, ContractStateAccess, ContractStateEvolve, FullOpRef,
    Status, Validity, WitnessStatus,
};
use crate::operation::seal::ExposedSeal;
use crate::{validation, ChainNet, ContractId, OpFullType, Operation, Opout, Schema, SchemaId};

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
    fn resolve_pub_witness(&self, witness_id: Txid) -> Result<Tx, WitnessResolverError>;

    fn resolve_pub_witness_ord(
        &self,
        witness_id: Txid,
    ) -> Result<WitnessStatus, WitnessResolverError>;

    fn check_chain_net(&self, chain_net: ChainNet) -> Result<(), WitnessResolverError>;
}

impl<T: ResolveWitness> ResolveWitness for &T {
    fn resolve_pub_witness(&self, witness_id: Txid) -> Result<Tx, WitnessResolverError> {
        ResolveWitness::resolve_pub_witness(*self, witness_id)
    }

    fn resolve_pub_witness_ord(
        &self,
        witness_id: Txid,
    ) -> Result<WitnessStatus, WitnessResolverError> {
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
    ) -> Result<WitnessStatus, WitnessResolverError> {
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

    status: Status,

    schema_id: SchemaId,
    contract_id: ContractId,
    chain_net: ChainNet,

    contract_state: S,
    input_assignments: BTreeSet<Opout>,

    resolver: CheckedWitnessResolver<&'resolver R>,
    safe_height: Option<u32>,
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
        safe_height: Option<u32>,
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

        Self {
            consignment,
            status,
            schema_id,
            contract_id,
            chain_net,
            input_assignments: none!(),
            resolver: CheckedWitnessResolver::from(resolver),
            contract_state: S::init(context),
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
        safe_height: Option<u32>,
    ) -> Status {
        let mut validator = Self::init(consignment, resolver, context, safe_height);
        // If the chain-network pair doesn't match there is no point in validating the contract
        // since all witness transactions will be missed.
        if validator.chain_net != chain_net {
            validator
                .status
                .add_failure(Failure::ContractChainNetMismatch(chain_net));
            return validator.status;
        }
        if resolver.check_chain_net(chain_net).is_err() {
            validator
                .status
                .add_failure(Failure::ResolverChainNetMismatch(chain_net));
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

        validator.validate_logic();
        // Done. Returning status report with all possible failures, issues, warnings
        // and notifications about transactions we were unable to obtain.
        validator.status
    }

    // *** PART I: Schema validation
    fn validate_schema(&mut self, schema: &Schema) {
        self.status += schema.verify(self.consignment.types());
    }

    // *** PART II: Validating business logic
    fn validate_logic(&mut self) {
        let schema = self.consignment.schema();

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
            FullOpRef::Genesis(self.consignment.genesis()),
            &mut self.contract_state,
        );

        // [VALIDATION]: Iterating over all consignment operations
        let mut ops = Vec::<FullOpRef>::new();
        let mut unsafe_history_map: HashMap<u32, HashSet<Txid>> = HashMap::new();
        for transition in self.consignment.transitions() {
            let opid = transition.id();
            let (_, witness_id) = self
                .consignment
                .anchor(opid)
                .expect("invalid checked consignment");
            let witness_status = match self.resolver.resolve_pub_witness_ord(witness_id) {
                Ok(ord) => ord,
                Err(err) => {
                    self.status
                        .add_failure(validation::Failure::WitnessUnresolved(opid, witness_id, err));
                    // We need to stop validation there since we can't order operations
                    return;
                }
            };
            if let Some(safe_height) = self.safe_height {
                match witness_status {
                    WitnessStatus::Mined(witness_height) => {
                        if witness_height > safe_height {
                            unsafe_history_map
                                .entry(witness_height.into())
                                .or_default()
                                .insert(witness_id);
                        }
                    }
                    WitnessStatus::Tentative | WitnessStatus::Ignored | WitnessStatus::Archived => {
                        unsafe_history_map.entry(0).or_default().insert(witness_id);
                    }
                }
            }
            ops.push(FullOpRef::Transition(transition, witness_id, witness_status, opid));
        }
        if self.safe_height.is_some() && !unsafe_history_map.is_empty() {
            self.status
                .add_warning(Warning::UnsafeHistory(unsafe_history_map));
        }

        // Operations are validated in the order they are reported by the consignment API
        for operation in ops {
            // We do not skip validating archive operations since after a re-org they may
            // become valid and thus must be added to the contract state and validated
            // beforehand.
            let opid = operation.id();

            if operation.contract_id() != self.contract_id {
                self.status
                    .add_failure(Failure::ContractMismatch(opid, operation.contract_id()));
            }

            if !self.status.validated_opids.contains(&opid)
                && matches!(operation.full_type(), OpFullType::StateTransition(_))
            {
                self.status.add_failure(Failure::SealsUnvalidated(opid));
            }
            // [VALIDATION]: Verify operation against the schema and scripts
            self.status +=
                schema.validate_state(&self.consignment, operation, &mut self.contract_state);

            match operation {
                FullOpRef::Genesis(_) => {
                    unreachable!("genesis is not a part of the operation history")
                }
                FullOpRef::Transition(transition, ..) => {
                    for input in &transition.inputs {
                        if self.consignment.operation(input.op).is_none() {
                            self.status.add_failure(Failure::OperationAbsent(input.op));
                        }
                    }
                }
            }
        }
    }

    // *** PART III: Validating single-use-seals
    fn validate_commitments(&mut self) {
        for transition in self.consignment.transitions() {
            let opid = transition.id();
            let Some((mpc_proof, witness_id)) = self.consignment.anchor(opid) else {
                self.status.add_failure(Failure::AnchorAbsent(opid));
                continue;
            };

            // [VALIDATION]: We validate that the seals were properly defined on BP-type layer
            let mut seals = vec![];

            if !self.status.validated_opids.insert(opid) {
                self.status.add_failure(Failure::CyclicGraph(opid));
            }

            // Checking that witness transaction closes seals defined by transition previous
            // outputs.
            for input in &transition.inputs {
                let Opout { op, ty, no } = input;
                if !self.input_assignments.insert(input) {
                    self.status.add_failure(Failure::DoubleSpend(input));
                }

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
                    self.status.add_failure(Failure::NoPrevOut(opid, input));
                    continue;
                };
                let Some(seal) = seal else {
                    // Everything is ok, but we have incomplete data (confidential), thus can't do a
                    // full verification and have to report the failure
                    self.status.add_failure(Failure::ConfidentialSeal(input));
                    continue;
                };

                let seal = if prev_op.full_type().is_transition() {
                    let Some(witness_id) = self.consignment.op_witness_id(op) else {
                        self.status.add_failure(Failure::OperationAbsent(op));
                        continue;
                    };
                    seal.to_output_seal_or_default(witness_id)
                } else {
                    seal.to_output_seal()
                        .expect("genesis must have explicit seals")
                };

                seals.push(seal);
            }

            // [VALIDATION]: We validate that the seals were properly closed on BP-type layer
            // Check that the anchor is committed into a transaction spending all the
            // transition inputs.
            // Here the method can do SPV proof instead of querying the indexer. The SPV
            // proofs can be part of the consignments.
            match self.resolver.resolve_pub_witness(witness_id) {
                Err(err) => {
                    // We were unable to retrieve the corresponding transaction, so can't check.
                    // Reporting this incident and continuing further. Why does this happen? No
                    // connection to Bitcoin Core, Electrum or another backend etc. So this is not a
                    // failure in a strict sense, however, we can't be sure that the consignment is
                    // valid.
                    // This also can mean that there is no known transaction with the id provided by
                    // the anchor, i.e., consignment is invalid. We are proceeding with further
                    // validation to detect the rest of the problems (and reporting the failure!)
                    self.status
                        .add_failure(Failure::SealNoPubWitness(opid, witness_id, err));
                }
                Ok(pub_witness) => {
                    let message = mpc::Message::from(opid);
                    let protocol = mpc::ProtocolId::from(self.contract_id);

                    // [VALIDATION]: Checking anchor MPC commitment
                    match mpc_proof.convolve(protocol, message) {
                        Err(err) => {
                            // The operation is not committed to the bitcoin transaction graph!
                            // Ultimate failure. But continuing to detect the rest (after reporting
                            // it).
                            self.status
                                .add_failure(Failure::MpcInvalid(opid, witness_id, err));
                        }
                        Ok(commitment) => {
                            // [VALIDATION]: CHECKING SINGLE-USE-SEALS
                            pub_witness
                                .verify_seals(seals, commitment)
                                .map_err(|err| {
                                    self.status.add_failure(Failure::SealsInvalid(
                                        opid,
                                        witness_id,
                                        err.to_string(),
                                    ));
                                })
                                .ok();
                        }
                    }
                }
            }
        }
    }
}

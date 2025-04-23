// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Designed in 2019-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
// Written in 2024-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association, Switzerland.
// Copyright (C) 2024-2025 LNP/BP Laboratories,
//                         Institute for Distributed and Cognitive Systems (InDCS), Switzerland.
// Copyright (C) 2025 RGB Consortium, Switzerland.
// Copyright (C) 2019-2025 Dr Maxim Orlovsky.
// All rights under the above copyrights are reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
// in compliance with the License. You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied. See the License for the specific language governing permissions and limitations under
// the License.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use amplify::confinement::SmallOrdMap;
use amplify::ByteArray;
use single_use_seals::{PublishedWitness, SealError, SealWitness};
use ultrasonic::{
    AuthToken, CallError, CellAddr, Codex, ContractId, LibRepo, Memory, Operation, Opid, VerifiedOperation,
};

use crate::{RgbSeal, RgbSealDef, LIB_NAME_RGB_CORE};

// TODO: Move to amplify crate
pub enum Step<A, B> {
    Next(A),
    Complete(B),
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_CORE)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "camelCase", bound = "SealDef: serde::Serialize + for<'d> serde::Deserialize<'d>")
)]
pub struct OperationSeals<SealDef: RgbSealDef> {
    pub operation: Operation,
    /// Operation itself contains only AuthToken's, which are a commitments to the seals. Hence, we
    /// have to separately include a full seal definitions next to the operation data.
    pub defined_seals: SmallOrdMap<u16, SealDef>,
}

pub trait ReadOperation: Sized {
    type SealDef: RgbSealDef;
    type WitnessReader: ReadWitness<SealDef = Self::SealDef, OperationReader = Self>;
    fn read_operation(self) -> Option<(OperationSeals<Self::SealDef>, Self::WitnessReader)>;
}

pub trait ReadWitness: Sized {
    type SealDef: RgbSealDef;
    type OperationReader: ReadOperation<SealDef = Self::SealDef, WitnessReader = Self>;
    #[allow(clippy::type_complexity)]
    fn read_witness(self) -> Step<(SealWitness<<Self::SealDef as RgbSealDef>::Src>, Self), Self::OperationReader>;
}

/// API exposed by the contract required for evaluating and verifying the contract state (see
/// [`ContractVerify`]).
///
/// NB: `apply_operation` is called only after `apply_witness`.
pub trait ContractApi<Seal: RgbSeal> {
    fn contract_id(&self) -> ContractId;
    fn codex(&self) -> &Codex;
    fn repo(&self) -> &impl LibRepo;
    fn memory(&self) -> &impl Memory;
    fn is_known(&self, opid: Opid) -> bool;
    fn apply_operation(&mut self, op: VerifiedOperation, seals: SmallOrdMap<u16, Seal::Definition>);
    fn apply_witness(&mut self, opid: Opid, witness: SealWitness<Seal>);
}

// We use dedicated trait here in order to prevent overriding of the implementation in client
// libraries
pub trait ContractVerify<Seal: RgbSeal>: ContractApi<Seal> {
    // TODO: Support multi-thread mode for parallel processing of unrelated operations
    fn evaluate<R: ReadOperation<SealDef = Seal::Definition>>(
        &mut self,
        mut reader: R,
    ) -> Result<(), VerificationError<Seal>> {
        let contract_id = self.contract_id();
        let codex_id = self.codex().codex_id();

        let mut first = true;
        let mut seals = BTreeMap::<CellAddr, Seal>::new();

        while let Some((mut header, mut witness_reader)) = reader.read_operation() {
            // Genesis can't commit to the contract id since the contract doesn't exist yet; thus, we have to
            // apply this little trick
            if first {
                if header.operation.contract_id.to_byte_array() != codex_id.to_byte_array() {
                    return Err(VerificationError::NoCodexCommitment);
                }
                header.operation.contract_id = contract_id;
            }
            let opid = header.operation.opid();

            // We need to check that all seal definitions strictly match operation-defined destructible cells
            let defined = header
                .operation
                .destructible
                .iter()
                .map(|cell| cell.auth)
                .collect::<BTreeSet<_>>();
            let reported = header
                .defined_seals
                .values()
                .map(|seal| seal.auth_token())
                .collect::<BTreeSet<_>>();
            // It is a subset and not equal set since some of the seals might be unknown to us: we know their
            // commitment auth token, but do not know definition.
            if !reported.is_subset(&defined) {
                let sources = header
                    .defined_seals
                    .iter()
                    .map(|(pos, seal)| (*pos, seal.to_string()))
                    .collect();
                return Err(VerificationError::SealsDefinitionMismatch { opid, reported, defined, sources });
            }

            // Collect single-use seal closings by the operation
            let mut closed_seals = Vec::<Seal>::new();
            for input in &header.operation.destroying {
                let seal = seals
                    .remove(&input.addr)
                    .ok_or(VerificationError::SealUnknown(input.addr))?;
                closed_seals.push(seal);
            }

            // If the operation was validated before, we need to skip its validation, since its inputs are not a
            // part of the state anymore.
            let operation = if !self.is_known(opid) {
                // Verify the operation
                let verified = self
                    .codex()
                    .verify(contract_id, header.operation, self.memory(), self.repo())?;
                Some(verified)
            } else {
                None
            };

            // This convoluted logic happens since we use a state machine which ensures the client can't lie to
            // the verifier
            let mut witness_count = 0usize;
            // Now we can add operation-defined seals to the set of known seals
            let mut seal_sources: BTreeSet<_> = header
                .defined_seals
                .iter()
                .filter_map(|(pos, seal)| seal.to_src().map(|seal| (CellAddr::new(opid, *pos), seal)))
                .collect();

            loop {
                // An operation may have multiple witnesses (like multiple commitment transactions in lightning
                // channel).
                match witness_reader.read_witness() {
                    Step::Next((witness, w)) => {
                        let msg = opid.to_byte_array();
                        witness
                            .verify_seals_closing(&closed_seals, msg.into())
                            .map_err(|e| VerificationError::SealsNotClosed(witness.published.pub_id(), opid, e))?;

                        //  Each witness actually produces its own set of witness-output based seal sources.
                        let pub_id = witness.published.pub_id();
                        let iter = header
                            .defined_seals
                            .iter()
                            .filter(|(_, seal)| seal.to_src().is_none())
                            .map(|(pos, seal)| (CellAddr::new(opid, *pos), seal.resolve(pub_id)));
                        seal_sources.extend(iter);

                        self.apply_witness(opid, witness);
                        witness_reader = w;
                    }
                    Step::Complete(r) => {
                        reader = r;
                        break;
                    }
                }
                witness_count += 1;
            }

            if !closed_seals.is_empty() && witness_count == 0 {
                return Err(VerificationError::NoWitness(opid));
            }

            seals.extend(seal_sources);
            if first {
                first = false
            } else if let Some(operation) = operation {
                self.apply_operation(operation, header.defined_seals);
            }
        }

        Ok(())
    }
}

impl<Seal: RgbSeal, C: ContractApi<Seal>> ContractVerify<Seal> for C {}

// TODO: Find a way to do Debug and Clone implementation
#[derive(Debug, Display, From)]
#[display(doc_comments)]
pub enum VerificationError<Seal: RgbSeal> {
    /// genesis does not commit to the codex id; a wrong contract genesis is used.
    NoCodexCommitment,

    /// no witness known for the operation {0}.
    NoWitness(Opid),

    /// single-use seals are not closed properly with witness {0} for operation {1}.
    ///
    /// Details: {2}
    SealsNotClosed(<Seal::PubWitness as PublishedWitness<Seal>>::PubId, Opid, SealError<Seal>),

    /// unknown seal definition for cell address {0}.
    SealUnknown(CellAddr),

    /// seals, reported to be defined by the operation {opid}, do match the assignments in the
    /// operation.
    ///
    /// Actual operation seals from the assignments: {defined:#?}
    ///
    /// Reported seals: {reported:#?}
    ///
    /// Sources for the reported seals: {sources:#?}
    SealsDefinitionMismatch {
        opid: Opid,
        reported: BTreeSet<AuthToken>,
        defined: BTreeSet<AuthToken>,
        sources: BTreeMap<u16, String>,
    },

    #[from]
    #[display(inner)]
    Vm(CallError),
}

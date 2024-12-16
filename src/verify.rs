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

use alloc::collections::BTreeMap;
use core::error::Error;
use std::collections::BTreeSet;

use amplify::confinement::SmallVec;
use amplify::Wrapper;
use single_use_seals::{PublishedWitness, SealError, SealWitness, SingleUseSeal};
use ultrasonic::{CallError, CellAddr, Codex, ContractId, LibRepo, Memory, Operation, Opid};

use crate::{SonicSeal, LIB_NAME_RGB_CORE};

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
    serde(
        rename_all = "camelCase",
        bound = "Seal: serde::Serialize + for<'d> serde::Deserialize<'d>, Seal::PubWitness: serde::Serialize + \
                 for<'d> serde::Deserialize<'d>, Seal::CliWitness: serde::Serialize + for<'d> serde::Deserialize<'d>"
    )
)]
pub struct OperationSeals<Seal: SonicSeal> {
    pub operation: Operation,
    /// Operation itself contains only AuthToken's, which are a commitments to the seals. Hence, we
    /// have to separately include a full seal definitions next to the operation data.
    pub defined_seals: SmallVec<Seal>,
}

pub trait ReadOperation: Sized {
    type Seal: SonicSeal;
    type WitnessReader: ReadWitness<Seal = Self::Seal, OpReader = Self, Error = Self::Error>;
    type Error: Error;
    fn read_operation(self) -> Result<Option<(OperationSeals<Self::Seal>, Self::WitnessReader)>, Self::Error>;
}

pub trait ReadWitness: Sized {
    type Seal: SonicSeal;
    type OpReader: ReadOperation<Seal = Self::Seal, WitnessReader = Self, Error = Self::Error>;
    type Error: Error;
    fn read_witness(self) -> Result<Step<(SealWitness<Self::Seal>, Self), Self::OpReader>, Self::Error>;
}

/// API exposed by the contract required for evaluating and verifying the contract state (see
/// [`ContractVerify`]).
///
/// NB: `apply_operation` is called only after `apply_witness`.
pub trait ContractApi<Seal: SonicSeal> {
    type Error: Error;
    fn contract_id(&self) -> ContractId;
    fn memory(&self) -> &impl Memory;
    fn apply_operation(&mut self, header: OperationSeals<Seal>) -> Result<(), Self::Error>;
    fn apply_witness(&mut self, opid: Opid, witness: SealWitness<Seal>) -> Result<(), Self::Error>;
}

// We use dedicated trait here in order to prevent overriding of the implementation in client
// libraries
pub trait ContractVerify<Seal: SonicSeal>: ContractApi<Seal> {
    // TODO: Support multi-thread mode for parallel processing of unrelated operations
    fn evaluate<R: ReadOperation<Seal = Seal>>(
        &mut self,
        // We have to pass this as an independent parameter and not through the trait due to rust borrow checker
        codex: &Codex,
        // We have to pass this as an independent parameter and not through the trait due to rust borrow checker
        repo: &impl LibRepo,
        mut reader: R,
    ) -> Result<(), VerificationError<Seal, R::Error, Self::Error>> {
        let contract_id = self.contract_id();

        let mut seals = BTreeMap::<CellAddr, Seal>::new();
        while let Some((header, mut witness_reader)) = reader
            .read_operation()
            .map_err(VerificationError::Retrieve)?
        {
            // First, we verify the operation
            codex.verify(contract_id, &header.operation, self.memory(), repo)?;

            // Next we verify its single-use seals
            let opid = header.operation.opid();

            let mut closed_seals = alloc::vec![];
            for input in &header.operation.destroying {
                let Some(seal) = seals.get(&input.addr) else {
                    return Err(VerificationError::Vm(CallError::NoReadOnceInput(input.addr)));
                };
                closed_seals.push(seal.clone());
            }

            let iter = header
                .defined_seals
                .iter()
                .enumerate()
                .map(|(pos, seal)| (CellAddr::new(opid, pos as u16), seal.clone()));

            // We need to check that all seal definitions strictly match operation-defined destructible cells
            let defined = header
                .operation
                .destructible
                .iter()
                .map(|cell| cell.auth.to_byte_array())
                .collect::<BTreeSet<_>>();
            let sealed = iter
                .clone()
                .map(|(_, seal)| seal.auth_token().to_byte_array())
                .collect::<BTreeSet<_>>();
            if sealed != defined {
                return Err(VerificationError::SealDefinitionMismatch(opid));
            }

            // This convoluted logic happens since we use a state machine which ensures the client can't lie to
            // the verifier
            let mut witness_count = 0usize;
            loop {
                match witness_reader
                    .read_witness()
                    .map_err(VerificationError::Retrieve)?
                {
                    Step::Next((witness, w)) => {
                        witness
                            .verify_seals_closing(&closed_seals, opid.into_inner())
                            .map_err(|e| VerificationError::Seal(witness.published.pub_id(), opid, e))?;
                        self.apply_witness(opid, witness)
                            .map_err(|e| VerificationError::Apply(opid, e))?;
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

            seals.extend(iter);
            self.apply_operation(header)
                .map_err(|e| VerificationError::Apply(opid, e))?;
        }

        Ok(())
    }
}

impl<Seal: SonicSeal, C: ContractApi<Seal>> ContractVerify<Seal> for C {}

// TODO: Find a way to do Debug and Clone implementation
#[derive(Debug, Display, From)]
#[display(doc_comments)]
pub enum VerificationError<Seal: SingleUseSeal, E1: Error, E2: Error> {
    /// no witness known for the operation {0}.
    NoWitness(Opid),

    /// single-use seals are not closed properly with witness {0} for operation {1}.
    ///
    /// Details: {2}
    Seal(<Seal::PubWitness as PublishedWitness<Seal>>::PubId, Opid, SealError<Seal>),

    /// seals, reported to be defined by the operation {0}, do match the assignments in the
    /// operation.
    SealDefinitionMismatch(Opid),

    #[from]
    #[display(inner)]
    Vm(CallError),

    /// error retrieving transaction; {0}
    Retrieve(E1),

    /// error applying transaction data to the contract for operation {0}.
    ///
    /// Details: {1}
    Apply(Opid, E2),
}

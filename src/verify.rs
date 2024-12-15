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

use amplify::confinement::SmallOrdMap;
use amplify::{Bytes32, Wrapper};
use commit_verify::CommitId;
use single_use_seals::{PublishedWitness, SealError, SealWitness, SingleUseSeal};
use ultrasonic::{CallError, CellAddr, Codex, ContractId, LibRepo, Memory, Operation, Opid};

pub struct Transaction<Seal: SingleUseSeal> {
    pub operation: Operation,
    pub defines: SmallOrdMap<CellAddr, Seal>,
    pub witness: Option<SealWitness<Seal>>,
}

pub trait ContractApi<Seal: SingleUseSeal> {
    fn memory(&self) -> &impl Memory;
    fn apply<E: Error>(&mut self, transaction: Transaction<Seal>) -> Result<(), E>;
}

pub trait ContractVerify<Seal: SingleUseSeal<Message = Bytes32>>: ContractApi<Seal> {
    // TODO: Support multi-thread mode for parallel processing of unrelated operations
    fn evaluate<E: Error>(
        &mut self,
        contract_id: ContractId,
        codex: &Codex,
        repo: &impl LibRepo,
        mut transactions: impl FnMut() -> Option<Result<Transaction<Seal>, E>>,
    ) -> Result<(), VerificationError<Seal, E>> {
        let mut seals = BTreeMap::new();
        while let Some(step) = transactions() {
            let tx = step.map_err(VerificationError::Transaction)?;
            let opid = tx.operation.commit_id();

            let mut closed_seals = alloc::vec![];
            for input in &tx.operation.destroying {
                let Some(seal) = seals.get(&input.addr) else {
                    return Err(VerificationError::Vm(CallError::NoReadOnceInput(input.addr)));
                };
                closed_seals.push(seal);
            }

            if !closed_seals.is_empty() {
                let Some(witness) = &tx.witness else {
                    return Err(VerificationError::NoWitness(opid));
                };
                witness
                    .verify_seals_closing(closed_seals, opid.into_inner())
                    .map_err(|e| VerificationError::Seal(witness.published.pub_id(), opid, e))?;
            }

            codex.verify(contract_id, &tx.operation, self.memory(), repo)?;
            seals.extend(tx.defines.iter().map(|(addr, seal)| (*addr, seal.clone())));
            self.apply(tx).map_err(VerificationError::Transaction)?;
        }

        Ok(())
    }
}

impl<Seal: SingleUseSeal<Message = Bytes32>, C: ContractApi<Seal>> ContractVerify<Seal> for C {}

// TODO: Find a way to do Debug and Clone implementation
#[derive(Display, From)]
#[display(doc_comments)]
pub enum VerificationError<Seal: SingleUseSeal, E: Error> {
    /// no witness known for the operation {0}.
    NoWitness(Opid),

    /// single-use seals are not closed properly with witness {0} for operation {1}.
    ///
    /// Details: {2}
    Seal(<Seal::PubWitness as PublishedWitness<Seal>>::PubId, Opid, SealError<Seal>),

    #[from]
    #[display(inner)]
    Vm(CallError),

    #[display(inner)]
    Transaction(E),
}

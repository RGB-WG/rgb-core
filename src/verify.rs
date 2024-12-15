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

use amplify::confinement::{SmallOrdMap, SmallVec};
use amplify::{Bytes32, Wrapper};
use commit_verify::CommitId;
use single_use_seals::{PublishedWitness, SealError, SealWitness, SingleUseSeal};
use ultrasonic::{CallError, CellAddr, Codex, ContractId, LibRepo, Memory, Operation, Opid};

#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = "RGBCore")]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(bound = "Seal: serde::Serialize + for<'d> serde::Deserialize<'d>, Seal::PubWitness: serde::Serialize + \
                   for<'d> serde::Deserialize<'d>, Seal::CliWitness: serde::Serialize + for<'d> \
                   serde::Deserialize<'d>")
)]
pub struct Transaction<Seal: SingleUseSeal> {
    pub operation: Operation,
    pub defines: SmallOrdMap<CellAddr, Seal>,
    pub witness: SmallVec<SealWitness<Seal>>,
}

pub trait ContractApi<Seal: SingleUseSeal> {
    fn memory(&self) -> &impl Memory;
    fn apply<E2: Error>(&mut self, transaction: Transaction<Seal>) -> Result<(), E2>;
}

pub trait ContractVerify<Seal: SingleUseSeal<Message = Bytes32>>: ContractApi<Seal> {
    // TODO: Support multi-thread mode for parallel processing of unrelated operations
    fn evaluate<E1: Error, E2: Error>(
        &mut self,
        contract_id: ContractId,
        codex: &Codex,
        repo: &impl LibRepo,
        mut transactions: impl FnMut() -> Option<Result<Transaction<Seal>, E1>>,
    ) -> Result<(), VerificationError<Seal, E1, E2>> {
        let mut seals = BTreeMap::new();
        while let Some(step) = transactions() {
            let tx = step.map_err(VerificationError::Retrieve)?;
            let opid = tx.operation.commit_id();

            let mut closed_seals = alloc::vec![];
            for input in &tx.operation.destroying {
                let Some(seal) = seals.get(&input.addr) else {
                    return Err(VerificationError::Vm(CallError::NoReadOnceInput(input.addr)));
                };
                closed_seals.push(seal);
            }

            if !closed_seals.is_empty() {
                if tx.witness.is_empty() {
                    return Err(VerificationError::NoWitness(opid));
                };
                for witness in &tx.witness {
                    witness
                        .verify_seals_closing(closed_seals.iter().map(|seal| *seal), opid.into_inner())
                        .map_err(|e| VerificationError::Seal(witness.published.pub_id(), opid, e))?;
                }
            }

            codex.verify(contract_id, &tx.operation, self.memory(), repo)?;
            seals.extend(tx.defines.iter().map(|(addr, seal)| (*addr, seal.clone())));
            self.apply(tx)
                .map_err(|e| VerificationError::Apply(opid, e))?;
        }

        Ok(())
    }
}

impl<Seal: SingleUseSeal<Message = Bytes32>, C: ContractApi<Seal>> ContractVerify<Seal> for C {}

// TODO: Find a way to do Debug and Clone implementation
#[derive(Display, From)]
#[display(doc_comments)]
pub enum VerificationError<Seal: SingleUseSeal, E1: Error, E2: Error> {
    /// no witness known for the operation {0}.
    NoWitness(Opid),

    /// single-use seals are not closed properly with witness {0} for operation {1}.
    ///
    /// Details: {2}
    Seal(<Seal::PubWitness as PublishedWitness<Seal>>::PubId, Opid, SealError<Seal>),

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

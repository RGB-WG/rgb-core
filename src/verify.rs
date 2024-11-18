// RGB Core Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2019-2024 Dr Maxim Orlovsky. All rights reserved.

use core::borrow::Borrow;

use amplify::{Bytes32, Wrapper};
use commit_verify::CommitId;
use single_use_seals::{PublishedWitness, SealError, SealWitness, SingleUseSeal};
use ultrasonic::{CallError, CellAddr, Codex, ContractId, LibRepo, Memory, Operation, Opid};

pub trait ContractStockpile<Seal: SingleUseSeal> {
    fn contract_id(&self) -> ContractId;
    fn codex(&self) -> impl Borrow<Codex>;
    fn memory(&self) -> &impl Memory;
    fn operations(&self) -> impl Iterator<Item = impl Borrow<Operation>>;
    fn witness(&self, opid: Opid) -> Option<SealWitness<Seal>>;
    fn lib_repo(&self) -> &impl LibRepo;
    fn read_seal(&self, addr: CellAddr) -> Option<Seal>;
    fn apply(&self, op: &Operation);
}

pub trait ContractVerify<Seal: SingleUseSeal<Message = Bytes32>>: ContractStockpile<Seal> {
    // TODO: Support multi-thread mode for parallel processing of unrelated operations
    fn evaluate(&self) -> Result<(), VerificationError<Seal>> {
        let codex = self.codex();
        let lib_repo = self.lib_repo();

        for op in self.operations() {
            let op = op.borrow();
            let opid = op.commit_id();
            let Some(witness) = self.witness(opid) else {
                return Err(VerificationError::NoWitness(opid));
            };

            let mut closed_seals = vec![];
            for input in &op.destroying {
                let Some(seal) = self.read_seal(input.addr) else {
                    return Err(VerificationError::Vm(CallError::NoReadOnceInput(input.addr)));
                };
                closed_seals.push(seal);
            }

            witness
                .verify_seals_closing(closed_seals, opid.into_inner())
                .map_err(|e| VerificationError::Seal(witness.published.pub_id(), opid, e))?;

            codex.borrow().verify(op, self.memory(), lib_repo)?;
            self.apply(op);
        }

        Ok(())
    }
}

impl<Seal: SingleUseSeal<Message = Bytes32>, C: ContractStockpile<Seal>> ContractVerify<Seal> for C {}

// TODO: Find a way to do Debug and Clone implementation
#[derive(Display, From)]
#[display(doc_comments)]
pub enum VerificationError<Seal: SingleUseSeal> {
    /// no witness known for the operation {0}.
    NoWitness(Opid),

    /// single-use seals are not closed properly with witness {0} for operation {1}.
    ///
    /// Details: {2}
    Seal(<Seal::PubWitness as PublishedWitness<Seal>>::PubId, Opid, SealError<Seal>),

    #[from]
    #[display(inner)]
    Vm(CallError),
}

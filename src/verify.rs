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

use amplify::ByteArray;
use bp::seals::TxoSeal;
use bp::{dbc, Txid};
use commit_verify::{mpc, CommitId};
use single_use_seals::{SealError, SealWitness};
use ultrasonic::{CallError, CellAddr, Codex, LibRepo, Memory, Operation, Opid};

use crate::ContractId;

pub trait ContractState<D: dbc::Proof>: Memory {
    fn read_seal(&self, addr: CellAddr) -> Option<TxoSeal<D>>;
    fn apply(&self, op: &Operation);
}

pub trait ContractStash<D: dbc::Proof> {
    fn contract_id(&self) -> ContractId;
    fn codex(&self) -> impl Borrow<Codex>;
    fn operations(&self) -> impl Iterator<Item = impl Borrow<Operation>>;
    fn witness(&self, opid: Opid) -> Option<SealWitness<TxoSeal<D>>>;
    fn lib_repo(&self) -> &impl LibRepo;
}

pub trait ContractVerify<D: dbc::Proof>: ContractStash<D> {
    // TODO: Support multi-thread mode for parallel processing of unrelated operations
    fn evaluate(&self, state: &mut impl ContractState<D>) -> Result<(), VerificationError<D>> {
        let codex = self.codex();
        let lib_repo = self.lib_repo();
        let contract_id = self.contract_id();

        for op in self.operations() {
            let op = op.borrow();
            let opid = op.commit_id();
            let Some(witness) = self.witness(opid) else {
                return Err(VerificationError::NoWitness(opid));
            };

            let mut closed_seals = vec![];
            for input in &op.destroying {
                let Some(seal) = state.read_seal(input.addr) else {
                    return Err(VerificationError::Vm(CallError::NoReadOnceInput(input.addr)));
                };
                closed_seals.push(seal);
            }

            let message = (contract_id.into(), mpc::Message::from_byte_array(opid.to_byte_array()));
            witness
                .verify_seals_closing(closed_seals, message)
                .map_err(|e| VerificationError::Seal(witness.published.txid(), opid, e))?;

            codex.borrow().verify(op, state, lib_repo)?;
            state.apply(op);
        }

        Ok(())
    }
}

impl<D: dbc::Proof, C: ContractStash<D>> ContractVerify<D> for C {}

#[derive(Clone, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum VerificationError<D: dbc::Proof> {
    /// no witness known for the operation {0}.
    NoWitness(Opid),

    /// single-use seals are not closed properly with witness {0} for operation {1}.
    ///
    /// Details: {2}
    Seal(Txid, Opid, SealError<TxoSeal<D>>),

    #[from]
    #[display(inner)]
    Vm(CallError),
}

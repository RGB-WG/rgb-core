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

use amplify::Bytes32;
#[cfg(feature = "bp")]
use commit_verify::mpc;
use commit_verify::CommitId;
use single_use_seals::{ClientSideWitness, PublishedWitness, SealError, SealWitness, SingleUseSeal};
use ultrasonic::{CallError, CellAddr, Codex, LibRepo, Memory, Operation, Opid};

use crate::ContractId;

pub trait FromContractOpid: Sized {
    fn from_contract_opid(contract_id: ContractId, opid: Opid) -> Self;
}

pub trait ContractState<Seal: SingleUseSeal>: Memory {
    fn read_seal(&self, addr: CellAddr) -> Option<Seal>;
    fn apply(&self, op: &Operation);
}

pub trait ContractStash<Seal: SingleUseSeal> {
    fn contract_id(&self) -> ContractId;
    fn codex(&self) -> impl Borrow<Codex>;
    fn operations(&self) -> impl Iterator<Item = impl Borrow<Operation>>;
    fn witness(&self, opid: Opid) -> Option<SealWitness<Seal>>;
    fn lib_repo(&self) -> &impl LibRepo;
}

pub trait ContractVerify<Seal: SingleUseSeal>: ContractStash<Seal>
where <Seal::CliWitness as ClientSideWitness>::Message: FromContractOpid
{
    // TODO: Support multi-thread mode for parallel processing of unrelated operations
    fn evaluate(&self, state: &mut impl ContractState<Seal>) -> Result<(), VerificationError<Seal>> {
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

            let message = <Seal::CliWitness as ClientSideWitness>::Message::from_contract_opid(contract_id, opid);
            witness
                .verify_seals_closing(closed_seals, message)
                .map_err(|e| VerificationError::Seal(witness.published.pub_id(), opid, e))?;

            codex.borrow().verify(op, state, lib_repo)?;
            state.apply(op);
        }

        Ok(())
    }
}

impl<Seal: SingleUseSeal, C: ContractStash<Seal>> ContractVerify<Seal> for C where <Seal::CliWitness as ClientSideWitness>::Message: FromContractOpid
{}

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

impl FromContractOpid for Bytes32 {
    fn from_contract_opid(_: ContractId, opid: Opid) -> Self { *opid }
}

#[cfg(feature = "bp")]
impl FromContractOpid for (mpc::ProtocolId, mpc::Message) {
    fn from_contract_opid(contract_id: ContractId, opid: Opid) -> Self {
        use amplify::ByteArray;
        (mpc::ProtocolId::from(contract_id), mpc::Message::from_byte_array(opid.to_byte_array()))
    }
}

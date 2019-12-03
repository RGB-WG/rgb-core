// LNP/BP Rust Library
// Written in 2019 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the MIT License
// along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

use std::collections::HashMap;

use ::bitcoin::{Txid, Transaction, OutPoint, BlockHash};

use super::{seal::*, blockchain::*};
use crate::cmt::*;


pub enum Error {
    AlreadySpent,
    WrongMessageCommitment,
    NotClosed,
    AbsentWitness,
    WrongWitness,
    NotCommitted,
}

pub struct BlockPosition {
    pub height: u64,
    pub block_hash: BlockHash,
}

pub struct Blockchain {
    pub verified: HashMap<Txid, Transaction>,
    pub mempool: HashMap<Txid, Transaction>,
    pub psbts: HashMap<Txid, Transaction>,
}

impl Blockchain {
    pub fn is_spent(&self, output: &OutPoint) -> bool {
        unimplemented!()
    }
}

impl Context for Blockchain {
    type Promice = OutPoint;
    type Witness = Transaction;
    type Error = Error;
}

impl BlockchainContext for Blockchain {
    type Id = Txid;
    type Tx = Transaction;
    type BlockchainPosition = BlockPosition;

    fn get_tx(&self, id: &Self::Id) -> Result<Self::Tx, Error> {
        unimplemented!()
    }

    fn has_tx(&self, tx: &Self::Tx) -> Result<Self::BlockchainPosition, Error> {
        unimplemented!()
    }

    fn add_tx(&mut self, tx: Self::Tx) -> Result<Self::BlockchainPosition, Error> {
        unimplemented!()
    }
}

pub struct TxoutSeal {
    pub outpoint: OutPoint,
    pub commitment: Option<TxoutCommitment>,
}

impl SingleUseSeal<Blockchain> for TxoutSeal {
    fn define(promice: &OutPoint, ctx: &Blockchain) -> Result<Self, Error> {
        match !ctx.is_spent(promice) {
            true => Ok(TxoutSeal { outpoint: *promice, commitment: None }),
            false => Err(Error::AlreadySpent),
        }
    }

    fn close(&mut self, msg: &Message, ctx: &mut Blockchain) -> Result<Transaction, Error> {
        unimplemented!();
    }

    fn is_closed(&self, ctx: &Blockchain) -> bool {
        ctx.is_spent(&self.outpoint) && self.commitment.is_some()
    }

    fn verify(&self, msg: &Message, witness: &Transaction, ctx: &Blockchain) -> Result<bool, Error> {
        if !msg.verify(&self.commitment)? {
            return Err(Error::WrongMessageCommitment);
        }
        if !ctx.is_spent(&self.outpoint) {
            return Err(Error::NotClosed);
        }
        if ctx.has_tx(witness).is_err() {
            return Err(Error::AbsentWitness);
        }
        if !witness.is_spending(self.outpoint, ctx) {
            return Err(Error::WrongWitness);
        }
        if !witness.verify_commitment(msg) {
            return Err(Error::NotCommitted);
        }
        return Ok(true);
    }
}

use bitcoin::{PublicKey, Transaction, TxOut};
use crate::commitments::{base::*, secp256k1::*, script::*};

impl CommitTarget for Transaction {}

pub struct TxCommitment {
    pub tx: Transaction,
    pub locator: VoutLocator,
}

impl CommitmentScheme<Transaction> for TxCommitment {
    fn commit(&self) -> Transaction {
        unimplemented!()
    }

    fn verify(&self, tx: Transaction) -> bool {
        unimplemented!()
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TxEngine(Transaction);

impl<'a> CommitmentEngine<Transaction, TweakSource<'a>, TxCommitment> for TxEngine {
    fn construct(&self, src: &TweakSource<'a>) -> TxCommitment {
        unimplemented!()
    }
}

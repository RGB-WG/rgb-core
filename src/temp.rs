//! Temporary module for refactoring period

use bitcoin::{Transaction, Txid};

#[derive(Debug, Display, Error)]
#[display(doc_comments)]
/// transaction {0} is not mined
pub struct TxResolverError(Txid);

pub trait ResolveTx {
    fn resolve_tx(&self, txid: Txid) -> Result<Transaction, TxResolverError>;
}

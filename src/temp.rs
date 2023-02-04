//! Temporary module for refactoring period

use bc::{Tx, Txid};

#[macro_export]
macro_rules! txid {
    ($old:expr) => {
        $old.to_string().parse().unwrap()
    };
}

#[macro_export]
macro_rules! outpoint {
    ($old:expr) => {
        bc::Outpoint {
            txid: txid!($old.txid),
            vout: $old.vout.into(),
        }
    };
}

#[macro_export]
macro_rules! tx {
    ($old:expr) => {
        serde_json::from_str(&serde_json::to_string($old).unwrap()).unwrap()
    };
}

#[derive(Debug, Display, Error)]
#[display(doc_comments)]
/// transaction {0} is not mined
pub struct TxResolverError(Txid);

pub trait ResolveTx {
    fn resolve_tx(&self, txid: Txid) -> Result<Tx, TxResolverError>;
}

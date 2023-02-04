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

// TODO: Change values according to the standard
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Display, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
#[repr(u32)]
pub enum Chain {
    #[default]
    #[display("mainnet")]
    Bitcoin = 0x00,
    #[display("testnet")]
    Testnet3 = 0x8000_0000,
    #[display("regtest")]
    Regtest = 0x8000_0001,
    #[display("signet")]
    Signet = 0x8000_0002,
}

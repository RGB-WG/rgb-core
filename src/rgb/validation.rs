// LNP/BP Rust Library
// Written in 2020 by
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


#![allow(unused_imports)]

use bitcoin::{OutPoint, Txid, Transaction};

use super::schema::SchemaError;
use super::seal::Error as SealError;
use super::history::GraphError;

/// Fetch a raw Bitcoin transaction given its identifier
pub trait TxFetch {
    type Error: std::fmt::Debug + Clone;

    fn fetch_from_txid(&mut self, txid: &Txid) -> Result<Transaction, Self::Error>;
}

#[derive(Debug, Clone)]
pub enum ValidationError<T>
where
    T: TxFetch
{
    InvalidOutpoint(OutPoint),
    TxInNeTxOut,

    Schema(SchemaError),
    Seal(SealError),
    Graph(GraphError),

    TxFetch(<T as TxFetch>::Error),
}

macro_rules! impl_error {
    ( $from:ty, $to:ident ) => {
        impl<T: TxFetch> std::convert::From<$from> for ValidationError<T> {
            fn from(err: $from) -> Self {
                ValidationError::$to(err)
            }
        }
    };
}

impl_error!(SchemaError, Schema);
impl_error!(SealError, Seal);
impl_error!(GraphError, Graph);

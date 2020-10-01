// LNP/BP Core Library implementing LNPBP specifications & standards
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

use bitcoin::{OutPoint, Transaction, Txid};

pub enum SpendingStatus {
    Unknown,
    Invalid,
    Unspent,
    Spent(Option<u32>),
}

pub trait TxGraph {
    type AccessError: std::error::Error;

    fn spending_status(
        &self,
        outpoint: &OutPoint,
    ) -> Result<SpendingStatus, Self::AccessError>;
    fn fetch_spending_tx(
        &self,
        outpoint: &OutPoint,
    ) -> Result<Transaction, Self::AccessError>;
    fn create_spending_tx(
        &self,
        outpoint: &OutPoint,
    ) -> Result<Transaction, Self::AccessError>;
    fn fetch_tx(&self, txid: Txid) -> Result<Transaction, Self::AccessError>;
    fn apply_tx(
        &self,
        signed_tx: &Transaction,
    ) -> Result<Transaction, Self::AccessError>;
}

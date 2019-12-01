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

use bitcoin::{Amount, TxOut};

use super::txout::TxoutCommitment;


#[derive(Clone, Eq, PartialEq)]
pub struct TxCommitment {
    pub entropy: u64,
    pub fee: Amount,
    pub tweaked: TxoutCommitment,
    pub original: TxoutCommitment,
}


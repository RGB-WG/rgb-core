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

use super::seal::*;

pub trait BlockchainContext: Context {
    type Id;
    type Tx;
    type BlockchainPosition;

    fn get_tx(&self, id: &Self::Id) -> Result<Self::Tx, Self::Error>;
    fn has_tx(&self, tx: &Self::Tx) -> Result<Self::BlockchainPosition, Self::Error>;
    fn add_tx(&mut self, tx: Self::Tx) -> Result<Self::BlockchainPosition, Self::Error>;
}


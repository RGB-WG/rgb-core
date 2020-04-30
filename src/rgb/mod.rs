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

pub mod anchor;
pub mod consignment;
pub mod contract;
pub mod interfaces;
pub mod schema;
pub mod stash;
pub mod vm;

pub mod prelude {
    pub use super::*;
    pub use anchor::Anchor;
    pub use consignment::Consignment;
    pub use contract::{Amount, Contract, ContractId, Genesis, SealDefinition, Transition};
    pub use schema::Schema;
    pub use schema::SimplicityScript;
    pub use stash::{CoordinatedTransition, CoordinatedUpdate, Stash};
}

pub use prelude::*;

use bitcoin::hashes::{sha256d, Hash};

hash_newtype!(
    ContractId,
    sha256d::Hash,
    32,
    doc = "Double-sha256 hash of the genesis transition"
);

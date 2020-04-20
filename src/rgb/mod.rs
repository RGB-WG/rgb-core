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


pub mod schema;
pub mod schemata;

pub mod metadata;
pub mod data;
pub mod seal;
pub mod state;
pub mod script;
pub mod transition;

pub mod serialize;
pub mod commit;

mod proof;


pub use schemata::*;

pub use data::Data;
pub use state::State;
pub use metadata::Metadata;
pub use script::Script;
pub use seal::Seal;
pub use transition::Transition;

pub use proof::*;


use bitcoin::hashes::{Hash, sha256d};

hash_newtype!(ContractId, sha256d::Hash, 32, doc="Double-sha256 hash of the genesis transition");
